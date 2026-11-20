# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Refuse unknown parameters on every agent-facing surface.

A parameter a tool does not take would otherwise be dropped without a word:
a session that sent `to` to `safe_transaction` would have its recipient
ignored and the call made with the default. Both surfaces refuse it and name
the parameters the tool does take, so the mistake is visible and fixable.
"""

import difflib
import typing as t

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, model_validator
from pydantic.json_schema import SkipJsonSchema
from pydantic_core import PydanticCustomError

from connect.activity import ActivityLog

# Names a session plausibly reaches for, and the parameter it meant: the safe
# path's call target is `target`, not the EOA path's `to`, and vice versa.
HINTS: dict[str, dict[str, str]] = {
    "target": {"to": "target", "address": "target"},
    "to": {"target": "to", "address": "to"},
}


def unknown_parameters_message(
    given: t.Iterable[str],
    expected: t.Collection[str],
    published: t.Collection[str] | None = None,
) -> str | None:
    """Say which parameters are unknown and what was expected, or None if none are.

    `published` is what the refusal names and hints at, when it differs from
    what is accepted: a parameter kept out of the published schema is taken
    but never advertised.
    """
    unknown = sorted(set(given) - set(expected))
    if not unknown:
        return None
    named = set(expected if published is None else published)
    parts = []
    for name in unknown:
        hint = next(
            (
                aliases[name]
                for wanted, aliases in HINTS.items()
                if wanted in named and name in aliases
            ),
            None,
        )
        if hint is None:
            close = difflib.get_close_matches(name, list(named), n=1)
            hint = close[0] if close else None
        parts.append(f"'{name}' (did you mean '{hint}'?)" if hint else f"'{name}'")
    return (
        f"unknown parameter {', '.join(parts)}; this call takes "
        f"{', '.join(sorted(named))}"
    )


UNKNOWN_PARAMETER_RULE = "unknown-parameter"

OnRefusal = t.Callable[[str], None]


def _check_known(
    cls: type[BaseModel],
    data: t.Any,
    on_refusal: OnRefusal | None = None,
    unread: t.Collection[str] = frozenset(),
) -> t.Any:
    """Before-validator body: refuse a mapping that carries unknown keys.

    `unread` are fields this position neither lists nor reads (S3): a strict
    model refuses them by name like any other unknown key.
    """
    if isinstance(data, dict):
        fields = [
            (name, field)
            for name, field in cls.model_fields.items()
            if (field.alias or name) not in unread
        ]
        expected = {field.alias or name for name, field in fields}
        published = {
            field.alias or name
            for name, field in fields
            if not any(isinstance(m, SkipJsonSchema) for m in field.metadata)
        }
        message = unknown_parameters_message(data, expected, published)
        if message is not None:
            if on_refusal is not None:
                on_refusal(message)
            # typed, so the HTTP audit finds its own refusals by type, not text
            raise PydanticCustomError(UNKNOWN_PARAMETER_RULE, message)
    return data


class AuditedRefusal(ToolError):
    """A tool call's refusal already recorded where it was refused.

    An unknown parameter under `strict_parameters`: the strict model audits
    it, so the mount does not audit it twice.
    """


class StrictBody(BaseModel):
    """Base for HTTP request bodies: unknown fields are refused, by name."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown(cls, data: t.Any) -> t.Any:
        return _check_known(cls, data)


def strict_arg_model(
    model: type[BaseModel],
    on_refusal: OnRefusal,
    unread: t.Collection[str] = frozenset(),
) -> type[BaseModel]:
    """Return a subclass of an MCP tool's argument model that refuses unknown keys.

    `unread` fields count as unknown: the position does not take them.
    """

    class Strict(model):  # type: ignore[valid-type, misc]
        """The tool's arguments, with unknown ones refused by name."""

        model_config = ConfigDict(**{**model.model_config, "extra": "forbid"})

        @model_validator(mode="before")
        @classmethod
        def _refuse_unknown(cls, data: t.Any) -> t.Any:
            return _check_known(cls, data, on_refusal, unread)

    Strict.__name__ = Strict.__qualname__ = model.__name__
    return Strict


def make_tools_strict(
    mcp: FastMCP,
    activity: ActivityLog,
    unread: t.Callable[[str], t.Collection[str]],
) -> None:
    """Make every registered tool refuse arguments it does not take, audited.

    `unread(tool)` names what this position does not take of a tool's own
    arguments (`tool_schema.unread`), so those are refused by name too.
    """
    for tool in mcp._tool_manager.list_tools():  # pylint: disable=protected-access

        def audit(message: str, name: str = tool.name) -> None:
            activity.record(
                "refusal", rule=UNKNOWN_PARAMETER_RULE, tool=name, reason=message
            )

        tool.fn_metadata.arg_model = strict_arg_model(
            tool.fn_metadata.arg_model, audit, unread(tool.name)
        )


def unknown_parameter_errors(
    errors: t.Iterable[t.Mapping[str, t.Any]],
) -> list[t.Mapping[str, t.Any]]:
    """Return the validation errors that are unknown-parameter refusals."""
    return [e for e in errors if e.get("type") == UNKNOWN_PARAMETER_RULE]


def audit_unknown_parameters(
    activity: ActivityLog, path: str, errors: t.Iterable[t.Mapping[str, t.Any]]
) -> None:
    """Record an HTTP body's unknown-parameter refusal in the activity log."""
    for error in unknown_parameter_errors(errors):
        activity.record(
            "refusal",
            rule=UNKNOWN_PARAMETER_RULE,
            path=path,
            reason=str(error.get("msg", "")),
        )
