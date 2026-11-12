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

"""Refuse unknown parameters on every agent-facing surface (OPE-2035 T6).

A parameter a tool does not take used to be dropped without a word: a
session that sent `to` to `safe_transaction` had its recipient ignored and
the call made with the default. Both surfaces now refuse it and name the
parameters the tool does take, so the mistake is visible and fixable.
"""

import difflib
import typing as t

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, model_validator

# Names a session plausibly reaches for, and the parameter it meant: the safe
# path's call target is `target`, not the EOA path's `to`, and vice versa.
HINTS: dict[str, dict[str, str]] = {
    "target": {"to": "target", "address": "target"},
    "to": {"target": "to", "address": "to"},
}


def unknown_parameters_message(
    given: t.Iterable[str], expected: t.Collection[str]
) -> str | None:
    """Say which parameters are unknown and what was expected, or None if none are."""
    unknown = sorted(set(given) - set(expected))
    if not unknown:
        return None
    parts = []
    for name in unknown:
        hint = next(
            (
                aliases[name]
                for wanted, aliases in HINTS.items()
                if wanted in expected and name in aliases
            ),
            None,
        )
        if hint is None:
            close = difflib.get_close_matches(name, list(expected), n=1)
            hint = close[0] if close else None
        parts.append(f"'{name}' (did you mean '{hint}'?)" if hint else f"'{name}'")
    return (
        f"unknown parameter {', '.join(parts)}; this call takes "
        f"{', '.join(sorted(expected))}"
    )


def _check_known(cls: type[BaseModel], data: t.Any) -> t.Any:
    """Before-validator body: refuse a mapping that carries unknown keys."""
    if isinstance(data, dict):
        expected = {field.alias or name for name, field in cls.model_fields.items()}
        message = unknown_parameters_message(data, expected)
        if message is not None:
            raise ValueError(message)
    return data


class StrictBody(BaseModel):
    """Base for HTTP request bodies: unknown fields are refused, by name."""

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown(cls, data: t.Any) -> t.Any:
        return _check_known(cls, data)


def strict_arg_model(model: type[BaseModel]) -> type[BaseModel]:
    """Return a subclass of an MCP tool's argument model that refuses unknown keys."""

    class Strict(model):  # type: ignore[valid-type, misc]
        """The tool's arguments, with unknown ones refused by name."""

        model_config = ConfigDict(**{**model.model_config, "extra": "forbid"})

        @model_validator(mode="before")
        @classmethod
        def _refuse_unknown(cls, data: t.Any) -> t.Any:
            return _check_known(cls, data)

    Strict.__name__ = Strict.__qualname__ = model.__name__
    return Strict


def make_tools_strict(mcp: FastMCP) -> None:
    """Make every registered tool refuse arguments it does not take."""
    for tool in mcp._tool_manager.list_tools():  # pylint: disable=protected-access
        tool.fn_metadata.arg_model = strict_arg_model(tool.fn_metadata.arg_model)
