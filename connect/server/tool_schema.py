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


"""The tool listing an agent reads: each argument presented as the reference does.

FastMCP renders a tool's arguments from its signature, as pydantic would: an
optional argument as a nullable union with a `title` and a `default`. The
reference publishes bare types instead (B3), and Connect presents every
argument that way. Its own extra arguments (S3) and the typed intent (S4) are
published only in the positions that turn them on.
"""

import copy
import typing as t

from connect.switches import Switches

# S3: the arguments a tool takes that the reference's does not (S18 adds
# `intent` on send_transaction); with the switch off they are not published
# and, if sent, not read
EXTRA_PARAMETERS: t.Mapping[str, frozenset[str]] = {
    "safe_transaction": frozenset({"wait_for_receipt", "timeout"}),
    "send_transaction": frozenset({"wait_for_receipt", "timeout", "intent"}),
    "simulate_transaction": frozenset({"via_safe"}),
    "chain_call": frozenset({"block"}),
    "mech_tools": frozenset({"limit", "offset"}),
    "mech_result": frozenset({"timeout"}),
    "mech_request": frozenset({"legacy_on_chain", "request_context"}),
}
# published as integers, as the reference types them
INTEGER_PARAMETERS: t.Mapping[str, frozenset[str]] = {
    "mech_request": frozenset({"timeout"}),
}


def unread(tool: str, switches: Switches) -> frozenset[str]:
    """Return the arguments of `tool` this position neither publishes nor reads."""
    if switches.extra_tool_parameters:
        return frozenset()
    return EXTRA_PARAMETERS.get(tool, frozenset())


def published(tool: str, parameters: t.Mapping[str, t.Any], switches: Switches) -> dict:
    """Return the input schema `tool` publishes in this position.

    `parameters` is FastMCP's rendering of the tool's arguments; it is never
    changed, so the argument model the boundary validates against stays whole.
    """
    hidden = unread(tool, switches)
    properties = {
        name: _argument(tool, name, schema, switches)
        for name, schema in parameters.get("properties", {}).items()
        if name not in hidden
    }
    schema: dict[str, t.Any] = {
        "type": "object",
        "properties": properties,
        "required": [n for n in parameters.get("required", []) if n in properties],
    }
    if switches.rich_intent_schema and "intent" in properties:
        schema["$defs"] = copy.deepcopy(parameters.get("$defs", {}))
    return schema


def _argument(
    tool: str, name: str, schema: t.Mapping[str, t.Any], switches: Switches
) -> dict:
    """Return one argument as published: its bare type, with no title or default."""
    if name in INTEGER_PARAMETERS.get(tool, frozenset()):
        return {"type": "integer"}
    if name == "intent" and not switches.rich_intent_schema:
        return {"type": "object"}
    present = _non_null(schema)
    out = {
        k: copy.deepcopy(v) for k, v in present.items() if k not in ("title", "default")
    }
    if "description" in schema:  # pydantic keeps a field's description on the union
        out["description"] = schema["description"]
    return out


def _non_null(schema: t.Mapping[str, t.Any]) -> t.Mapping[str, t.Any]:
    """Return the one non-null member of an optional argument's union, else itself."""
    members = [m for m in schema.get("anyOf", []) if m.get("type") != "null"]
    return members[0] if len(members) == 1 else schema
