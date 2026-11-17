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

"""Unknown parameters are refused by name on both surfaces."""

import json
import typing as t

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.intent import parse_intent
from connect.mech import MechService
from connect.server.auth import TOOL_AMOUNTS, TOOL_CAPS
from connect.server.strict import (
    audit_unknown_parameters,
    unknown_parameters_message,
)
from connect.signer import Signer
from connect.switches import Switches

from tests.conftest import FakeW3, audit_entries

TOKEN = "strict-test-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20


@pytest.fixture
def mcp(make_mcp: t.Callable[..., FastMCP]) -> FastMCP:
    """Return the MCP server built with the strict_parameters switch on."""
    return make_mcp(Switches(strict_parameters=True))


async def test_an_unknown_parameter_is_ignored_with_the_switch_off(
    make_mcp: t.Callable[..., FastMCP], fake_w3: FakeW3
) -> None:
    """The strict_parameters switch is off in production: the key is dropped."""
    lenient = make_mcp()
    await lenient.call_tool(
        "safe_transaction",
        {"chain": "testchain", "target": RECIPIENT, "targett": RECIPIENT},
    )
    assert len(fake_w3.eth.sent) == 1


@pytest.fixture
def client(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
) -> t.Iterator[TestClient]:
    """HTTP client with a valid token."""
    app = make_app(test_signer, app_config, activity, token=TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        yield client


def test_message_names_the_unknown_and_the_expected() -> None:
    """The refusal says what was wrong and what the call takes."""
    message = unknown_parameters_message({"chain", "to"}, {"chain", "target", "value"})
    assert message == (
        "unknown parameter 'to' (did you mean 'target'?); this call takes "
        "chain, target, value"
    )


def test_message_falls_back_to_the_closest_name_or_none() -> None:
    """A typo gets its nearest parameter; a stray name gets no guess."""
    assert "did you mean 'value'" in t.cast(
        str, unknown_parameters_message({"valeu"}, {"value"})
    )
    assert unknown_parameters_message({"zzz"}, {"value"}) == (
        "unknown parameter 'zzz'; this call takes value"
    )
    assert unknown_parameters_message({"value"}, {"value"}) is None


async def test_a_misspelled_target_is_refused_by_name(
    mcp: FastMCP, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """`targett` beside `target` is refused and the message names `target`."""
    with pytest.raises(ToolError, match=r"'targett' \(did you mean 'target'\?\)"):
        await mcp.call_tool(
            "safe_transaction",
            {"chain": "testchain", "target": RECIPIENT, "targett": RECIPIENT},
        )
    assert not fake_w3.eth.sent
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert entry == {**entry, "rule": "unknown-parameter", "tool": "safe_transaction"}


async def test_to_is_an_alias_of_target_with_the_switch_on(
    mcp: FastMCP, fake_w3: FakeW3
) -> None:
    """`to` aliases a safe call's `target`, so strictness does not refuse it."""
    await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert len(fake_w3.eth.sent) == 1


def _placeholder(schema: dict) -> t.Any:
    """Return a value of the JSON schema's type, so only the unknown name fails."""
    kinds = {schema.get("type")} | {o.get("type") for o in schema.get("anyOf", [])}
    for kind, value in (
        ("integer", 1),
        ("number", 1),
        ("boolean", False),
        ("object", {}),
        ("array", []),
    ):
        if kind in kinds:
            return value
    return "testchain"


async def test_every_mcp_tool_refuses_an_unknown_parameter(
    mcp: FastMCP, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """A tool that skipped the strict wrapper would drop the name silently."""
    tools = await mcp.list_tools()
    assert len(tools) > 10
    for tool in tools:
        properties = tool.inputSchema.get("properties", {})
        required = {
            name: _placeholder(properties[name])
            for name in tool.inputSchema.get("required", [])
        }
        with pytest.raises(ToolError, match="unknown parameter 'zzz'"):
            await mcp.call_tool(tool.name, {**required, "zzz": 1})
    assert not fake_w3.eth.sent
    refused = [
        e["tool"]
        for e in audit_entries(store_path)
        if e["kind"] == "refusal" and e["rule"] == "unknown-parameter"
    ]
    assert sorted(refused) == sorted(tool.name for tool in tools)


async def test_a_misspelled_max_payment_is_refused_not_uncapped(
    mcp: FastMCP, mech_service: MechService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """mech_request's cap dropped silently would pay the default; it is named instead."""
    monkeypatch.setattr(mech_service, "request", lambda *a, **k: pytest.fail("sent"))
    with pytest.raises(
        ToolError, match=r"'max_paymnet' \(did you mean 'max_payment'\?\)"
    ):
        await mcp.call_tool(
            "mech_request", {"prompt": "q", "tool": "t", "max_paymnet": 10}
        )


async def test_send_transaction_hints_the_other_way(mcp: FastMCP) -> None:
    """The EOA path takes `to`, so `target` there is pointed back at it."""
    with pytest.raises(ToolError, match=r"'target' \(did you mean 'to'\?\)"):
        await mcp.call_tool(
            "send_transaction", {"chain": "testchain", "target": RECIPIENT}
        )


async def test_known_arguments_still_work(mcp: FastMCP, fake_w3: FakeW3) -> None:
    """Strictness changes nothing for a call that names its parameters right."""
    await mcp.call_tool("safe_transaction", {"chain": "testchain", "target": RECIPIENT})
    assert len(fake_w3.eth.sent) == 1


async def test_read_only_tools_carry_read_only_hint(mcp: FastMCP) -> None:
    """Exactly the tools that never sign, broadcast or pay are flagged read-only."""
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    read_only = {
        name
        for name, tool in tools.items()
        if tool.annotations is not None and tool.annotations.readOnlyHint
    }
    assert read_only == {
        "wallet_info",
        "preflight_transaction",
        "transaction_status",
        "mech_result",
        "mech_tools",
        "simulate_transaction",
        "chain_call",
        "get_abi",
        "decode_calldata",
    }


def test_http_safe_transaction_refuses_to(
    client: TestClient, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """The HTTP route takes `target`, like the tool, and names it when given `to`."""
    response = client.post(
        "/safe-transaction",
        json={"chain": "testchain", "to": RECIPIENT},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 422
    assert "did you mean 'target'" in response.text
    assert not fake_w3.eth.sent
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert entry["rule"] == "unknown-parameter"
    assert entry["path"] == "/safe-transaction"
    # the typed error's own message, not a ValueError's "Value error, ..." text
    assert entry["reason"].startswith("unknown parameter 'to' (did you mean 'target'?)")


def test_the_audit_matches_the_error_type_not_its_text(
    activity: ActivityLog, store_path: t.Any
) -> None:
    """Another validation error that mentions unknown parameters is not audited."""
    audit_unknown_parameters(
        activity,
        "/safe-transaction",
        [{"type": "value_error", "msg": "Value error, unknown parameter 'to'"}],
    )
    assert not [e for e in audit_entries(store_path) if e["kind"] == "refusal"]


def test_http_sign_message_refuses_unknown_fields(client: TestClient) -> None:
    """Every signing body is strict, not just the two send routes."""
    response = client.post(
        "/sign-message",
        json={"digest": "0x" + "00" * 32, "prefix": True},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 422
    assert "unknown parameter 'prefix'" in response.text


def test_a_non_mapping_body_is_left_to_pydantic() -> None:
    """Only a mapping can carry unknown keys; anything else fails as a type error."""
    from pydantic import ValidationError  # pylint: disable=import-outside-toplevel

    from connect.server.signer_routes import (  # pylint: disable=import-outside-toplevel
        SignMessageRequest,
    )

    with pytest.raises(ValidationError, match="model_type"):
        SignMessageRequest.model_validate("not a body")


async def test_the_tool_schema_declares_base_unit_amounts_as_strings(
    mcp: FastMCP,
) -> None:
    """Every value and max_payment is a string in the published schema.

    The mount reads exactly these (`TOOL_AMOUNTS`), so no amount is missed.
    """
    declared: dict[str, list[str]] = {}
    for tool in await mcp.list_tools():
        for name, schema in tool.inputSchema.get("properties", {}).items():
            if name in ("value", "max_payment"):
                kinds = {schema.get("type")} | {
                    o.get("type") for o in schema.get("anyOf", [])
                }
                assert "string" in kinds, (tool.name, name, schema)
                assert not kinds & {"integer", "number"}, (tool.name, name, schema)
                declared.setdefault(tool.name, []).append(name)
    assert declared == {
        tool: list(names) for tool, names in (TOOL_AMOUNTS | TOOL_CAPS).items()
    }


@pytest.mark.parametrize("amount", [1.5, 1.0, 2**53, 2**53 + 1, "1e18", -1, True])
async def test_a_tool_refuses_an_amount_a_json_number_may_have_rounded(
    mcp: FastMCP, fake_w3: FakeW3, amount: t.Any
) -> None:
    """A float, a number from 2^53 on or a non-amount is refused naming the rule.

    The mech cap is a bound, not a spend, so only the amounts a double cannot
    hold are exempt there (`test_a_mech_cap_takes_any_whole_json_integer`).
    """
    for tool, arguments in (
        ("safe_transaction", {"chain": "testchain", "target": RECIPIENT}),
        ("simulate_transaction", {"chain": "testchain", "target": RECIPIENT}),
    ):
        with pytest.raises(ToolError, match="rule 'bad-value'"):
            await mcp.call_tool(tool, {**arguments, "value": amount})
    if amount not in (2**53, 2**53 + 1):
        with pytest.raises(ToolError, match="rule 'bad-value'"):
            await mcp.call_tool(
                "mech_request", {"prompt": "q", "tool": "t", "max_payment": amount}
            )
    assert not fake_w3.eth.sent


@pytest.mark.parametrize("cap", [2**53, 2**53 + 1, 10**18])
async def test_a_mech_cap_takes_any_whole_json_integer(
    mcp: FastMCP, mech_service: MechService, monkeypatch: pytest.MonkeyPatch, cap: int
) -> None:
    """A cap a double could not hold still reaches the mech flow as itself.

    The cap bounds the mech's price, which is checked exactly; it is never
    spent, so a client sending its budget in base units as a JSON integer is
    not refused.
    """
    seen: list[t.Any] = []

    def request(*_args: t.Any, **kwargs: t.Any) -> dict:
        seen.append(kwargs["max_payment"])
        return {}

    monkeypatch.setattr(mech_service, "request", request)
    await mcp.call_tool(
        "mech_request", {"prompt": "q", "tool": "t", "max_payment": cap}
    )
    assert seen == [cap]


async def test_a_decimal_string_amount_reaches_the_signer_exactly(
    mcp: FastMCP,
    test_signer: Signer,
    mech_service: MechService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """10^18 + 1, past what a JSON number holds, arrives as that exact integer."""
    exact = 10**18 + 1
    seen: list[t.Any] = []

    def send_via_safe(*_args: t.Any, **kwargs: t.Any) -> str:
        seen.append(kwargs["value"])
        return "0x" + "11" * 32

    def request(*_args: t.Any, **kwargs: t.Any) -> dict:
        seen.append(kwargs["max_payment"])
        return {}

    monkeypatch.setattr(test_signer, "send_via_safe", send_via_safe)
    monkeypatch.setattr(mech_service, "request", request)
    await mcp.call_tool(
        "safe_transaction",
        {"chain": "testchain", "target": RECIPIENT, "value": str(exact)},
    )
    await mcp.call_tool(
        "safe_transaction",
        {"chain": "testchain", "target": RECIPIENT, "value": hex(exact)},
    )
    await mcp.call_tool(
        "mech_request", {"prompt": "q", "tool": "t", "max_payment": str(exact)}
    )
    await mcp.call_tool(
        "mech_request", {"prompt": "q", "tool": "t", "max_payment": exact}
    )
    await mcp.call_tool(
        "safe_transaction", {"chain": "testchain", "target": RECIPIENT, "value": 5}
    )
    assert seen == [exact, exact, exact, exact, 5]


def _schema_types(schema: dict, defs: dict) -> set[t.Any]:
    """Return the JSON types a property schema allows, following $ref and anyOf."""
    if "$ref" in schema:
        schema = defs[schema["$ref"].rsplit("/", 1)[-1]]
    kinds = {schema.get("type")} - {None}
    for option in schema.get("anyOf", []):
        kinds |= _schema_types(option, defs)
    return kinds


def _resolved(schema: dict, defs: dict) -> dict:
    """Return the object schema behind a nullable or referenced property."""
    for option in [schema, *schema.get("anyOf", [])]:
        if "$ref" in option:
            return defs[option["$ref"].rsplit("/", 1)[-1]]
        if option.get("type") in ("object", "array"):
            return option
    raise AssertionError(schema)


async def test_the_tool_schema_declares_every_intent_amount_as_a_string(
    mcp: FastMCP,
) -> None:
    """spend, receive_min and each approval's amount are strings, on every tool."""
    with_intent = []
    for tool in await mcp.list_tools():
        schema = tool.inputSchema
        if "intent" not in schema.get("properties", {}):
            continue
        with_intent.append(tool.name)
        defs = schema.get("$defs", {})
        intent = _resolved(schema["properties"]["intent"], defs)
        for where in ("spend", "receive_min"):
            per_token = _resolved(intent["properties"][where], defs)
            kinds = _schema_types(per_token["additionalProperties"], defs)
            assert kinds == {"string"}, (tool.name, where, per_token)
        approvals = _resolved(intent["properties"]["approvals"], defs)
        approval = _resolved(approvals["items"], defs)
        kinds = _schema_types(approval["properties"]["amount"], defs)
        assert kinds == {"string"}, (tool.name, approval)
    # preflight answers the guardrail's verdict alone, so it takes no intent
    assert sorted(with_intent) == sorted(
        TOOL_AMOUNTS.keys() - {"preflight_transaction"}
    )


def _intent_with(where: str, amount: t.Any) -> dict:
    """Return an intent declaring `amount` at `where`."""
    if where == "approvals":
        return {
            "approvals": [{"token": RECIPIENT, "spender": RECIPIENT, "amount": amount}]
        }
    return {where: {"native": amount}}


@pytest.mark.parametrize("where", ["spend", "receive_min", "approvals"])
@pytest.mark.parametrize("amount", [1.5, 2**53, -1])
async def test_a_tool_refuses_an_intent_amount_a_json_number_may_have_rounded(
    mcp: FastMCP, fake_w3: FakeW3, where: str, amount: t.Any
) -> None:
    """An intent's amount follows the value rule: a float or 2^53 is refused by name."""
    for tool in ("safe_transaction", "simulate_transaction"):
        with pytest.raises(ToolError, match="rule 'bad-value'"):
            await mcp.call_tool(
                tool,
                {
                    "chain": "testchain",
                    "target": RECIPIENT,
                    "intent": _intent_with(where, amount),
                },
            )
    assert not fake_w3.eth.sent


@pytest.mark.parametrize("where", ["spend", "receive_min", "approvals"])
async def test_a_decimal_string_intent_amount_reaches_the_gate_exactly(
    mcp: FastMCP,
    test_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
) -> None:
    """10^18 + 1 in an intent, past what a JSON number holds, arrives exact."""
    exact = 10**18 + 1
    seen: list[t.Any] = []

    def send_via_safe(*_args: t.Any, **kwargs: t.Any) -> str:
        seen.append(kwargs["intent"])
        return "0x" + "11" * 32

    monkeypatch.setattr(test_signer, "send_via_safe", send_via_safe)
    for spelling in (str(exact), hex(exact)):
        await mcp.call_tool(
            "safe_transaction",
            {
                "chain": "testchain",
                "target": RECIPIENT,
                "intent": _intent_with(where, spelling),
            },
        )
    for intent in seen:
        parsed, problems = parse_intent(intent)
        assert not problems
        assert parsed is not None
        if where == "approvals":
            assert parsed["approvals"][0]["amount"] == exact
        else:
            assert parsed[where] == {"native": exact}  # type: ignore[literal-required]
    assert len(seen) == 2


@pytest.mark.parametrize("where", ["spend", "receive_min", "approvals"])
@pytest.mark.parametrize("amount", [5, 2**53 - 1])
async def test_a_json_integer_intent_amount_reaches_the_gate_exactly(
    mcp: FastMCP,
    test_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
    amount: int,
) -> None:
    """An intent amount sent as a JSON integer up to 2^53 - 1 arrives as itself."""
    seen: list[t.Any] = []

    def send_via_safe(*_args: t.Any, **kwargs: t.Any) -> str:
        seen.append(kwargs["intent"])
        return "0x" + "11" * 32

    monkeypatch.setattr(test_signer, "send_via_safe", send_via_safe)
    await mcp.call_tool(
        "safe_transaction",
        {
            "chain": "testchain",
            "target": RECIPIENT,
            "intent": _intent_with(where, amount),
        },
    )
    (intent,) = seen
    parsed, problems = parse_intent(intent)
    assert not problems
    assert parsed is not None
    if where == "approvals":
        assert parsed["approvals"][0]["amount"] == amount
    else:
        assert parsed[where] == {"native": amount}  # type: ignore[literal-required]


@pytest.mark.parametrize(
    ("intent", "unknown"),
    [
        ({"receive_minimum": {"native": "1000"}}, "receive_minimum"),
        (
            {
                "approvals": [
                    {
                        "token": RECIPIENT,
                        "spender": RECIPIENT,
                        "amount": "1",
                        "amout": "1",
                    }
                ]
            },
            "amout",
        ),
    ],
)
async def test_a_misspelled_intent_key_on_a_tool_is_refused_not_dropped(
    mcp: FastMCP, fake_w3: FakeW3, intent: dict, unknown: str
) -> None:
    """A key the intent does not know reaches the gate, which refuses it by name."""
    with pytest.raises(ToolError, match="rule 'bad-intent'") as refused:
        await mcp.call_tool(
            "safe_transaction",
            {"chain": "testchain", "target": RECIPIENT, "intent": intent},
        )
    assert unknown in str(refused.value)
    (content,) = await mcp.call_tool(
        "simulate_transaction",
        {"chain": "testchain", "target": RECIPIENT, "intent": intent},
    )
    (problem,) = json.loads(content.text)["problems"]  # type: ignore[union-attr]
    assert problem.startswith("intent gate: rule 'bad-intent' (")
    assert unknown in problem
    assert not fake_w3.eth.sent
