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


"""The MCP surface the agent sees is OnchainBench's reference surface."""

import json
import logging
import typing as t

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from connect import settings as settings_module
from connect import texts
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import GuardError
from connect.idempotency import InFlightError
from connect.input_errors import InputError
from connect.mech import MechError
from connect.server.auth import ACTION_SCOPES, GrantRefused
from connect.server.mcp_tools import with_aliases
from connect.signer import Signer, SignerError
from connect.switches import PRODUCTION, Switches, TEST_INTERFACE

from tests.conftest import FakeW3, approval_log

TOKEN = "surface-test-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20
SAFE = "0x" + "22" * 20  # the test chain's service safe
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Authorization": f"Bearer {TOKEN}",
}


@pytest.fixture
def mcp(make_mcp: t.Callable[..., FastMCP]) -> FastMCP:
    """Return the MCP server as Pearl builds it."""
    return make_mcp()


@pytest.fixture
def client(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
) -> t.Iterator[TestClient]:
    """HTTP client with a valid token, over an app whose signer has its guard."""
    app = make_app(test_signer, app_config, activity, token=TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        yield client


def _rpc(client: TestClient, method: str, params: dict) -> dict:
    """Send one JSON-RPC request to the MCP mount and return its message."""
    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=MCP_HEADERS,
    )
    assert response.status_code == 200
    if response.headers["content-type"].startswith("application/json"):
        return response.json()
    data = [line for line in response.text.splitlines() if line.startswith("data:")]
    return json.loads(data[-1].removeprefix("data:"))


def _tool_error(client: TestClient, name: str, arguments: dict) -> str:
    """Call a tool over the transport and return the error text the client reads."""
    result = _rpc(client, "tools/call", {"name": name, "arguments": arguments})[
        "result"
    ]
    assert result["isError"], result
    return result["content"][0]["text"]


def test_a_guardrail_refusal_reads_as_its_constant_through_the_transport(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """A self-call reaches the client as the reference text, nothing prepended."""
    text = _tool_error(
        client, "safe_transaction", {"chain": "testchain", "target": SAFE}
    )
    assert text == texts.GUARD_NO_SELF_CALL
    assert not fake_w3.eth.sent


def test_a_gate_refusal_ends_not_sent_through_the_transport(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """A call breaking its intent reads as the gate's refusal, ending not-sent."""
    text = _tool_error(
        client,
        "safe_transaction",
        {
            "chain": "testchain",
            "target": RECIPIENT,
            "value": "5",
            "intent": {"spend": {"native": "5"}},
        },
    )
    assert text == (
        f"intent gate: rule 'undeclared-recipient' ({RECIPIENT}){texts.NOT_SENT_SUFFIX}"
    )
    assert not fake_w3.eth.sent


def test_a_no_intent_send_is_held_to_strict_through_the_transport(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """Pearl's strict policy: a no-intent call that grants an approval is refused."""
    token, spender = "0x" + "70" * 20, "0x" + "5e" * 20
    fake_w3.provider.logs = [approval_log(token, SAFE, spender, 10)]
    text = _tool_error(
        client,
        "safe_transaction",
        {"chain": "testchain", "target": token, "data": "0x12345678"},
    )
    assert text == (
        f"intent gate: rule 'undeclared-approval' ({token} to {spender}, 10)"
        f"{texts.NOT_SENT_SUFFIX}"
    )
    assert not fake_w3.eth.sent


def test_an_unknown_tool_is_named_through_the_transport(client: TestClient) -> None:
    """The mount passes an unknown name on, and the client reads the reference."""
    assert _tool_error(client, "no_such_tool", {}) == texts.UNKNOWN_TOOL("no_such_tool")


@pytest.mark.parametrize("expose_mode", [False, True])
def test_every_registered_tool_has_a_scope(
    make_mcp: t.Callable[..., FastMCP],
    monkeypatch: pytest.MonkeyPatch,
    expose_mode: bool,
) -> None:
    """A tool with no scope would be refused by every token, `settings` included."""
    monkeypatch.setattr(settings_module, "EXPOSE_MODE_TO_AGENT", expose_mode)
    names = make_mcp().tool_names()
    assert ("settings" in names) is expose_mode
    assert names <= set(ACTION_SCOPES)


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, ValidationError])
async def test_an_unexpected_error_is_logged_and_never_forwarded(
    mcp: FastMCP,
    monkeypatch: pytest.MonkeyPatch,
    test_signer: Signer,
    caplog: pytest.LogCaptureFixture,
    error_type: type[Exception],
) -> None:
    """A library's text (which may name an RPC key) stays in the log, redacted."""
    rpc = "https://rpc.example/v2/" + "SECRETKEY"  # kept off the raising line

    def broken(*_: t.Any, **__: t.Any) -> str:
        if error_type is ValidationError:  # a model inside the body, not the args
            raise ValidationError.from_exception_data(f"{rpc} model", [])
        raise error_type(f"{rpc} is down")

    monkeypatch.setattr(test_signer, "send_via_safe", broken)
    with caplog.at_level(logging.ERROR, logger="agent"):
        with pytest.raises(ToolError) as raised:
            await mcp.call_tool(
                "safe_transaction", {"chain": "testchain", "target": RECIPIENT}
            )
    assert str(raised.value) == texts.tool_failed("safe_transaction")
    assert f"tool safe_transaction failed: {error_type.__name__}" in caplog.text
    assert "SECRETKEY" not in caplog.text


async def test_an_unknown_tool_is_named_in_the_reference_s_words(
    mcp: FastMCP,
) -> None:
    """An unknown tool reads `unknown tool <name>`, lower case and no colon."""
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("no_such_tool", {})
    assert str(raised.value) == texts.UNKNOWN_TOOL("no_such_tool")


def test_initialize_reports_the_reference_s_server_info(client: TestClient) -> None:
    """The initialize answer carries the reference's serverInfo and no instructions."""
    result = _rpc(
        client,
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"},
        },
    )["result"]
    assert result["serverInfo"] == texts.SERVER_INFO
    assert "instructions" not in result


async def test_every_published_description_is_the_reference_s(mcp: FastMCP) -> None:
    """Every tool publishes the texts module's description, two of Connect's aside."""
    tools = await mcp.list_tools()
    assert {tool.name: tool.description for tool in tools} == {
        **texts.TOOL_DESCRIPTIONS,
        "get_abi": texts.GET_ABI_DESCRIPTION,
        "transaction_status": texts.TRANSACTION_STATUS_DESCRIPTION,
    }


async def test_to_reaches_the_signer_as_a_safe_call_s_target(
    mcp: FastMCP, fake_w3: FakeW3
) -> None:
    """A safe_transaction with `to` and no `target` makes the safe call `to`."""
    await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert len(fake_w3.eth.sent) == 1
    assert bytes.fromhex(RECIPIENT[2:]) in fake_w3.eth.sent[0]


async def test_preflight_takes_to_as_its_target(mcp: FastMCP) -> None:
    """A preflight with `to` and no `target` is answered, not refused."""
    content = await mcp.call_tool(
        "preflight_transaction", {"chain": "testchain", "to": RECIPIENT}
    )
    assert json.loads(content[0].text) == {"permitted": True}  # type: ignore[index]


def test_target_wins_over_to_and_other_tools_are_left_alone() -> None:
    """The alias fills `target` only when absent, and only on the safe-call tools."""
    other = "0x" + "bb" * 20
    assert with_aliases("safe_transaction", {"target": RECIPIENT, "to": other}) == {
        "target": RECIPIENT
    }
    for tool in ("preflight_transaction", "simulate_transaction"):
        assert with_aliases(tool, {"to": other}) == {"target": other}
    assert with_aliases("send_transaction", {"to": other}) == {"to": other}
    assert with_aliases("simulate_transaction", {"chain": "c"}) == {"chain": "c"}


def test_the_test_interface_takes_the_reference_s_positions() -> None:
    """The bench's positions: simulate-only, lenient, no EOA route, no boot top-up."""
    assert TEST_INTERFACE == Switches(
        no_intent_policy="simulate-only",
        strict_parameters=False,
        rest_signing_routes=False,
        agent_topup_at_boot=False,
    )
    assert PRODUCTION.no_intent_policy == "strict"
    assert PRODUCTION.rest_signing_routes
    assert PRODUCTION.agent_topup_at_boot


async def test_request_context_warns_that_it_may_be_published(mcp: FastMCP) -> None:
    """The IPFS warning rides on the field, since the tool text is the reference's."""
    (tool,) = [t for t in await mcp.list_tools() if t.name == "mech_request"]
    field = tool.inputSchema["properties"]["request_context"]
    assert field["description"] == texts.REQUEST_CONTEXT_NOTE


@pytest.mark.parametrize(
    "error",
    [
        InputError("unknown chain 'x'"),
        SignerError(texts.GUARD_NO_SELF_CALL),
        GuardError(texts.GUARD_NO_DELEGATECALL),
        GrantRefused("token-scope", "this token does not allow it"),
        MechError("refused before payment"),
        InFlightError("request r1 is still in flight"),
        ToolError("a tool's own refusal"),
    ],
    ids=lambda e: type(e).__name__,
)
async def test_each_error_connect_words_reaches_the_caller_verbatim(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, test_signer: Signer, error: Exception
) -> None:
    """Every type CALLER_ERRORS holds, and ToolError, keeps its text verbatim."""

    def refuse(*_: t.Any, **__: t.Any) -> str:
        raise error

    monkeypatch.setattr(test_signer, "send_via_safe", refuse)
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert str(raised.value) == str(error)
    assert isinstance(raised.value.__cause__, type(error))


def test_an_app_built_at_the_test_interface_gates_at_its_positions(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
    fake_w3: FakeW3,
) -> None:
    """One switch set per build: the app's signer runs the bench's simulate-only."""
    token, spender = "0x" + "70" * 20, "0x" + "5e" * 20
    fake_w3.provider.logs = [approval_log(token, SAFE, spender, 10)]
    app = make_app(
        test_signer, app_config, activity, token=TOKEN, switches=TEST_INTERFACE
    )
    assert app.state.signer.switches is TEST_INTERFACE
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        answer = client.post(
            "/safe-transaction",
            json={"chain": "testchain", "target": token, "data": "0x12345678"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert answer.status_code == 200, answer.text
    assert len(fake_w3.eth.sent) == 1


def test_an_unknown_no_intent_policy_is_refused() -> None:
    """A typo is an error, never read as the permissive position."""
    with pytest.raises(ValueError, match="no_intent_policy 'Strict' is unknown"):
        Switches(no_intent_policy="Strict")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("tool", "arguments", "expected"),
    [
        (
            "safe_transaction",
            {"chain": "gnosiss", "target": RECIPIENT},
            "unknown chain 'gnosiss'; configured chains: ['testchain']",
        ),
        (
            "sign_message",
            {"digest": "0xzz"},
            "digest must be hex (0x and whole bytes), got '0xzz'",
        ),
        (
            "get_abi",
            {"chain": "testchain", "address": "0x12"},
            "address must be a 0x address (40 hex digits), got '0x12'",
        ),
    ],
)
async def test_connect_s_input_refusals_reach_the_caller(
    mcp: FastMCP, tool: str, arguments: dict, expected: str
) -> None:
    """Each InputError site reads as its own words, never as texts.tool_failed."""
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool(tool, arguments)
    assert str(raised.value) == expected


async def test_a_malformed_argument_reads_as_the_reference_s_invalid_request(
    mcp: FastMCP,
) -> None:
    """The arguments' check is Connect's: named, and never echoing the value."""
    marker = "MARKER-" + "x" * 200
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool(
            "safe_transaction",
            {"chain": "testchain", "target": RECIPIENT, "value": marker},
        )
    assert str(raised.value) == (
        f"invalid request: ValidationError: value: Value error, {texts.AMOUNT_REFUSED}"
    )


async def test_two_bad_arguments_are_named_in_order_joined(mcp: FastMCP) -> None:
    """Each failing argument is named, the problems joined with `; `."""
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool(
            "mech_request",
            {"prompt": "q", "tool": "t", "max_payment": "nope", "timeout": "soon"},
        )
    assert str(raised.value) == (
        "invalid request: ValidationError: timeout: Input should be a valid "
        "number, unable to parse string as a number; "
        f"max_payment: Value error, {texts.CAP_REFUSED}"
    )


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        (
            {"chain": "testchain", "target": "0x12"},
            "target must be a 0x address (40 hex digits), got '0x12'",
        ),
        (
            {"chain": "testchain", "target": RECIPIENT, "data": "0xzz"},
            "data must be hex (0x and whole bytes), got '0xzz'",
        ),
    ],
)
async def test_every_address_and_hex_argument_is_checked_as_the_reference(
    mcp: FastMCP, fake_w3: FakeW3, arguments: dict, expected: str
) -> None:
    """The reference's check_args runs before any tool, for every tool."""
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", arguments)
    assert str(raised.value) == expected
    with pytest.raises(ToolError, match="priority_mech must be a 0x address"):
        await mcp.call_tool("mech_tools", {"priority_mech": "nope"})
    assert not fake_w3.eth.sent


async def test_a_failure_in_the_argument_check_itself_is_logged_not_forwarded(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A deeply nested intent (RecursionError) reads texts.tool_failed, cause logged."""
    manager = mcp._tool_manager  # pylint: disable=protected-access
    tool = manager.get_tool("safe_transaction")

    def deep(*_: t.Any) -> dict:
        raise RecursionError("maximum recursion depth exceeded while decoding")

    monkeypatch.setattr(type(tool.fn_metadata), "pre_parse_json", deep)
    with caplog.at_level(logging.ERROR, logger="agent"):
        with pytest.raises(ToolError) as raised:
            await mcp.call_tool(
                "safe_transaction", {"chain": "testchain", "target": RECIPIENT}
            )
    assert str(raised.value) == texts.tool_failed("safe_transaction")
    assert "tool safe_transaction failed: RecursionError" in caplog.text


async def test_a_stringified_intent_is_taken_like_the_object(
    mcp: FastMCP, fake_w3: FakeW3
) -> None:
    """The argument check still runs FastMCP's JSON pre-parse."""
    intent = {"spend": {"native": "5"}, "recipients": [RECIPIENT]}
    await mcp.call_tool(
        "safe_transaction",
        {
            "chain": "testchain",
            "target": RECIPIENT,
            "value": "5",
            "intent": json.dumps(intent),
        },
    )
    assert len(fake_w3.eth.sent) == 1


def test_a_delegatecall_operation_is_refused_by_the_guardrail_s_rule(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """`operation` is read, so the floor rule refuses it, not a parameter check."""
    text = _tool_error(
        client,
        "safe_transaction",
        {"chain": "testchain", "target": RECIPIENT, "operation": 1},
    )
    assert text == texts.GUARD_NO_DELEGATECALL
    assert not fake_w3.eth.sent
    _rpc(
        client,
        "tools/call",
        {
            "name": "safe_transaction",
            "arguments": {"chain": "testchain", "target": RECIPIENT, "operation": 0},
        },
    )
    assert len(fake_w3.eth.sent) == 1


@pytest.mark.parametrize("switches", [PRODUCTION, TEST_INTERFACE])
async def test_operation_is_accepted_but_not_published(
    make_mcp: t.Callable[..., FastMCP], switches: Switches
) -> None:
    """The reference reads `operation` without publishing it."""
    (tool,) = [
        t for t in await make_mcp(switches).list_tools() if t.name == "safe_transaction"
    ]
    assert "operation" not in tool.inputSchema["properties"]


@pytest.mark.parametrize("operation", [-1, 2, 256])
async def test_an_operation_that_is_neither_call_nor_delegatecall_is_refused(
    mcp: FastMCP, fake_w3: FakeW3, operation: int
) -> None:
    """A Safe has CALL (0) and DELEGATECALL (1); anything else is bad input."""
    with pytest.raises(ToolError) as refused:
        await mcp.call_tool(
            "safe_transaction",
            {"chain": "testchain", "target": RECIPIENT, "operation": operation},
        )
    assert str(refused.value).startswith(
        "invalid request: ValidationError: operation: Input should be "
    )
    assert not fake_w3.eth.sent


async def test_a_strict_refusal_never_advertises_an_unpublished_parameter(
    make_mcp: t.Callable[..., FastMCP], fake_w3: FakeW3
) -> None:
    """`operation` is taken under strict_parameters but never named or hinted."""
    strict = make_mcp(Switches(strict_parameters=True))
    with pytest.raises(ToolError) as refused:
        await strict.call_tool(
            "safe_transaction",
            {"chain": "testchain", "target": RECIPIENT, "operatoin": 1},
        )
    assert "operation" not in str(refused.value)
    await strict.call_tool(
        "safe_transaction",
        {"chain": "testchain", "target": RECIPIENT, "operation": 0},
    )
    assert len(fake_w3.eth.sent) == 1


async def test_wallet_info_takes_chain_even_under_strict_parameters(
    make_mcp: t.Callable[..., FastMCP],
) -> None:
    """With unknown parameters refused, `chain` is still one wallet_info takes."""
    strict = make_mcp(Switches(strict_parameters=True))
    (bare,) = await strict.call_tool("wallet_info", {})
    (carried,) = await strict.call_tool("wallet_info", {"chain": "gnosis"})
    assert json.loads(carried.text) == json.loads(bare.text)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("tool", "plain", "extra"),
    [
        ("wallet_info", {}, {"chain": "gnosis"}),
        (
            "decode_calldata",
            {"data": "0xa9059cbb"},
            {"address": RECIPIENT, "chain": "testchain"},
        ),
    ],
)
async def test_an_argument_the_handler_does_not_read_changes_nothing(
    mcp: FastMCP, tool: str, plain: dict, extra: dict
) -> None:
    """`chain` on wallet_info, `address`/`chain` on decode_calldata, ignored."""
    (bare,) = await mcp.call_tool(tool, plain)
    (carried,) = await mcp.call_tool(tool, {**plain, **extra})
    assert json.loads(carried.text) == json.loads(bare.text)  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("arguments", "refusal"),
    [
        ({"to": "0x12"}, "to must be a 0x address (40 hex digits), got '0x12'"),
        (
            {"target": RECIPIENT, "to": "0xzz"},
            "to must be a 0x address (40 hex digits), got '0xzz'",
        ),
        (
            {"target": RECIPIENT, "data": "0Xabcd"},
            "data must be hex (0x and whole bytes), got '0Xabcd'",
        ),
    ],
)
async def test_the_arguments_are_checked_as_sent_before_any_alias(
    mcp: FastMCP, fake_w3: FakeW3, arguments: dict, refusal: str
) -> None:
    """The reference checks `to` by its own name, even beside a valid `target`."""
    with pytest.raises(ToolError) as refused:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", **arguments})
    assert str(refused.value) == refusal
    assert not fake_w3.eth.sent


async def test_an_empty_target_reads_the_alias(mcp: FastMCP, fake_w3: FakeW3) -> None:
    """`a.get("target") or a.get("to")`: an empty target does not hide `to`."""
    await mcp.call_tool(
        "safe_transaction", {"chain": "testchain", "target": "", "to": RECIPIENT}
    )
    assert len(fake_w3.eth.sent) == 1


async def test_a_checksummed_address_is_accepted_at_the_boundary(
    mcp: FastMCP, fake_w3: FakeW3
) -> None:
    """Mixed case is a valid address: the check reads hex, not a checksum."""
    checksummed = "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
    await mcp.call_tool(
        "safe_transaction", {"chain": "testchain", "target": checksummed}
    )
    assert len(fake_w3.eth.sent) == 1


async def test_a_checksummed_priority_mech_is_accepted_at_the_boundary(
    mcp: FastMCP, mech_service: t.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mech tools take a checksummed mech address as sent."""
    checksummed = "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
    asked: list[t.Any] = []

    def tools(**kwargs: t.Any) -> dict:
        asked.append(kwargs["priority_mech"])
        return {}

    monkeypatch.setattr(mech_service, "tools", tools)
    await mcp.call_tool("mech_tools", {"priority_mech": checksummed})
    assert asked == [checksummed]
