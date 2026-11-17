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

from connect import settings as settings_module
from connect import texts
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import GuardError
from connect.idempotency import InFlightError
from connect.input_errors import InputError
from connect.mech import MechError
from connect.server.auth import ACTION_SCOPES, GrantRefused
from connect.server.mcp_tools import (
    GET_ABI_DESCRIPTION,
    REQUEST_CONTEXT_NOTE,
    TOOL_FAILED,
    with_aliases,
)
from connect.signer import Signer, SignerError
from connect.switches import PRODUCTION, Switches, TEST_INTERFACE

from tests.conftest import FakeW3

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
    assert text.startswith("intent gate: rule '")
    assert text.endswith(texts.NOT_SENT_SUFFIX)
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


async def test_the_in_process_error_is_the_handler_s_own_text(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, test_signer: Signer
) -> None:
    """A refusal Connect wrote is raised character for character."""

    def refuse(*_: t.Any, **__: t.Any) -> str:
        raise SignerError(texts.GUARD_NO_SELF_CALL)

    monkeypatch.setattr(test_signer, "send_via_safe", refuse)
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert str(raised.value) == texts.GUARD_NO_SELF_CALL
    assert isinstance(raised.value.__cause__, SignerError)


async def test_an_unexpected_error_is_logged_and_never_forwarded(
    mcp: FastMCP,
    monkeypatch: pytest.MonkeyPatch,
    test_signer: Signer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A library's text (which may name an RPC key) stays in the log."""
    rpc = "https://rpc.example/v2/" + "SECRETKEY"  # kept off the raising line

    def broken(*_: t.Any, **__: t.Any) -> str:
        raise RuntimeError(f"{rpc} is down")

    monkeypatch.setattr(test_signer, "send_via_safe", broken)
    with caplog.at_level(logging.ERROR, logger="agent"):
        with pytest.raises(ToolError) as raised:
            await mcp.call_tool(
                "safe_transaction", {"chain": "testchain", "target": RECIPIENT}
            )
    assert str(raised.value) == TOOL_FAILED.format(tool="safe_transaction")
    assert "tool safe_transaction failed: RuntimeError" in caplog.text
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
    """Every tool publishes the texts module's description, get_abi aside."""
    tools = await mcp.list_tools()
    # get_abi keeps Connect's own text until its answers match the reference's
    assert {tool.name: tool.description for tool in tools} == {
        **texts.TOOL_DESCRIPTIONS,
        "get_abi": GET_ABI_DESCRIPTION,
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
    assert field["description"] == REQUEST_CONTEXT_NOTE


@pytest.mark.parametrize(
    "error",
    [
        InputError("unknown chain 'x'"),
        SignerError(texts.GUARD_NO_SELF_CALL),
        GuardError(texts.GUARD_NO_DELEGATECALL),
        GrantRefused("token-scope", "this token does not allow it"),
        MechError("refused before payment"),
        InFlightError("request r1 is still in flight"),
    ],
    ids=lambda e: type(e).__name__,
)
async def test_each_error_connect_words_reaches_the_caller_verbatim(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, test_signer: Signer, error: Exception
) -> None:
    """Every forwarded type keeps its text; dropping one from the list fails here."""

    def refuse(*_: t.Any, **__: t.Any) -> str:
        raise error

    monkeypatch.setattr(test_signer, "send_via_safe", refuse)
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert str(raised.value) == str(error)


async def test_a_library_value_error_is_not_forwarded(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, test_signer: Signer
) -> None:
    """A builtin ValueError is a library's words, so the caller reads TOOL_FAILED."""

    def broken(*_: t.Any, **__: t.Any) -> str:
        raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(test_signer, "send_via_safe", broken)
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert str(raised.value) == TOOL_FAILED.format(tool="safe_transaction")
