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
import typing as t

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from connect import texts
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import MechService
from connect.server.mcp_tools import build_mcp, with_aliases
from connect.settings import SettingsStore
from connect.signer import Signer
from connect.switches import PRODUCTION, Switches, TEST_INTERFACE

from tests.conftest import FakeW3, grant_store

TOKEN = "surface-test-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Authorization": f"Bearer {TOKEN}",
}


@pytest.fixture
def mcp(  # pylint: disable=too-many-arguments
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    guard: Guard,
    mech_service: MechService,
    settings_store: SettingsStore,
) -> FastMCP:
    """Return the MCP server as Pearl builds it."""
    return build_mcp(
        test_signer,
        app_config,
        activity,
        guard=guard,
        mech=mech_service,
        settings_store=settings_store,
        grants=grant_store("workspace-token"),
    )


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


def _tool_text(client: TestClient, name: str, arguments: dict) -> tuple[bool, str]:
    """Call a tool over the transport; return (isError, the text the client reads)."""
    result = _rpc(client, "tools/call", {"name": name, "arguments": arguments})[
        "result"
    ]
    return result["isError"], result["content"][0]["text"]


def test_a_tool_error_reaches_the_client_with_no_transport_prefix(
    client: TestClient,
) -> None:
    """The client reads the refusing code's own text, not FastMCP's wrapper."""
    is_error, text = _tool_text(
        client, "safe_transaction", {"chain": "nochain", "target": RECIPIENT}
    )
    assert is_error
    assert not text.startswith("Error executing tool")


async def test_the_in_process_error_is_the_handler_s_own_text(
    mcp: FastMCP, monkeypatch: pytest.MonkeyPatch, test_signer: Signer
) -> None:
    """The raised text equals what the handler raised, character for character."""

    def refuse(*_: t.Any, **__: t.Any) -> str:
        raise ValueError(texts.GUARD_NO_SELF_CALL)

    monkeypatch.setattr(test_signer, "send_via_safe", refuse)
    with pytest.raises(ToolError) as raised:
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert str(raised.value) == texts.GUARD_NO_SELF_CALL
    assert isinstance(raised.value.__cause__, ValueError)


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
    """The 13 tools publish the texts module's descriptions and nothing else."""
    tools = await mcp.list_tools()
    assert {tool.name: tool.description for tool in tools} == texts.TOOL_DESCRIPTIONS


async def test_to_reaches_the_signer_as_a_safe_call_s_target(
    mcp: FastMCP, fake_w3: FakeW3
) -> None:
    """A safe_transaction with `to` and no `target` makes the safe call `to`."""
    await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert len(fake_w3.eth.sent) == 1
    assert bytes.fromhex(RECIPIENT[2:]) in fake_w3.eth.sent[0]


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


async def test_preflight_takes_to_as_its_target(mcp: FastMCP) -> None:
    """A preflight with `to` and no `target` is answered, not refused."""
    content = await mcp.call_tool(
        "preflight_transaction", {"chain": "testchain", "to": RECIPIENT}
    )
    assert json.loads(content[0].text) == {"permitted": True}  # type: ignore[index]


def test_the_test_interface_takes_the_reference_s_positions() -> None:
    """The bench's positions: no strict parameters, no EOA route, no boot top-up."""
    assert TEST_INTERFACE == Switches(
        strict_parameters=False, rest_signing_routes=False, agent_topup_at_boot=False
    )
    assert PRODUCTION.rest_signing_routes
    assert PRODUCTION.agent_topup_at_boot
