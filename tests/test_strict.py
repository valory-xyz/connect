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

import typing as t

import pytest
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import MechService
from connect.server.auth import GrantStore
from connect.server.mcp_tools import build_mcp
from connect.server.strict import unknown_parameters_message
from connect.settings import SettingsStore
from connect.signer import Signer

from tests.conftest import FakeW3, audit_entries

TOKEN = "strict-test-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20


@pytest.fixture
def mcp(  # pylint: disable=too-many-arguments
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    guard: Guard,
    mech_service: MechService,
    settings_store: SettingsStore,
) -> FastMCP:
    """Return the MCP server as Connect builds it."""
    return build_mcp(
        test_signer,
        app_config,
        activity,
        guard=guard,
        mech=mech_service,
        settings_store=settings_store,
        grants=GrantStore("workspace-token"),
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


async def test_mcp_tool_refuses_to_on_safe_transaction(
    mcp: FastMCP, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """`to` on safe_transaction was silently dropped; now it is refused by name."""
    with pytest.raises(ToolError, match=r"'to' \(did you mean 'target'\?\)"):
        await mcp.call_tool("safe_transaction", {"chain": "testchain", "to": RECIPIENT})
    assert not fake_w3.eth.sent
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert entry == {**entry, "rule": "unknown-parameter", "tool": "safe_transaction"}


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
