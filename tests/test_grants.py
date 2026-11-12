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

"""Scoped tokens."""

import json
import time
import typing as t

import pytest
from fastapi.testclient import TestClient

from connect import intent as intent_module
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.server.auth import (
    AuthFailureLimiter,
    AuthMiddleware,
    GrantRefused,
    GrantStore,
    TokenGrant,
    WORKSPACE_GRANT,
    narrower,
)
from connect.signer import Signer

from tests.conftest import FakeW3, audit_entries, pay

WORKSPACE = "workspace-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20
USDC = "0x" + "c0" * 20


def grant(**kwargs: t.Any) -> TokenGrant:
    """Return a grant with every scope unless told otherwise."""
    return TokenGrant(**{"scopes": ["read", "mech", "tx"], **kwargs})


def test_the_workspace_token_can_do_what_a_session_always_could() -> None:
    """Check read + mech + tx with no caps: the workspace token loses nothing."""
    store = GrantStore(WORKSPACE)
    assert store.lookup(f"Bearer {WORKSPACE}") == WORKSPACE
    assert store.grant(WORKSPACE) == WORKSPACE_GRANT
    for action in ("wallet_info", "mech_request", "safe_transaction"):
        store.authorize(WORKSPACE, action, {"value": 10**30})


def test_unknown_or_malformed_tokens_are_not_found() -> None:
    """Only a Bearer header carrying a token we issued resolves."""
    store = GrantStore(WORKSPACE)
    assert store.lookup(None) is None
    assert store.lookup(WORKSPACE) is None  # no Bearer prefix
    assert store.lookup("Bearer nope") is None


def test_narrower_is_a_partial_order_on_every_field() -> None:
    """Fewer scopes, tighter caps, an earlier expiry; never the reverse."""
    parent = grant(
        scopes=["read", "tx"],
        max_value_per_tx={"native": 10},
        max_value_per_session={"native": 50},
        max_mech_payment=5,
        expires_at=1000,
    )
    assert narrower(grant(scopes=["read"], **_capped(10, 50, 5, 1000)), parent)
    assert not narrower(grant(scopes=["mech"], **_capped(10, 50, 5, 1000)), parent)
    assert not narrower(grant(scopes=["read"], **_capped(11, 50, 5, 1000)), parent)
    assert not narrower(grant(scopes=["read"], **_capped(10, 51, 5, 1000)), parent)
    assert not narrower(grant(scopes=["read"], **_capped(10, 50, 6, 1000)), parent)
    assert not narrower(grant(scopes=["read"], **_capped(10, 50, 5, 1001)), parent)
    assert not narrower(grant(scopes=["read"]), parent)  # uncapped is wider
    assert not narrower(
        grant(
            scopes=["read"],
            **{**_capped(10, 50, 5, 1000), "max_value_per_tx": {USDC: 1}},
        ),
        parent,
    )
    assert narrower(grant(**_capped(1, 1, 1, 1)), WORKSPACE_GRANT)


def _capped(per_tx: int, session: int, mech: int, expiry: int) -> dict:
    return {
        "max_value_per_tx": {"native": per_tx},
        "max_value_per_session": {"native": session},
        "max_mech_payment": mech,
        "expires_at": expiry,
    }


def test_mint_only_narrows() -> None:
    """A minted token works; a wider grant is refused as token-scope."""
    store = GrantStore(WORKSPACE)
    child = store.mint(WORKSPACE, grant(scopes=["read"]))
    assert store.lookup(f"Bearer {child}") == child
    with pytest.raises(GrantRefused, match="narrower") as refused:
        store.mint(child, grant(scopes=["read", "tx"]))
    assert refused.value.rule == "token-scope"


def test_a_read_token_reads_and_does_nothing_else() -> None:
    """wallet_info, mech_tools and the status calls; no mech, no tx."""
    store = GrantStore(WORKSPACE)
    reader = store.mint(WORKSPACE, grant(scopes=["read"]))
    for action in ("wallet_info", "mech_tools", "mech_result", "transaction_status"):
        store.authorize(reader, action, {})
    for action in ("mech_request", "safe_transaction", "sign_message", "nope"):
        with pytest.raises(GrantRefused) as refused:
            store.authorize(reader, action, {})
        assert refused.value.rule == "token-scope"


def test_an_expired_token_is_refused() -> None:
    """Past expires_at the token answers nothing, and mints nothing."""
    store = GrantStore(WORKSPACE)
    old = store.mint(WORKSPACE, grant(expires_at=int(time.time()) - 1))
    with pytest.raises(GrantRefused) as refused:
        store.authorize(old, "wallet_info", {})
    assert (refused.value.rule, refused.value.status) == ("token-expired", 401)


def test_mech_payment_cap() -> None:
    """A capped token must name a max_payment within its cap."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_mech_payment=100))
    store.authorize(capped, "mech_request", {"max_payment": 100})
    for asked in (None, 101, True):
        with pytest.raises(GrantRefused) as refused:
            store.authorize(capped, "mech_request", {"max_payment": asked})
        assert refused.value.rule == "token-mech-payment-cap"


def test_value_caps_per_tx_and_per_session() -> None:
    """Caps hold the declared spend (and the native value) per call and in all."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(
        WORKSPACE,
        grant(
            max_value_per_tx={"native": 10, USDC: 5},
            max_value_per_session={"native": 15, USDC: 100},
        ),
    )
    store.authorize(capped, "safe_transaction", {"value": "0xa", "intent": {}})
    with pytest.raises(GrantRefused) as per_tx:
        store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 6}}})
    assert per_tx.value.rule == "token-cap-per-tx"
    with pytest.raises(GrantRefused) as session:
        store.authorize(capped, "send_transaction", {"value": "6"})
    assert session.value.rule == "token-cap-per-session"
    store.authorize(capped, "safe_transaction", {"value": 5})  # 10 + 5 of 15
    with pytest.raises(GrantRefused):
        store.authorize(capped, "safe_transaction", {"value": 1})
    # a digest can authorize any safe transaction, which no cap would see
    with pytest.raises(GrantRefused, match="may not sign raw digests") as digest:
        store.authorize(capped, "sign_message", {})
    assert digest.value.rule == "token-cap-per-tx"
    store.authorize(WORKSPACE, "sign_message", {})  # an uncapped token still may


@pytest.mark.parametrize(
    ("approval", "allowed"),
    [
        ({"token": USDC, "spender": RECIPIENT, "amount": 5}, True),
        ({"token": USDC, "spender": RECIPIENT, "amount": 6}, False),
        ({"token": USDC, "spender": RECIPIENT, "amount": 2**256 - 1}, False),
        ({"token": "0x" + "d0" * 20, "spender": RECIPIENT, "amount": 1}, False),
    ],
)
def test_a_capped_token_approves_no_more_than_its_caps(
    approval: dict, allowed: bool
) -> None:
    """An approval is spend the spender takes later: the caps bound it too."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(
        WORKSPACE,
        grant(max_value_per_tx={USDC: 5}, max_value_per_session={USDC: 100}),
    )
    arguments = {"intent": {"approvals": [approval]}}
    if allowed:
        store.authorize(capped, "safe_transaction", arguments)
        return
    with pytest.raises(GrantRefused, match="may approve at most") as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == "token-cap-per-tx"
    session_only = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 5}))
    with pytest.raises(GrantRefused, match="may approve at most"):
        store.authorize(session_only, "safe_transaction", arguments)
    store.authorize(WORKSPACE, "safe_transaction", arguments)  # uncapped


def test_cap_keys_are_normalised_when_minted() -> None:
    """A checksummed address, NATIVE or the CELO face caps what the gate books."""
    store = GrantStore(WORKSPACE)
    checksummed = "0x" + "C0" * 20
    capped = store.mint(
        WORKSPACE,
        grant(max_value_per_tx={checksummed: 5, "NATIVE": 3}),
    )
    assert store.grant(capped).max_value_per_tx == {USDC: 5, "native": 3}
    store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 5}}})
    store.mint(capped, grant(max_value_per_tx={checksummed: 5}))  # not wider
    celo = "0x471ece3750da237f93b8e339c536989b8978a438"
    assert grant(max_value_per_tx={celo: 1}).max_value_per_tx == {"native": 1}
    assert grant(max_value_per_tx=None).max_value_per_tx is None  # no cap
    for caps in ({"usdc": 1}, {USDC: -1}, {"native": 1, celo: 1}):
        with pytest.raises(ValueError):  # noqa: PT011 - pydantic's own error
            grant(max_value_per_tx=caps)


def test_a_json_string_intent_is_capped_like_the_tool_reads_it() -> None:
    """Decode a string intent before capping it, as FastMCP does before the tool."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_tx={USDC: 10}))
    with pytest.raises(GrantRefused) as refused:
        store.authorize(
            capped,
            "safe_transaction",
            {"intent": json.dumps({"spend": {USDC: 10**12}})},
        )
    assert refused.value.rule == "token-cap-per-tx"


@pytest.mark.parametrize(
    ("arguments", "rule"),
    [
        ({"intent": {"spend": {USDC: -(10**30)}}}, "bad-intent"),
        ({"intent": {"spend": {USDC: "lots"}}}, "bad-intent"),
        ({"intent": "not json"}, "bad-intent"),
        ({"value": -(10**30)}, "bad-value"),
        ({"value": "abc"}, "bad-value"),
        ({"value": True}, "bad-value"),
    ],
)
def test_malformed_amounts_are_refused_before_any_budget_moves(
    arguments: dict, rule: str
) -> None:
    """A negative or malformed amount can never refill a session budget."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == rule
    store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 100}}})
    with pytest.raises(GrantRefused):
        store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 1}}})


def test_children_draw_on_their_parents_session_budget() -> None:
    """Minting more children does not multiply a parent's session cap."""
    store = GrantStore(WORKSPACE)
    parent = store.mint(WORKSPACE, grant(max_value_per_session={"native": 10}))
    children = [
        store.mint(parent, grant(max_value_per_session={"native": 10}))
        for _ in range(3)
    ]
    store.authorize(children[0], "safe_transaction", {"value": 6})
    store.authorize(children[1], "safe_transaction", {"value": 4})
    with pytest.raises(GrantRefused, match="every token minted from it"):
        store.authorize(children[2], "safe_transaction", {"value": 1})


def test_per_tx_only_caps_do_not_track_a_session() -> None:
    """A per-transaction cap alone has no running total."""
    store = GrantStore(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_tx={"native": 10}))
    for _ in range(3):
        store.authorize(capped, "safe_transaction", {"value": 10})


@pytest.fixture
def client(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
) -> t.Iterator[TestClient]:
    """HTTP client over the real app."""
    app = make_app(test_signer, app_config, activity, token=WORKSPACE)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        yield client


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_http_mint_and_use_a_read_token(
    client: TestClient, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """POST /tokens mints a narrower token; it reads, and its sends are refused."""
    minted = client.post(
        "/tokens", json={"scopes": ["read"]}, headers=_bearer(WORKSPACE)
    )
    assert minted.status_code == 200
    reader = minted.json()["token"]
    assert minted.json()["grant"]["scopes"] == ["read"]
    assert client.get("/wallet", headers=_bearer(reader)).status_code == 200
    refused = client.post(
        "/safe-transaction",
        json={
            "chain": "testchain",
            "target": RECIPIENT,
            "value": 1,
            "intent": pay(RECIPIENT, 1),
        },
        headers=_bearer(reader),
    )
    assert refused.status_code == 403
    assert "token-scope" in refused.json()["detail"]
    for path, body in (
        ("/sign-and-send", {"chain": "testchain", "to": RECIPIENT}),
        ("/sign-message", {"digest": "0x" + "00" * 32}),
    ):
        assert client.post(path, json=body, headers=_bearer(reader)).status_code == 403
    assert not fake_w3.eth.sent
    wider = client.post(
        "/tokens", json={"scopes": ["read", "tx"]}, headers=_bearer(reader)
    )
    assert wider.status_code == 403
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["token-scope"] * 4


def test_http_capped_token_is_refused_above_its_cap(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """A capped tx token sends within its cap and is refused, by rule, above it."""
    capped = client.post(
        "/tokens",
        json={"scopes": ["tx"], "max_value_per_tx": {"native": 5}},
        headers=_bearer(WORKSPACE),
    ).json()["token"]
    ok = client.post(
        "/safe-transaction",
        json={
            "chain": "testchain",
            "target": RECIPIENT,
            "value": 5,
            "intent": pay(RECIPIENT, 5),
        },
        headers=_bearer(capped),
    )
    assert ok.status_code == 200
    over = client.post(
        "/safe-transaction",
        json={
            "chain": "testchain",
            "target": RECIPIENT,
            "value": 6,
            "intent": pay(RECIPIENT, 6),
        },
        headers=_bearer(capped),
    )
    assert over.status_code == 403
    assert "token-cap-per-tx" in over.json()["detail"]
    assert len(fake_w3.eth.sent) == 1


class TestMcpMiddleware:
    """The MCP mount authorizes each tools/call before the SDK sees it."""

    @staticmethod
    async def _call(
        middleware: AuthMiddleware, token: str, body: bytes
    ) -> tuple[list[dict], list[bytes]]:
        sent: list[dict] = []
        seen: list[bytes] = []

        async def inner(scope: t.Any, receive: t.Any, send: t.Any) -> None:
            seen.append((await receive())["body"])
            seen.append((await receive())["type"].encode())

        middleware._app = inner  # pylint: disable=protected-access
        chunks: list[dict[str, t.Any]] = [
            {"type": "http.request", "body": body[:5], "more_body": True},
            {"type": "http.request", "body": body[5:], "more_body": False},
            {"type": "http.disconnect"},
        ]

        async def receive() -> dict:
            return chunks.pop(0)

        async def send(message: dict) -> None:
            sent.append(message)

        scope = {
            "type": "http",
            "path": "/",
            "headers": [(b"authorization", f"Bearer {token}".encode())],
        }
        await middleware(scope, receive, send)
        return sent, seen

    @pytest.fixture
    def setup(self, activity: ActivityLog) -> tuple[AuthMiddleware, str]:
        """Return a middleware over a store with a read-only token minted."""
        store = GrantStore(WORKSPACE)
        reader = store.mint(WORKSPACE, grant(scopes=["read"]))
        middleware = AuthMiddleware(
            lambda *a: None, store, activity, AuthFailureLimiter()
        )
        return middleware, reader

    async def test_an_allowed_call_reaches_the_server_with_its_body(
        self, setup: tuple[AuthMiddleware, str]
    ) -> None:
        """The body read for the check is replayed, then the real stream follows."""
        middleware, reader = setup
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "wallet_info", "arguments": {}},
            }
        ).encode()
        sent, seen = await self._call(middleware, reader, body)
        assert sent == []
        assert seen == [body, b"http.disconnect"]

    async def test_a_refused_call_is_a_json_rpc_error(
        self, setup: tuple[AuthMiddleware, str], store_path: t.Any
    ) -> None:
        """The session reads the rule in the tool error; nothing reaches the server."""
        middleware, reader = setup
        body = json.dumps(
            [
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                "junk",
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {"name": "safe_transaction", "arguments": "x"},
                },
            ]
        ).encode()
        sent, seen = await self._call(middleware, reader, body)
        assert seen == []
        assert sent[0]["status"] == 200
        answer = json.loads(sent[1]["body"])
        assert answer["id"] == 7
        assert "token-scope" in answer["error"]["message"]
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["tool"] == "safe_transaction"

    async def test_a_malformed_body_is_left_to_the_server(
        self, setup: tuple[AuthMiddleware, str]
    ) -> None:
        """Not JSON, or not a tool call: the MCP server answers it itself."""
        middleware, reader = setup
        _, seen = await self._call(middleware, reader, b"{not json")
        assert seen[0] == b"{not json"
        call = json.dumps({"method": "tools/call", "params": None}).encode()
        sent, _ = await self._call(middleware, reader, call)
        assert "token-scope" in json.loads(sent[1]["body"])["error"]["message"]


async def test_a_disconnect_before_any_body_is_passed_on(activity: ActivityLog) -> None:
    """A client gone before sending a body reaches the server as it would have."""
    seen: list[dict] = []

    async def inner(scope: t.Any, receive: t.Any, send: t.Any) -> None:
        seen.append(await receive())
        seen.append(await receive())

    middleware = AuthMiddleware(inner, WORKSPACE, activity, AuthFailureLimiter())
    messages = [{"type": "http.disconnect"}, {"type": "http.disconnect"}]

    async def receive() -> dict:
        return messages.pop(0)

    async def send(message: dict) -> None:
        raise AssertionError(message)

    scope = {
        "type": "http",
        "path": "/",
        "headers": [(b"authorization", f"Bearer {WORKSPACE}".encode())],
    }
    await middleware(scope, receive, send)
    assert seen == [
        {"type": "http.request", "body": b"", "more_body": False},
        {"type": "http.disconnect"},
    ]


SAFE = "0x" + "22" * 20
POSITIONS = "0x" + "4d" * 20


def _position_out_log() -> dict:
    """Return an ERC-1155 TransferSingle moving one position out of the safe."""
    return {
        "address": POSITIONS,
        "topics": [
            intent_module.TRANSFER_SINGLE,
            "0x" + SAFE[2:].rjust(64, "0"),
            "0x" + SAFE[2:].rjust(64, "0"),
            "0x" + RECIPIENT[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(7)[2:].rjust(64, "0") + hex(3)[2:].rjust(64, "0"),
    }


def _mint_capped(client: TestClient) -> str:
    minted = client.post(
        "/tokens",
        json={"scopes": ["tx"], "max_value_per_tx": {"native": 5}},
        headers=_bearer(WORKSPACE),
    )
    assert minted.status_code == 200
    return minted.json()["token"]


def test_http_capped_token_may_not_move_a_position(
    client: TestClient, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """No cap bounds a position, so a capped token moves none out; others may."""
    fake_w3.provider.logs = [_position_out_log()]
    body = {
        "chain": "testchain",
        "target": POSITIONS,
        "intent": {"recipients": [RECIPIENT]},
    }
    capped = _mint_capped(client)
    refused = client.post("/safe-transaction", json=body, headers=_bearer(capped))
    assert refused.status_code == 400
    assert "token-cap-positions" in refused.json()["detail"]
    assert not fake_w3.eth.sent
    allowed = client.post("/safe-transaction", json=body, headers=_bearer(WORKSPACE))
    assert allowed.status_code == 200
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["token-cap-positions"]


def test_mcp_capped_token_may_not_move_a_position(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """Through the real MCP mount: the tool sees which token called it."""
    fake_w3.provider.logs = [_position_out_log()]
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "safe_transaction",
            "arguments": {
                "chain": "testchain",
                "target": POSITIONS,
                "intent": {"recipients": [RECIPIENT]},
            },
        },
    }
    headers = {"Accept": "application/json, text/event-stream"}
    capped = _mint_capped(client)
    refused = client.post("/mcp/", json=call, headers={**headers, **_bearer(capped)})
    assert "token-cap-positions" in refused.text
    assert not fake_w3.eth.sent
    allowed = client.post("/mcp/", json=call, headers={**headers, **_bearer(WORKSPACE)})
    assert "token-cap-positions" not in allowed.text
    assert len(fake_w3.eth.sent) == 1


def test_http_mint_refuses_an_unknown_field_by_name(
    client: TestClient, store_path: t.Any
) -> None:
    """POST /tokens is strict like every body: the error names what it takes."""
    refused = client.post(
        "/tokens",
        json={"scopes": ["read"], "max_value": {"native": 1}},
        headers=_bearer(WORKSPACE),
    )
    assert refused.status_code == 422
    assert "max_value_per_tx" in json.dumps(refused.json())
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["unknown-parameter"]
