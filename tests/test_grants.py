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
    store.authorize(capped, "sign_message", {})  # digests carry no value


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
