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

import asyncio
import json
import threading
import time
import typing as t

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from connect import intent as intent_module
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.server import auth as auth_module
from connect.server import mcp_tools as mcp_tools_module
from connect.server import signer_routes as signer_routes_module
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

from tests.conftest import (
    FakeW3,
    TOKEN_EXPIRES_AT,
    advance_token_clock,
    audit_entries,
    grant_store,
    pay,
)

WORKSPACE = "workspace-token"  # nosec B105
RECIPIENT = "0x" + "aa" * 20
USDC = "0x" + "c0" * 20
ROBINHOOD_ROUTER = "0x8876789976decbfcbbbe364623c63652db8c0904"


LIVE = {"expires_at": TOKEN_EXPIRES_AT}  # what every minted body needs


def grant(**kwargs: t.Any) -> TokenGrant:
    """Return a mintable grant with every scope unless told otherwise."""
    return TokenGrant(
        **{
            "scopes": ["read", "mech", "tx"],
            "max_mech_payment_per_session": 10**30,
            **LIVE,
            **kwargs,
        }
    )


def test_the_workspace_token_can_do_what_a_session_always_could() -> None:
    """Check read + mech + tx with no caps: the workspace token loses nothing."""
    store = grant_store(WORKSPACE)
    assert store.lookup(f"Bearer {WORKSPACE}") == WORKSPACE
    assert store.grant(WORKSPACE) == WORKSPACE_GRANT
    for action in ("wallet_info", "mech_request", "safe_transaction"):
        store.authorize(WORKSPACE, action, {"value": 10**30})


def test_unknown_or_malformed_tokens_are_not_found() -> None:
    """Only a Bearer header carrying a token we issued resolves."""
    store = grant_store(WORKSPACE)
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
    # each limit on its own: a child without it would outlive or outspend
    for field in ("expires_at", "max_mech_payment"):
        unlimited = {**_capped(10, 50, 5, 1000), field: None}
        assert not narrower(grant(scopes=["read"], **unlimited), parent)
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


def test_a_live_grant_cannot_be_widened_in_place() -> None:
    """Neither the minting caller's object nor a handed-out grant is the stored one."""
    store = grant_store(WORKSPACE)
    asked = grant(max_value_per_tx={"native": 1})
    capped = store.mint(WORKSPACE, asked)
    with pytest.raises(ValidationError):
        store.grant(capped).max_value_per_tx = None  # type: ignore[misc]
    t.cast(dict, asked.max_value_per_tx)["native"] = 10**30
    t.cast(dict, store.grant(capped).max_value_per_tx)["native"] = 10**30
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", {"value": 2})
    assert refused.value.rule == "token-cap-per-tx"


def test_mint_only_narrows() -> None:
    """A minted token works; a wider grant is refused as token-scope."""
    store = grant_store(WORKSPACE)
    child = store.mint(WORKSPACE, grant(scopes=["read"]))
    assert store.lookup(f"Bearer {child}") == child
    with pytest.raises(GrantRefused, match="narrower") as refused:
        store.mint(child, grant(scopes=["read", "tx"]))
    assert refused.value.rule == "token-scope"


def test_a_read_token_reads_and_does_nothing_else() -> None:
    """wallet_info, mech_tools and the status calls; no mech, no tx."""
    store = grant_store(WORKSPACE)
    reader = store.mint(WORKSPACE, grant(scopes=["read"]))
    for action in ("wallet_info", "mech_tools", "mech_result", "transaction_status"):
        store.authorize(reader, action, {})
    for action in ("mech_request", "safe_transaction", "sign_message", "nope"):
        with pytest.raises(GrantRefused) as refused:
            store.authorize(reader, action, {})
        assert refused.value.rule == "token-scope"


def test_an_expired_token_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Past expires_at the token answers nothing, and mints nothing."""
    store = grant_store(WORKSPACE)
    old = store.mint(WORKSPACE, grant(expires_at=int(time.time()) + 60))
    advance_token_clock(monkeypatch, 120)
    for call in (
        lambda: store.authorize(old, "wallet_info", {}),
        lambda: store.mint(old, grant(scopes=["read"])),
    ):
        with pytest.raises(GrantRefused) as refused:
            call()
        assert (refused.value.rule, refused.value.status) == ("token-expired", 401)


def test_mech_payment_cap() -> None:
    """A capped token must name a max_payment within its cap."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_mech_payment=100))
    store.authorize(capped, "mech_request", {"max_payment": 100})
    for asked in (None, 101, True):
        with pytest.raises(GrantRefused) as refused:
            store.authorize(capped, "mech_request", {"max_payment": asked})
        assert refused.value.rule == "token-mech-payment-cap"


def test_value_caps_per_tx_and_per_session() -> None:
    """Caps hold the declared spend (and the native value) per call and in all."""
    store = grant_store(WORKSPACE)
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
    store.authorize(WORKSPACE, "sign_message", {})  # an uncapped token still may


@pytest.mark.parametrize("cap", ["max_value_per_tx", "max_value_per_session"])
def test_a_token_with_either_value_cap_may_not_sign_a_digest(cap: str) -> None:
    """A digest can authorize any safe transaction, which no cap would see."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(**{cap: {"native": 10}}))
    with pytest.raises(GrantRefused, match="may not sign raw digests") as digest:
        store.authorize(capped, "sign_message", {})
    assert digest.value.rule == "token-cap-sign"  # neither cap: the power itself


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
    store = grant_store(WORKSPACE)
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
    with pytest.raises(GrantRefused, match="may approve at most") as by_session:
        store.authorize(session_only, "safe_transaction", arguments)
    assert by_session.value.rule == "token-cap-per-session"  # the cap it has
    store.authorize(WORKSPACE, "safe_transaction", arguments)  # uncapped


def test_approvals_draw_on_the_session_budget() -> None:
    """Two approvals each under the cap may not add up past it."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    other = "0x" + "5f" * 20
    store.authorize(
        capped,
        "safe_transaction",
        {
            "intent": {
                "approvals": [{"token": USDC, "spender": RECIPIENT, "amount": 60}]
            }
        },
    )
    with pytest.raises(GrantRefused) as refused:
        store.authorize(
            capped,
            "safe_transaction",
            {
                "intent": {
                    "approvals": [{"token": USDC, "spender": other, "amount": 60}]
                }
            },
        )
    assert refused.value.rule == "token-cap-per-session"


def test_a_uniswap_swap_draws_its_amount_twice_not_three_times() -> None:
    """The router pulls only from its caller, so Permit2's grant to it is free.

    The skill lib's separate-approvals path: approve Permit2, Permit2 grants
    the router, then the swap spends. Only the approval of Permit2 and the
    spend draw on the session, so a swap of X fits a session cap of 2X.
    """
    import router  # pylint: disable=import-outside-toplevel,import-error

    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 80}))
    intents = [call["intent"] for call in router.approval_calls(4663, USDC, 40, 99)]
    assert intents[0]["approvals"][0]["spender"] == intent_module.PERMIT2
    intents.append({"spend": {USDC: 40}})  # the swap itself
    for intent in intents:
        store.authorize(
            capped, "safe_transaction", {"chain": "robinhood", "intent": intent}
        )
    with pytest.raises(GrantRefused) as refused:  # and the budget is all used
        store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 1}}})
    assert refused.value.rule == "token-cap-per-session"


def test_re_approving_permit2_draws_on_the_session_each_time() -> None:
    """Permit2 also honours grants made before this token, so each approval draws."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    approval = {"token": USDC, "spender": intent_module.PERMIT2, "amount": 100}
    arguments = {"chain": "robinhood", "intent": {"approvals": [approval]}}
    store.authorize(capped, "safe_transaction", arguments)
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == "token-cap-per-session"


def test_a_universal_router_approval_on_its_chain_draws_nothing() -> None:
    """The router pulls only from its caller: its grant funds only the safe's swaps."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    approval = {"token": USDC, "spender": ROBINHOOD_ROUTER, "amount": 100}
    arguments = {"chain": "robinhood", "intent": {"approvals": [approval]}}
    store.authorize(capped, "safe_transaction", arguments)
    store.authorize(capped, "safe_transaction", arguments)
    store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 100}}})


def test_an_unknown_spender_on_a_listed_chain_draws_on_the_session() -> None:
    """Only a router Connect ships is exempt; any other spender draws."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    approval = {"token": USDC, "spender": RECIPIENT, "amount": 100}
    arguments = {"chain": "robinhood", "intent": {"approvals": [approval]}}
    store.authorize(capped, "safe_transaction", arguments)
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == "token-cap-per-session"


@pytest.mark.parametrize("chain", ["gnosis", "not-a-chain", None])
def test_a_universal_router_draws_off_the_chain_it_is_deployed_on(
    chain: str | None,
) -> None:
    """The Robinhood Chain router's address is not a known router elsewhere."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    approval = {"token": USDC, "spender": ROBINHOOD_ROUTER, "amount": 100}
    arguments = {"chain": chain, "intent": {"approvals": [approval]}}
    store.authorize(capped, "safe_transaction", arguments)
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == "token-cap-per-session"


def test_an_approval_of_permit2_is_still_held_to_the_caps() -> None:
    """An approval of Permit2 may not exceed a cap."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 80}))
    approval = {"token": USDC, "spender": intent_module.PERMIT2, "amount": 81}
    with pytest.raises(GrantRefused, match="may approve at most"):
        store.authorize(
            capped, "safe_transaction", {"intent": {"approvals": [approval]}}
        )


@pytest.mark.parametrize("cap", ["max_value_per_tx", "max_value_per_session"])
def test_an_asset_a_cap_does_not_name_may_not_be_spent(cap: str) -> None:
    """A token capped on native only spends no USDC at all."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(**{cap: {"native": 10}}))
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 1}}})
    assert refused.value.rule == cap.replace("max_value_", "token-cap-").replace(
        "_", "-"
    )


def test_an_integral_float_value_is_taken_and_a_fraction_refused() -> None:
    """5.0 is what the tool's int field takes too; 0.5 and inf are not amounts."""
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_tx={"native": 5}))
    store.authorize(capped, "safe_transaction", {"value": 5.0})
    for value in (0.5, float("inf")):
        with pytest.raises(GrantRefused) as refused:
            store.authorize(capped, "safe_transaction", {"value": value})
        assert refused.value.rule == "bad-value"


def test_a_call_with_no_known_token_is_held_as_capped() -> None:
    """The one capped rule fails closed: no token, or an unknown one, is capped."""
    store = grant_store(WORKSPACE)
    raw = {"spend": {"native": 1}}
    for token in (None, "not-a-token"):
        assert store.intent_for(token, raw) == intent_module.Capped(raw)
    assert store.intent_for(WORKSPACE, raw) is raw
    capped = store.mint(WORKSPACE, grant(max_value_per_tx={"native": 5}))
    assert store.intent_for(capped, raw) == intent_module.Capped(raw)


def test_cap_keys_are_normalised_when_minted() -> None:
    """A checksummed address, NATIVE or the CELO face caps what the gate books."""
    store = grant_store(WORKSPACE)
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
    store = grant_store(WORKSPACE)
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
    store = grant_store(WORKSPACE)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={USDC: 100}))
    with pytest.raises(GrantRefused) as refused:
        store.authorize(capped, "safe_transaction", arguments)
    assert refused.value.rule == rule
    store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 100}}})
    with pytest.raises(GrantRefused):
        store.authorize(capped, "safe_transaction", {"intent": {"spend": {USDC: 1}}})


def test_children_draw_on_their_parents_session_budget() -> None:
    """Minting more children does not multiply a parent's session cap."""
    store = grant_store(WORKSPACE)
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
    store = grant_store(WORKSPACE)
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
        "/tokens", json={"scopes": ["read"], **LIVE}, headers=_bearer(WORKSPACE)
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
        "/tokens", json={"scopes": ["read", "tx"], **LIVE}, headers=_bearer(reader)
    )
    assert wider.status_code == 403
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["token-scope"] * 4


@pytest.mark.parametrize(
    ("grant_body", "status", "rule"),
    [
        ({"scopes": ["tx"]}, 403, "token-scope"),
        (
            {"scopes": ["read"], "expires_at": int(time.time()) + 60},
            401,
            "token-expired",
        ),
    ],
)
def test_http_wallet_needs_a_live_read_token(  # pylint: disable=too-many-arguments
    client: TestClient,
    store_path: t.Any,
    monkeypatch: pytest.MonkeyPatch,
    grant_body: dict,
    status: int,
    rule: str,
) -> None:
    """GET /wallet is held to the token's grant, and its refusal audited."""
    token = client.post(
        "/tokens", json={**LIVE, **grant_body}, headers=_bearer(WORKSPACE)
    )
    assert token.status_code == 200
    advance_token_clock(monkeypatch, 120)
    refused = client.get("/wallet", headers=_bearer(token.json()["token"]))
    assert refused.status_code == status
    assert rule in refused.json()["detail"]
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert (entry["rule"], entry["path"]) == (rule, "/wallet")


def test_http_capped_token_is_refused_above_its_cap(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """A capped tx token sends within its cap and is refused, by rule, above it."""
    capped = client.post(
        "/tokens",
        json={"scopes": ["tx"], "max_value_per_tx": {"native": 5}, **LIVE},
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
        store = grant_store(WORKSPACE)
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

    middleware = AuthMiddleware(
        inner, grant_store(WORKSPACE), activity, AuthFailureLimiter()
    )
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


def _position_out_log(holder: str = SAFE) -> dict:
    """Return an ERC-1155 TransferSingle moving one position out of `holder`."""
    return {
        "address": POSITIONS,
        "topics": [
            intent_module.TRANSFER_SINGLE,
            "0x" + holder[2:].lower().rjust(64, "0"),
            "0x" + holder[2:].lower().rjust(64, "0"),
            "0x" + RECIPIENT[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(7)[2:].rjust(64, "0") + hex(3)[2:].rjust(64, "0"),
    }


def _mint_capped(client: TestClient) -> str:
    minted = client.post(
        "/tokens",
        json={"scopes": ["tx"], "max_value_per_tx": {"native": 5}, **LIVE},
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


@pytest.mark.parametrize(
    ("tool", "to_key"), [("safe_transaction", "target"), ("send_transaction", "to")]
)
def test_mcp_capped_token_may_not_move_a_position(
    client: TestClient, fake_w3: FakeW3, test_signer: Signer, tool: str, to_key: str
) -> None:
    """Through the real MCP mount, on both send tools: the tool sees the token."""
    holder = SAFE if tool == "safe_transaction" else test_signer.address
    fake_w3.provider.logs = [_position_out_log(holder)]
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {
                "chain": "testchain",
                to_key: POSITIONS,
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


@pytest.mark.parametrize("tool", ["preflight_transaction", "simulate_transaction"])
def test_mcp_dry_runs_hold_a_capped_token_as_the_send_would(
    client: TestClient, fake_w3: FakeW3, tool: str
) -> None:
    """A capped token's preflight and simulation answer as its real call would."""
    fake_w3.provider.logs = [_position_out_log()]
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": {
                "chain": "testchain",
                "target": POSITIONS,
                "intent": {"recipients": [RECIPIENT]},
            },
        },
    }
    headers = {"Accept": "application/json, text/event-stream"}
    capped = client.post(
        "/tokens",
        json={"scopes": ["read", "tx"], "max_value_per_tx": {"native": 5}, **LIVE},
        headers=_bearer(WORKSPACE),
    ).json()["token"]
    refused = client.post("/mcp/", json=call, headers={**headers, **_bearer(capped)})
    assert "token-cap-positions" in refused.text
    allowed = client.post("/mcp/", json=call, headers={**headers, **_bearer(WORKSPACE)})
    assert "token-cap-positions" not in allowed.text
    assert not fake_w3.eth.sent


def test_http_sign_and_send_holds_a_capped_token_to_its_positions(
    client: TestClient, fake_w3: FakeW3, test_signer: Signer
) -> None:
    """The EOA route wraps a capped token's intent as the safe route does."""
    fake_w3.provider.logs = [_position_out_log(test_signer.address)]
    body = {
        "chain": "testchain",
        "to": POSITIONS,
        "intent": {"recipients": [RECIPIENT]},
    }
    refused = client.post(
        "/sign-and-send", json=body, headers=_bearer(_mint_capped(client))
    )
    assert refused.status_code == 400
    assert "token-cap-positions" in refused.json()["detail"]
    assert not fake_w3.eth.sent


def test_mcp_value_that_is_not_finite_is_a_bad_value_refusal(
    client: TestClient, store_path: t.Any
) -> None:
    """JSON 1e999 decodes to inf: a named refusal, audited, never an HTTP 500."""
    body = (
        '{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": '
        '{"name": "safe_transaction", "arguments": {"chain": "testchain", '
        '"target": "0x' + "aa" * 20 + '", "value": 1e999}}}'
    )
    capped = _mint_capped(client)
    answer = client.post(
        "/mcp/",
        content=body,
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **_bearer(capped),
        },
    )
    assert answer.status_code == 200
    assert "rule 'bad-value'" in answer.text
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["bad-value"]


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


def _session_capped(client: TestClient) -> str:
    minted = client.post(
        "/tokens",
        json={
            "scopes": ["read", "tx"],
            "max_value_per_session": {"native": 10},
            **LIVE,
        },
        headers=_bearer(WORKSPACE),
    )
    assert minted.status_code == 200
    return minted.json()["token"]


def test_http_a_replayed_request_id_draws_the_session_once(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """A retry of a send that went out answers its hash; it is not charged again.

    signer_client retries on a timeout: charging the retry would refuse it
    while its transaction is on-chain, and the script would never learn so.
    """
    capped = _session_capped(client)
    body = {
        "chain": "testchain",
        "target": RECIPIENT,
        "value": 10,
        "intent": pay(RECIPIENT, 10),
        "request_id": "r1",
    }
    first = client.post("/safe-transaction", json=body, headers=_bearer(capped))
    assert first.status_code == 200
    again = client.post("/safe-transaction", json=body, headers=_bearer(capped))
    assert again.json() == first.json()
    assert len(fake_w3.eth.sent) == 1
    # the id is the safe path's: on the EOA path it is a new send, and drawn
    eoa = client.post(
        "/sign-and-send",
        json={**{k: v for k, v in body.items() if k != "target"}, "to": RECIPIENT},
        headers=_bearer(capped),
    )
    assert eoa.status_code == 403
    assert "token-cap-per-session" in eoa.json()["detail"]
    fresh = client.post(
        "/safe-transaction", json={**body, "request_id": "r2"}, headers=_bearer(capped)
    )
    assert fresh.status_code == 403


def test_http_a_retry_while_the_send_is_in_flight_is_not_drawn_again(
    client: TestClient, fake_w3: FakeW3, monkeypatch: pytest.MonkeyPatch
) -> None:
    """signer_client retries the moment its timeout fires, often mid-broadcast.

    That retry is refused by the signer as in flight, and sends nothing: it
    must get that answer, not a cap refusal for a draw it already made.
    """
    capped = _session_capped(client)
    body = {
        "chain": "testchain",
        "target": RECIPIENT,
        "value": 10,
        "intent": pay(RECIPIENT, 10),
        "request_id": "r1",
    }
    broadcasting, release = threading.Event(), threading.Event()
    send_raw = fake_w3.eth.send_raw_transaction

    def slow_broadcast(raw: bytes) -> t.Any:
        broadcasting.set()
        assert release.wait(10)
        return send_raw(raw)

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", slow_broadcast)
    answers: list = []
    first = threading.Thread(
        target=lambda: answers.append(
            client.post("/safe-transaction", json=body, headers=_bearer(capped))
        )
    )
    first.start()
    try:
        assert broadcasting.wait(10)
        retry = client.post("/safe-transaction", json=body, headers=_bearer(capped))
    finally:
        release.set()
        first.join(10)
    assert retry.status_code == 400
    assert "in flight" in retry.json()["detail"]
    assert answers[0].status_code == 200
    assert len(fake_w3.eth.sent) == 1


@pytest.mark.parametrize("surface", ["http", "mcp"])
@pytest.mark.parametrize(
    ("tool", "path", "to_key"),
    [
        ("safe_transaction", "/safe-transaction", "target"),
        ("send_transaction", "/sign-and-send", "to"),
    ],
)
def test_a_spared_retry_never_sends_fresh_after_the_first_send_fails(  # pylint: disable=too-many-arguments,too-many-locals
    client: TestClient,
    fake_w3: FakeW3,
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
    tool: str,
    path: str,
    to_key: str,
) -> None:
    """The draw was spared because the id was in flight; then the first send failed.

    The retry must not broadcast on a draw it never paid: it is answered from
    the id's result or refused, and a later retry is charged in full.
    """
    capped = _session_capped(client)
    arguments = {
        "chain": "testchain",
        to_key: RECIPIENT,
        "value": 10,
        "intent": pay(RECIPIENT, 10),
        "request_id": "r1",
    }
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    headers = {"Accept": "application/json, text/event-stream", **_bearer(capped)}

    def post() -> t.Any:
        if surface == "http":
            return client.post(path, json=arguments, headers=headers)
        return client.post("/mcp/", json=call, headers=headers)

    broadcasting, release = threading.Event(), threading.Event()
    retry_authorized, first_done = threading.Event(), threading.Event()
    broadcasts: list = []
    send_raw = fake_w3.eth.send_raw_transaction

    def slow_broadcast(raw: bytes) -> t.Any:
        broadcasts.append(raw)
        broadcasting.set()
        assert release.wait(10)
        return send_raw(raw)  # fails: fail_broadcast is set by then

    module = signer_routes_module if surface == "http" else mcp_tools_module
    dispatch = module._dispatch  # pylint: disable=protected-access

    def hold_retry(replay_only: bool) -> None:
        if replay_only:  # the retry, authorized as a replay of the held id
            retry_authorized.set()
            assert first_done.wait(10)

    def held_back(*args: t.Any, **kwargs: t.Any) -> t.Any:
        hold_retry(kwargs["replay_only"])
        return dispatch(*args, **kwargs)

    async def held_back_async(*args: t.Any, **kwargs: t.Any) -> t.Any:
        # the MCP tool runs on the event loop: wait off it, or the first stalls
        await asyncio.to_thread(hold_retry, kwargs["replay_only"])
        return await dispatch(*args, **kwargs)

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", slow_broadcast)
    monkeypatch.setattr(
        module, "_dispatch", held_back if surface == "http" else held_back_async
    )
    answers: dict = {}
    first = threading.Thread(target=lambda: answers.update(first=post()))
    retry = threading.Thread(target=lambda: answers.update(retry=post()))
    first.start()
    try:
        assert broadcasting.wait(10)
        retry.start()
        assert retry_authorized.wait(10)
        fake_w3.eth.fail_broadcast = True
    finally:
        release.set()
        first.join(10)
        first_done.set()
        retry.join(10)
    assert "the RPC could not take the transaction" in answers["first"].text
    assert "nothing was sent for this retry" in answers["retry"].text
    assert len(broadcasts) == 1  # the retry broadcast nothing
    assert "token-cap-per-session" in post().text  # not held now: drawn in full


def test_a_held_request_id_is_drawn_only_past_this_token_s_own_draw() -> None:
    """The exemption covers what this token drew for the id, and nothing more."""
    held: set = set()
    store = GrantStore(WORKSPACE, held=lambda rid, via_safe: (rid, via_safe) in held)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={"native": 10}))
    other = store.mint(WORKSPACE, grant(max_value_per_session={"native": 10}))
    store.authorize(capped, "safe_transaction", {"value": 6, "request_id": "r1"})
    held.add(("r1", True))  # the signer is sending it
    store.authorize(capped, "safe_transaction", {"value": 6, "request_id": "r1"})
    store.authorize(capped, "safe_transaction", {"value": 9, "request_id": "r1"})
    with pytest.raises(GrantRefused) as past:  # 9 drawn; 11 is 2 more of 1 left
        store.authorize(capped, "safe_transaction", {"value": 11, "request_id": "r1"})
    assert past.value.rule == "token-cap-per-session"
    # another token never drew for r1: it is drawn in full
    store.authorize(other, "safe_transaction", {"value": 10, "request_id": "r1"})
    with pytest.raises(GrantRefused):  # all 10 of its budget went to r1
        store.authorize(other, "safe_transaction", {"value": 1, "request_id": "r2"})
    # the EOA namespace is another id; and one the signer no longer holds
    # (the first attempt failed, so a retry really sends) is drawn in full
    with pytest.raises(GrantRefused):
        store.authorize(capped, "send_transaction", {"value": 6, "request_id": "r1"})
    held.clear()
    with pytest.raises(GrantRefused):
        store.authorize(capped, "safe_transaction", {"value": 6, "request_id": "r1"})


def test_a_retry_s_record_keeps_the_most_drawn_per_asset() -> None:
    """A retry declaring less, or leaving an asset out, lowers nothing on record."""
    store = GrantStore(WORKSPACE, held=lambda rid, via_safe: True)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={"native": 20, USDC: 5}))

    def send(request_id: str, value: int, usdc: int = 0) -> None:
        spend = {USDC: usdc} if usdc else {}
        arguments = {"value": value, "intent": {"spend": spend}}
        store.authorize(
            capped, "safe_transaction", {**arguments, "request_id": request_id}
        )

    for value in (9, 6, 9):  # decreasing, then back: 9 is drawn once
        send("r1", value)
    send("r2", 1, usdc=5)
    send("r2", 1)  # USDC left out of this retry
    send("r2", 1, usdc=5)  # and declared again: still drawn once
    send("r3", 10)  # 9 + 1 + 10 is all 20 of native
    with pytest.raises(GrantRefused):
        send("r4", 1)
    with pytest.raises(GrantRefused):
        send("r4", 0, usdc=1)


def test_a_forgotten_request_id_is_drawn_in_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the bound a draw is forgotten, which only ever draws again."""
    monkeypatch.setattr(auth_module, "MAX_DRAWN_REQUEST_IDS", 1)
    store = GrantStore(WORKSPACE, held=lambda rid, via_safe: True)
    capped = store.mint(WORKSPACE, grant(max_value_per_session={"native": 10}))
    store.authorize(capped, "safe_transaction", {"value": 4, "request_id": "r1"})
    store.authorize(capped, "safe_transaction", {"value": 4, "request_id": "r2"})
    store.authorize(capped, "safe_transaction", {"value": 4, "request_id": "r2"})
    with pytest.raises(GrantRefused):  # r1 forgotten: 4 more of the 2 left
        store.authorize(capped, "safe_transaction", {"value": 4, "request_id": "r1"})


def test_mcp_a_replayed_request_id_draws_the_session_once(
    client: TestClient, fake_w3: FakeW3
) -> None:
    """The MCP mount authorizes a replay as the HTTP route does."""
    call = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "safe_transaction",
            "arguments": {
                "chain": "testchain",
                "target": RECIPIENT,
                "value": 10,
                "intent": pay(RECIPIENT, 10),
                "request_id": "r1",
            },
        },
    }
    headers = {"Accept": "application/json, text/event-stream"}
    headers.update(_bearer(_session_capped(client)))
    first = client.post("/mcp/", json=call, headers=headers)
    assert "tx_hash" in first.text
    again = client.post("/mcp/", json=call, headers=headers)
    assert "token-cap-per-session" not in again.text
    assert "tx_hash" in again.text
    assert len(fake_w3.eth.sent) == 1


def test_mcp_preflight_answers_with_the_token_s_cap_and_draws_nothing(
    client: TestClient, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """Preflight refuses as the send would, by cap, without spending the budget."""
    capped = client.post(
        "/tokens",
        json={
            "scopes": ["read", "tx"],
            "max_value_per_tx": {"native": 5},
            "max_value_per_session": {"native": 5},
            **LIVE,
        },
        headers=_bearer(WORKSPACE),
    ).json()["token"]
    headers = {"Accept": "application/json, text/event-stream", **_bearer(capped)}

    def call(tool: str, value: int) -> str:
        arguments = {
            "chain": "testchain",
            "target": RECIPIENT,
            "value": value,
            "intent": pay(RECIPIENT, value),
        }
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        return client.post("/mcp/", json=body, headers=headers).text

    over = call("preflight_transaction", 6)
    assert '\\"allowed\\": false' in over
    assert "token-cap-per-tx" in over
    for _ in range(2):  # a dry run draws nothing on the session budget
        assert '\\"allowed\\": true' in call("preflight_transaction", 5)
    assert "tx_hash" in call("safe_transaction", 5)
    spent = call("preflight_transaction", 1)
    assert "token-cap-per-session" in spent
    assert len(fake_w3.eth.sent) == 1
    checked = [e for e in audit_entries(store_path) if e["kind"] == "checked"]
    assert [e["allowed"] for e in checked] == [False, True, True, False]
    assert "token-cap-per-tx" in checked[0]["reason"]
    assert checked[0]["probed_value"] == "6"
    assert not [e for e in audit_entries(store_path) if e["kind"] == "refusal"]


def test_mcp_preflight_answers_a_read_only_token_as_its_send_would(
    client: TestClient, fake_w3: FakeW3, store_path: t.Any
) -> None:
    """A read token may preflight, and is told its send would be refused by scope."""
    reader = client.post(
        "/tokens", json={"scopes": ["read"], **LIVE}, headers=_bearer(WORKSPACE)
    ).json()["token"]
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "preflight_transaction",
            "arguments": {"chain": "testchain", "target": RECIPIENT},
        },
    }
    headers = {"Accept": "application/json, text/event-stream", **_bearer(reader)}
    answer = client.post("/mcp/", json=body, headers=headers).text
    assert '\\"allowed\\": false' in answer
    assert "token-scope" in answer
    (checked,) = [e for e in audit_entries(store_path) if e["kind"] == "checked"]
    assert "token-scope" in checked["reason"]
    assert not [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert fake_w3.provider.simulated == []


def _mcp_call(client: TestClient, token: str, tool: str, arguments: dict) -> t.Any:
    """Call one MCP tool through the real mount; return the raw response."""
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    headers = {"Accept": "application/json, text/event-stream", **_bearer(token)}
    return client.post("/mcp/", json=body, headers=headers)


def _refused_rule(response: t.Any) -> str | None:
    """Return the rule of a JSON-RPC -32001 refusal, or None if not refused."""
    if not response.headers["content-type"].startswith("application/json"):
        return None
    error = response.json().get("error") or {}
    if error.get("code") != -32001:
        return None
    return error["message"].split("'")[1]


def test_mcp_mech_request_is_held_to_the_token_s_mech_caps(
    client: TestClient,
    mech_service: t.Any,
    monkeypatch: pytest.MonkeyPatch,
    store_path: t.Any,
) -> None:
    """Over /mcp: per request and per session, and nothing reaches the mech when refused."""
    asked: list[t.Any] = []

    def request(*_args: t.Any, **kwargs: t.Any) -> dict:
        asked.append(kwargs["max_payment"])
        return {"request_ids": []}

    monkeypatch.setattr(mech_service, "request", request)
    capped = client.post(
        "/tokens",
        json={
            "scopes": ["mech"],
            "max_mech_payment": 100,
            "max_mech_payment_per_session": 150,
            **LIVE,
        },
        headers=_bearer(WORKSPACE),
    ).json()["token"]

    def pay_mech(**max_payment: t.Any) -> str | None:
        return _refused_rule(
            _mcp_call(
                client,
                capped,
                "mech_request",
                {"prompt": "q", "tool": "t", **max_payment},
            )
        )

    assert pay_mech(max_payment=101) == "token-mech-payment-cap"
    assert pay_mech() == "token-mech-payment-cap"  # omitted: the default is no cap
    assert pay_mech(max_payment="100") == "token-mech-payment-cap"
    assert pay_mech(max_payment=100) is None
    assert pay_mech(max_payment=100) == "token-mech-session-cap"  # 200 > 150
    assert pay_mech(max_payment=50) is None
    assert asked == [100, 50]
    rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert rules == ["token-mech-payment-cap"] * 3 + ["token-mech-session-cap"]


def test_mcp_an_expired_token_is_refused_on_a_tool_call(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, store_path: t.Any
) -> None:
    """Expiry holds on the MCP mount as on HTTP: a -32001 naming token-expired."""
    reader = client.post(
        "/tokens",
        json={"scopes": ["read"], "expires_at": int(time.time()) + 60},
        headers=_bearer(WORKSPACE),
    ).json()["token"]
    assert _refused_rule(_mcp_call(client, reader, "wallet_info", {})) is None
    advance_token_clock(monkeypatch, 120)
    assert (
        _refused_rule(_mcp_call(client, reader, "wallet_info", {})) == "token-expired"
    )
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert (entry["rule"], entry["tool"]) == ("token-expired", "wallet_info")


def test_mech_payments_draw_on_every_ancestor_s_session_budget() -> None:
    """Minting more children never multiplies a parent's mech budget."""
    store = grant_store(WORKSPACE)
    parent = store.mint(WORKSPACE, grant(max_mech_payment_per_session=100))
    children = [
        store.mint(parent, grant(max_mech_payment_per_session=100)) for _ in range(2)
    ]
    store.authorize(children[0], "mech_request", {"max_payment": 60})
    with pytest.raises(GrantRefused) as refused:
        store.authorize(children[1], "mech_request", {"max_payment": 60})
    assert refused.value.rule == "token-mech-session-cap"
    store.authorize(children[1], "mech_request", {"max_payment": 40})
    for asked in (None, "1", -1, True):  # a budget is drawn by a whole amount only
        with pytest.raises(GrantRefused) as refused:
            store.authorize(children[1], "mech_request", {"max_payment": asked})
        assert refused.value.rule == "token-mech-session-cap"
    # the workspace token has no mech budget of its own, so it is never drawn
    store.authorize(WORKSPACE, "mech_request", {"max_payment": 10**30})


@pytest.mark.parametrize(
    ("body", "rule"),
    [
        ({"scopes": ["read"]}, "token-expiry-required"),
        ({"scopes": ["read"], "expires_at": 1}, "token-expiry-required"),
        ({"scopes": ["mech"], **LIVE}, "token-mech-cap-required"),
    ],
)
def test_http_mint_needs_a_future_expiry_and_a_mech_session_cap(
    client: TestClient, store_path: t.Any, body: dict, rule: str
) -> None:
    """A minted token is never immortal, nor a mech payer without a session budget."""
    refused = client.post("/tokens", json=body, headers=_bearer(WORKSPACE))
    assert refused.status_code == 400
    assert f"rule '{rule}'" in refused.json()["detail"]
    (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
    assert entry["rule"] == rule


@pytest.mark.parametrize(
    "field",
    [
        {"expires_at": 0},
        {"expires_at": -5},
        {"max_mech_payment": -1},
        {"max_mech_payment_per_session": -1},
    ],
)
def test_a_grant_out_of_range_is_invalid(field: dict) -> None:
    """An expiry before 1970 or a negative mech cap is not a grant at all."""
    with pytest.raises(ValidationError):
        grant(**field)


def test_scopes_are_immutable() -> None:
    """The workspace grant cannot gain a scope in place."""
    assert isinstance(WORKSPACE_GRANT.scopes, tuple)
    assert isinstance(grant(scopes=["read"]).scopes, tuple)


def test_tokens_are_stored_by_hash_and_found_by_one_lookup() -> None:
    """The store keeps no token in the clear, and still finds every one."""
    store = grant_store(WORKSPACE)
    child = store.mint(WORKSPACE, grant(scopes=["read"]))
    keys = set(store._grants)  # pylint: disable=protected-access
    assert WORKSPACE not in keys
    assert child not in keys
    assert store.lookup(f"Bearer {child}") == child
    assert store.lookup(f"Bearer {child}x") is None


def test_one_token_mints_a_bounded_number_of_live_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the cap a mint is refused until some expire; expired ones are dropped."""
    monkeypatch.setattr(auth_module, "MAX_CHILDREN_PER_TOKEN", 2)
    store = grant_store(WORKSPACE)
    soon = int(time.time()) + 60
    short = [
        store.mint(
            WORKSPACE, grant(expires_at=soon, max_value_per_session={"native": 5})
        )
    ]
    store.authorize(short[0], "safe_transaction", {"value": 1, "request_id": "r1"})
    store.mint(WORKSPACE, grant(scopes=["read"]))
    with pytest.raises(GrantRefused) as refused:
        store.mint(WORKSPACE, grant(scopes=["read"]))
    assert refused.value.rule == "token-limit"
    advance_token_clock(monkeypatch, 120)
    store.mint(WORKSPACE, grant(scopes=["read"]))  # the expired one made room
    assert store.lookup(f"Bearer {short[0]}") is None  # and is forgotten


def test_the_store_holds_a_bounded_number_of_live_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Grandchildren count too: a tree of tokens cannot grow without bound."""
    monkeypatch.setattr(auth_module, "MAX_LIVE_TOKENS", 3)  # the root included
    store = grant_store(WORKSPACE)
    child = store.mint(WORKSPACE, grant())
    store.mint(child, grant())
    with pytest.raises(GrantRefused) as refused:
        store.mint(child, grant())
    assert refused.value.rule == "token-limit"
