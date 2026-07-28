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

"""Tests for the skill's SDK-dependent glue (trade.py, remote_signer.py).

These import ``py_clob_client_v2``, which is NOT a repo dependency (the agent
pip-installs it into its own venv). So the whole module SKIPS when the SDK is
absent — e.g. in the repo's CI — and runs where it is installed (the agent
env, or a dev venv with the SDK). It covers the branches the live e2e did
not: the auth-failure creds-refresh retry, the Account-shim routing, and the
ambiguous-submission reconciliation (lost responses, provisional "matched").
"""

# mypy: ignore-errors

import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("py_clob_client_v2")

_SCRIPTS = (
    Path(__file__).resolve().parent.parent
    / "connect"
    / "assets"
    / "skills"
    / "connect-polymarket"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS))

import funds  # noqa: E402
import remote_signer  # noqa: E402
import trade  # noqa: E402
from py_clob_client_v2.exceptions import PolyApiException  # noqa: E402

# --- trade._auth_failed ---------------------------------------------------------


def test_auth_failed_on_401_status() -> None:
    """A 401 status is treated as an auth failure (status-code path)."""
    err = PolyApiException(error_msg="nope")
    err.status_code = 401
    assert trade._auth_failed(err) is True


def test_auth_failed_on_message() -> None:
    """An 'unauthorized' message is treated as an auth failure (message path)."""
    assert trade._auth_failed(PolyApiException(error_msg="unauthorized")) is True


def test_auth_failed_false_on_other() -> None:
    """A non-auth rejection is not treated as an auth failure."""
    assert trade._auth_failed(PolyApiException(error_msg="bad order")) is False


# --- trade._run_client: refresh creds once on auth failure ----------------------


class _FakeClient:
    """A placeholder CLOB client (behaviour supplied by the op closure)."""


def test_run_client_refreshes_creds_then_succeeds(monkeypatch, capsys) -> None:
    """An auth failure clears cached creds, rebuilds the client, and retries."""
    built = []
    cleared = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(
        trade, "make_clob_client", lambda cs, dw: built.append(1) or _FakeClient()
    )
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: cleared.append(1))

    state = {"attempt": 0}

    def op(client, dw):
        state["attempt"] += 1
        if state["attempt"] == 1:
            raise PolyApiException(error_msg="unauthorized")
        return {"ok": True}

    trade._run_client(object(), op)
    assert json.loads(capsys.readouterr().out) == {"ok": True}
    assert cleared == [1]  # creds cleared once
    assert len(built) == 2  # client built twice (initial + rebuild)


def test_run_client_non_auth_error_exits(monkeypatch) -> None:
    """A non-auth rejection is not retried; it prints and exits 1."""
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _FakeClient())
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)

    def op(client, dw):
        raise PolyApiException(error_msg="bad order")

    with pytest.raises(SystemExit):
        trade._run_client(object(), op)


def test_disabled_auth_retry_does_not_resubmit_operation(monkeypatch, capsys) -> None:
    """Order placement surfaces an auth-looking error after one submission."""
    attempts = []
    built = []
    cleared = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(
        trade, "make_clob_client", lambda cs, dw: built.append(1) or _FakeClient()
    )
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: cleared.append(1))

    def op(client, dw):
        attempts.append(client)
        raise PolyApiException(error_msg="unauthorized")

    with pytest.raises(SystemExit):
        trade._run_client(object(), op, retry_auth=False)

    assert len(attempts) == 1
    assert len(built) == 1
    assert cleared == [1]
    output = json.loads(capsys.readouterr().out)
    assert output["error"] == "unauthorized"
    assert "reconcile before retrying" in output["warning"]


# --- remote_signer._AccountShim: sentinel routes to connect, real key delegates --


def test_account_shim_routes_sentinel_to_connect_signer() -> None:
    """A RemoteSigner sentinel signs via connect, not eth_account."""

    class _CS:
        agent_eoa = "0x" + "9e" * 20

        def sign_digest(self, digest):
            return "0x" + "ab" * 65

    signer = remote_signer.RemoteSigner(_CS())
    signed = remote_signer._AccountShim._sign_hash(b"\x11" * 32, private_key=signer)
    assert signed.signature.hex().endswith("ab" * 65)


def test_account_shim_delegates_real_key(monkeypatch) -> None:
    """A real (non-sentinel) key falls through to eth_account unchanged."""
    called = {}
    monkeypatch.setattr(
        remote_signer._RealAccount,
        "_sign_hash",
        staticmethod(
            lambda digest, private_key=None: called.setdefault("k", private_key)
        ),
    )
    remote_signer._AccountShim._sign_hash(b"\x11" * 32, private_key=b"\x02" * 32)
    assert called["k"] == b"\x02" * 32


# --- remote_signer.clear_cached_creds -------------------------------------------


def test_clear_cached_creds_removes_and_persists(monkeypatch) -> None:
    """Cached creds are dropped and the trimmed state is written back."""
    saved = {}
    monkeypatch.setattr(
        remote_signer, "load_state", lambda cs: {"clob_creds": {"api_key": "x"}, "k": 1}
    )
    monkeypatch.setattr(
        remote_signer, "save_state", lambda cs, state: saved.update(state)
    )
    remote_signer.clear_cached_creds(object())
    assert "clob_creds" not in saved
    assert saved.get("k") == 1


# --- trade.cmd_limit: BUY records the token, SELL does not ----------------------


class _OrderClient:
    """A CLOB client whose order calls succeed with a dummy response."""

    def create_order(self, args):
        """Return an opaque order object."""
        return "order"

    def post_order(self, order, order_type):
        """Return a dummy live-order response."""
        return {"success": True, "status": "live"}


class _AmbiguousOrderClient:
    """A CLOB client that loses the response after a possible acceptance.

    It has no read methods at all, so the pre-submission snapshot fails and
    reconciliation cannot attribute anything — the worst case.
    """

    def post_order(self, order, order_type):
        """Raise without an HTTP status, leaving submission outcome unknown."""
        raise PolyApiException(error_msg="Request exception!")


class _LostResponseClient:
    """Submission raises a transport error; reads replay configured pages.

    The first page of each series is what the pre-submission snapshot sees;
    later polls pop the next page and then repeat the last one.
    """

    def __init__(self, trades_pages=None, orders_pages=None):
        """Store the page series for get_trades and get_open_orders."""
        self._trades = [list(p) for p in (trades_pages or [[]])]
        self._orders = [list(p) for p in (orders_pages or [[]])]

    @staticmethod
    def _page(pages):
        """Pop pages until one remains, then keep returning it."""
        return pages.pop(0) if len(pages) > 1 else pages[0]

    def get_trades(self, params=None, **kwargs):
        """Return the next configured trades page."""
        return self._page(self._trades)

    def get_open_orders(self, params=None, **kwargs):
        """Return the next configured open-orders page."""
        return self._page(self._orders)

    def post_order(self, order, order_type):
        """Raise the transport failure that loses the CLOB's response."""
        raise PolyApiException(error_msg="The read operation timed out")


class _MatchedResponseClient(_LostResponseClient):
    """A CLOB client whose submission succeeds with a "matched" payload."""

    def post_order(self, order, order_type):
        """Return the success/matched response under settlement test."""
        return {
            "success": True,
            "status": "matched",
            "orderID": "0xAB",
            "tradeIDs": ["0bfda62e"],
        }


class _HttpErrorOrderClient:
    """A CLOB client that returns an HTTP error with an ambiguous outcome."""

    def __init__(self, status_code):
        """Store the HTTP status to raise from post_order."""
        self.status_code = status_code

    def post_order(self, order, order_type):
        """Raise a CLOB API exception carrying the configured status."""
        err = PolyApiException(error_msg="response lost")
        err.status_code = self.status_code
        raise err


class _AuthMessageOrderClient:
    """A CLOB client raising an auth-looking error without an HTTP status."""

    def post_order(self, order, order_type):
        """Raise a message-only error whose submission outcome is ambiguous."""
        raise PolyApiException(error_msg="unauthorized")


def _track_intents(monkeypatch):
    """Stub the intent bookkeeping; return (recorded, confirmed, rejected)."""
    recorded = []
    confirmed = []
    rejected = []
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    monkeypatch.setattr(
        trade.pm, "confirm_dw_buy_intent", lambda cs, tid: confirmed.append(tid)
    )
    monkeypatch.setattr(
        trade.pm, "reject_dw_buy_intent", lambda cs, tid: rejected.append(tid)
    )
    return recorded, confirmed, rejected


def _no_network_no_sleep(monkeypatch, book_ok=True):
    """Keep reconciliation off the wire and off the clock."""
    monkeypatch.setattr(trade, "RECONCILE_DELAYS", ())
    if book_ok:
        monkeypatch.setattr(trade.pm, "http_get_json", lambda url, params=None: {})
    else:
        monkeypatch.setattr(
            trade.pm,
            "http_get_json",
            lambda url, params=None: (_ for _ in ()).throw(OSError("down")),
        )


def test_buy_hint_survives_ambiguous_submission(monkeypatch, capsys) -> None:
    """A lost response with no read access reports unknown, keeping its hint."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)

    with pytest.raises(SystemExit):
        trade._post_buy_with_recovery_hint(
            _AmbiguousOrderClient(), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
    assert confirmed == []
    assert rejected == []
    output = json.loads(capsys.readouterr().out)
    assert output["submission"] == "unknown"
    assert "double fill" in output["recovery"]
    assert "order endpoint" in output["venue_health"]


def test_buy_hint_survives_http_408(monkeypatch, capsys) -> None:
    """A timeout response is ambiguous and must retain its recovery marker."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)

    with pytest.raises(SystemExit):
        trade._post_buy_with_recovery_hint(
            _HttpErrorOrderClient(408), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
    assert confirmed == []
    assert rejected == []
    assert json.loads(capsys.readouterr().out)["submission"] == "unknown"


def test_http_400_rejection_still_propagates(monkeypatch) -> None:
    """A CLOB application 4xx is an answer, not ambiguity — it raises as-is."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)

    with pytest.raises(PolyApiException):
        trade._post_buy_with_recovery_hint(
            _HttpErrorOrderClient(400), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
    assert confirmed == []
    assert rejected == []


def test_lost_submission_reports_fill(monkeypatch) -> None:
    """A timed-out submission that actually filled is reported as filled."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _LostResponseClient(trades_pages=[[], [{"id": "t1", "size": "1.38"}]])

    result = trade._post_buy_with_recovery_hint(
        client, object(), "12345", "order", "FOK"
    )

    assert result["submission"] == "filled"
    assert result["trades"] == [{"id": "t1", "size": "1.38"}]
    assert "do NOT resubmit" in result["warning"]
    assert confirmed == [12345]
    assert rejected == []


def test_lost_submission_reports_resting_order(monkeypatch) -> None:
    """A timed-out limit submission that rests on the book is reported so."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _LostResponseClient(orders_pages=[[], [{"id": "0xa"}]])

    result = trade._post_buy_with_recovery_hint(
        client, object(), "12345", "order", "GTC"
    )

    assert result["submission"] == "resting"
    assert result["open_orders"] == [{"id": "0xa"}]
    assert confirmed == [12345]
    assert rejected == []


def test_lost_submission_ignores_preexisting_activity(monkeypatch, capsys) -> None:
    """Old trades and resting orders must not be claimed as this submission."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _LostResponseClient(
        trades_pages=[[{"id": "t0"}]], orders_pages=[[{"id": "o0"}]]
    )

    with pytest.raises(SystemExit):
        trade._post_buy_with_recovery_hint(client, object(), "12345", "order", "FOK")

    assert confirmed == []
    assert json.loads(capsys.readouterr().out)["submission"] == "unknown"


def test_lost_submission_reports_venue_down_when_reads_fail(
    monkeypatch, capsys
) -> None:
    """When reads fail too, the venue-health hint says so instead of guessing."""
    _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch, book_ok=False)

    with pytest.raises(SystemExit):
        trade._post_buy_with_recovery_hint(
            _AmbiguousOrderClient(), object(), "12345", "order", "FOK"
        )

    assert "reads fail too" in json.loads(capsys.readouterr().out)["venue_health"]


def test_matched_response_settles_via_backing_trade(monkeypatch) -> None:
    """A matched response backed by a trade for our order id is settled."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _MatchedResponseClient(
        trades_pages=[[], [{"id": "t1", "taker_order_id": "0xab"}]]
    )

    response = trade._post_buy_with_recovery_hint(
        client, object(), "12345", "order", "FOK"
    )

    assert response["settlement"] == "settled"
    assert response["settlement_trades"] == [{"id": "t1", "taker_order_id": "0xab"}]
    assert confirmed == [12345]


def test_matched_response_settles_via_new_trade_fallback(monkeypatch) -> None:
    """Without taker attribution, a trade new since the snapshot settles it."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _MatchedResponseClient(
        trades_pages=[[{"id": "t0"}], [{"id": "t0"}, {"id": "t9"}]]
    )

    response = trade._post_buy_with_recovery_hint(
        client, object(), "12345", "order", "FOK"
    )

    assert response["settlement"] == "settled"
    assert response["settlement_trades"] == [{"id": "t9"}]
    assert confirmed == [12345]


def test_matched_response_without_backing_trade_is_provisional(monkeypatch) -> None:
    """A phantom match keeps its pending marker and warns instead of confirming."""
    recorded, confirmed, rejected = _track_intents(monkeypatch)
    _no_network_no_sleep(monkeypatch)
    client = _MatchedResponseClient(trades_pages=[[]])

    response = trade._post_buy_with_recovery_hint(
        client, object(), "12345", "order", "FOK"
    )

    assert response["success"] is True
    assert response["settlement"] == "unverified"
    assert "phantom match" in response["warning"]
    assert confirmed == []
    assert rejected == []


def test_buy_hint_is_cleared_on_clean_http_401(monkeypatch) -> None:
    """A positive authentication rejection resolves its unsubmitted intent."""
    recorded = []
    rejected = []
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    monkeypatch.setattr(
        trade.pm, "reject_dw_buy_intent", lambda cs, tid: rejected.append(tid)
    )

    with pytest.raises(PolyApiException):
        trade._post_buy_with_recovery_hint(
            _HttpErrorOrderClient(401), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
    assert rejected == [12345]


def test_buy_hint_survives_message_only_auth_error(monkeypatch) -> None:
    """An auth-looking message without status remains an ambiguous submission."""
    rejected = []
    monkeypatch.setattr(trade.pm, "record_dw_buy_intent", lambda cs, tid: None)
    monkeypatch.setattr(
        trade.pm, "reject_dw_buy_intent", lambda cs, tid: rejected.append(tid)
    )

    with pytest.raises(PolyApiException):
        trade._post_buy_with_recovery_hint(
            _AuthMessageOrderClient(), object(), "12345", "order", "FOK"
        )

    assert rejected == []


def test_buy_hint_is_cleared_on_definitive_rejection(monkeypatch) -> None:
    """A success-false response is definitive and must not leave stale intent."""
    recorded = []
    rejected = []
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    monkeypatch.setattr(
        trade.pm, "reject_dw_buy_intent", lambda cs, tid: rejected.append(tid)
    )
    client = _OrderClient()
    monkeypatch.setattr(
        client,
        "post_order",
        lambda order, order_type: {"success": False, "errorMsg": "not filled"},
    )

    with pytest.raises(SystemExit, match="not filled"):
        trade._post_buy_with_recovery_hint(client, object(), "12345", "order", "FOK")

    assert recorded == [12345]
    assert rejected == [12345]


def test_buy_hint_is_confirmed_on_accepted_response(monkeypatch) -> None:
    """An accepted response resolves pending state but keeps the sweep hint."""
    recorded = []
    confirmed = []
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    monkeypatch.setattr(
        trade.pm, "confirm_dw_buy_intent", lambda cs, tid: confirmed.append(tid)
    )

    response = trade._post_buy_with_recovery_hint(
        _OrderClient(), object(), "12345", "order", "FOK"
    )

    assert response["success"] is True
    assert recorded == [12345]
    assert confirmed == [12345]


def test_buy_confirmation_state_failure_does_not_mask_acceptance(
    monkeypatch, capsys
) -> None:
    """Post-success bookkeeping failure keeps pending state and only warns."""
    monkeypatch.setattr(trade.pm, "record_dw_buy_intent", lambda cs, tid: None)

    def fail_confirmation(cs, token_id):
        raise OSError("disk full")

    monkeypatch.setattr(trade.pm, "confirm_dw_buy_intent", fail_confirmation)

    response = trade._post_buy_with_recovery_hint(
        _OrderClient(), object(), "12345", "order", "FOK"
    )

    assert response["success"] is True
    assert "action itself succeeded" in capsys.readouterr().err


def test_limit_buy_records_token(monkeypatch, capsys) -> None:
    """A limit BUY records the token to the DW-holdings hint (finding 1)."""
    recorded = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _OrderClient())
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    monkeypatch.setattr(trade.pm, "confirm_dw_buy_intent", lambda cs, tid: None)
    trade.cmd_limit(object(), "12345", "buy", 0.5, 10.0, "gtc", None)
    assert recorded == [12345]


def test_limit_sell_does_not_record(monkeypatch, capsys) -> None:
    """A limit SELL records nothing (no new token enters the DW)."""
    recorded = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _OrderClient())
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)
    monkeypatch.setattr(
        trade.pm, "record_dw_buy_intent", lambda cs, tid: recorded.append(tid)
    )
    trade.cmd_limit(object(), "12345", "sell", 0.5, 10.0, "gtc", None)
    assert recorded == []


@pytest.mark.parametrize(
    "invoke",
    [
        lambda: trade.cmd_buy(object(), "12345", 1.0, "fok"),
        lambda: trade.cmd_sell(object(), "12345", 1.0, "fak"),
        lambda: trade.cmd_limit(object(), "12345", "buy", 0.5, 10.0, "gtc", None),
        lambda: trade.cmd_limit(object(), "12345", "sell", 0.5, 10.0, "gtc", None),
    ],
)
def test_order_placement_disables_whole_operation_auth_retry(
    monkeypatch, invoke
) -> None:
    """No order-placement command may rebuild and resubmit a fresh order."""
    retry_modes = []
    monkeypatch.setattr(
        trade,
        "_run_client",
        lambda cs, op, retry_auth=True: retry_modes.append(retry_auth),
    )

    invoke()

    assert retry_modes == [False]


@pytest.mark.parametrize(
    "invoke",
    [
        lambda: trade.cmd_order(object(), "0xorder"),
        lambda: trade.cmd_cancel(object(), "0xorder"),
    ],
)
def test_existing_order_operations_keep_auth_retry(monkeypatch, invoke) -> None:
    """Reads and ID-based cancellation retain their retry-safe behavior."""
    retry_modes = []
    monkeypatch.setattr(
        trade,
        "_run_client",
        lambda cs, op, retry_auth=True: retry_modes.append(retry_auth),
    )

    invoke()

    assert retry_modes == [True]


# --- funds sweep: refuse while resting orders back the DW (finding 2) -----------


class _OrdersClient:
    """A CLOB client returning a fixed open-order list (or raising)."""

    def __init__(self, orders=None, boom=False):
        """Configure the fixed open orders, or a failure to fetch them."""
        self._orders = orders or []
        self._boom = boom

    def get_open_orders(self):
        """Return the configured open orders, or raise if boom is set."""
        if self._boom:
            raise RuntimeError("clob down")
        return self._orders


def test_abort_if_open_orders_blocks(monkeypatch) -> None:
    """An open order blocks the sweep with a cancel-first message."""
    monkeypatch.setattr(
        remote_signer, "make_clob_client", lambda cs, dw: _OrdersClient([{"id": "0xa"}])
    )
    with pytest.raises(SystemExit) as exc:
        funds._abort_if_open_orders(object(), "0xdw")
    assert "open CLOB order" in str(exc.value)


def test_abort_if_open_orders_allows_when_none(monkeypatch) -> None:
    """No open orders → the guard passes without raising."""
    monkeypatch.setattr(
        remote_signer, "make_clob_client", lambda cs, dw: _OrdersClient([])
    )
    funds._abort_if_open_orders(object(), "0xdw")


def test_abort_if_open_orders_blocks_when_unverifiable(monkeypatch) -> None:
    """A failure to check open orders blocks — don't sweep blind."""
    monkeypatch.setattr(
        remote_signer, "make_clob_client", lambda cs, dw: _OrdersClient(boom=True)
    )
    with pytest.raises(SystemExit) as exc:
        funds._abort_if_open_orders(object(), "0xdw")
    assert "could not verify" in str(exc.value)


class _EmptyDwCS:
    """A connect-signer stand-in whose DW reads as empty."""

    safe_address = "0x" + "5a" * 20
    w3 = object()


def _mock_empty_dw(monkeypatch) -> list:
    """Make cmd_sweep see an empty DW; return a list tracking guard calls."""
    called = []
    monkeypatch.setattr(funds, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(funds, "_abort_if_open_orders", lambda cs, dw: called.append(1))
    monkeypatch.setattr(funds.pm, "erc20_balance_of", lambda w3, token, owner: 0)
    monkeypatch.setattr(funds.pm, "dw_open_tokens", lambda cs: [])
    monkeypatch.setattr(funds.pm, "dw_pending_buy_tokens", lambda cs: [])
    monkeypatch.setattr(funds, "_dw_position_token_ids", lambda dw: [])
    return called


def test_cmd_sweep_checks_orders_by_default(monkeypatch, capsys) -> None:
    """Without --force, the open-orders guard runs."""
    called = _mock_empty_dw(monkeypatch)
    funds.cmd_sweep(_EmptyDwCS(), None, force=False)
    assert called == [1]


def test_cmd_sweep_force_skips_order_check(monkeypatch, capsys) -> None:
    """--force bypasses the open-orders guard."""
    called = _mock_empty_dw(monkeypatch)
    funds.cmd_sweep(_EmptyDwCS(), None, force=True)
    assert called == []
