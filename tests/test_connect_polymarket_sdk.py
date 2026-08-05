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
env, or a dev venv with the SDK). It covers the two branches the live e2e did
not: the auth-failure creds-refresh retry, and the Account-shim routing.
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
    """A CLOB client that loses the response after a possible acceptance."""

    def post_order(self, order, order_type):
        """Raise without an HTTP status, leaving submission outcome unknown."""
        raise PolyApiException(error_msg="Request exception!")


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


def test_buy_hint_survives_ambiguous_submission(monkeypatch) -> None:
    """A lost response must leave a hint that a later sweep can inspect."""
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

    with pytest.raises(PolyApiException):
        trade._post_buy_with_recovery_hint(
            _AmbiguousOrderClient(), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
    assert confirmed == []
    assert rejected == []


def test_buy_hint_survives_http_408(monkeypatch) -> None:
    """A timeout response is ambiguous and must retain its recovery marker."""
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

    with pytest.raises(PolyApiException):
        trade._post_buy_with_recovery_hint(
            _HttpErrorOrderClient(408), object(), "12345", "order", "FOK"
        )

    assert recorded == [12345]
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


# --- trade.py quote (OPE-1862 #4) ----------------------------------------------


class _QuoteSdkClient:
    """Stands in for the SDK's sizing calls, with a flat 3% taker fee."""

    def calculate_market_price(self, token_id, side, amount, order_type):
        return 0.5

    def _adjust_buy_amount_for_balance(self, token_id, amount, price, balance, _):
        return min(amount, balance / 1.03)


class _QuoteCS:
    """A connect-signer stand-in: the quote only needs a web3 for the balance."""

    w3 = object()


def _mock_quote(monkeypatch, balance_units) -> None:
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _QuoteSdkClient())
    monkeypatch.setattr(
        trade.pm, "erc20_balance_of", lambda w3, token, owner: balance_units
    )


def test_cmd_quote_prices_a_buy_without_placing_it(monkeypatch, capsys) -> None:
    """The whole point: the numbers, with no order behind them."""
    _mock_quote(monkeypatch, 100_000_000)
    monkeypatch.setattr(
        trade.pm,
        "record_dw_buy_intent",
        lambda cs, tid: pytest.fail("a quote must not touch order state"),
    )

    trade.cmd_quote(_QuoteCS(), "12345", 10.0, "fok")

    quote = json.loads(capsys.readouterr().out)
    assert quote["fill_price"] == 0.5
    assert quote["estimated_shares"] == 20.0
    assert quote["shortfall_usd"] == 0.0
    assert quote["blocked"] is False


def test_cmd_quote_answers_on_an_empty_deposit_wallet(monkeypatch, capsys) -> None:
    """`buy` refuses a zero balance; a quote is how you learn the top-up."""
    _mock_quote(monkeypatch, 0)

    trade.cmd_quote(_QuoteCS(), "12345", 10.0, "fok")

    quote = json.loads(capsys.readouterr().out)
    assert quote["dw_balance_usd"] == 0.0
    assert quote["shortfall_usd"] == quote["required_dw_balance_usd"]


def test_quote_keeps_the_auth_retry(monkeypatch) -> None:
    """A quote places nothing, so a credentials refresh cannot double-spend."""
    retry_modes = []
    monkeypatch.setattr(
        trade,
        "_run_client",
        lambda cs, op, retry_auth=True: retry_modes.append(retry_auth),
    )

    trade.cmd_quote(_QuoteCS(), "12345", 10.0, "fok")

    assert retry_modes == [True]


def test_buy_preflight_and_quote_agree(monkeypatch, capsys) -> None:
    """The blocked-buy error must quote the same numbers `quote` reports.

    They share pm.quote_buy precisely so a preflight refusal and a quote can
    never disagree about the top-up needed.
    """
    _mock_quote(monkeypatch, 1_000_000)  # a $1.00 balance against a $1.00 bet
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)

    trade.cmd_quote(_QuoteCS(), "12345", 1.0, "fok")
    quote = json.loads(capsys.readouterr().out)
    assert quote["blocked"] is True

    with pytest.raises(SystemExit) as exc:
        trade.cmd_buy(_QuoteCS(), "12345", 1.0, "fok")
    assert f"{quote['shortfall_usd']:.4f}" in str(exc.value)
    assert "trade.py quote" in str(exc.value)


def test_main_wires_the_quote_subcommand(monkeypatch, capsys) -> None:
    """The CLI is the only way this runs in production, so parse it for real."""
    _mock_quote(monkeypatch, 100_000_000)
    monkeypatch.setattr(
        trade.pm.ConnectSigner, "from_workspace", classmethod(lambda cls: _QuoteCS())
    )
    monkeypatch.setattr(
        sys, "argv", ["trade.py", "quote", "--token-id", "12345", "--usd", "10"]
    )

    trade.main()

    assert json.loads(capsys.readouterr().out)["requested_usd"] == 10.0


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
