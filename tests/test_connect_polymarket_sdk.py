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
        return {"status": "live"}


def test_limit_buy_records_token(monkeypatch, capsys) -> None:
    """A limit BUY records the token to the DW-holdings hint (finding 1)."""
    recorded = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _OrderClient())
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)
    monkeypatch.setattr(
        trade.pm, "record_dw_token_best_effort", lambda cs, tid: recorded.append(tid)
    )
    trade.cmd_limit(object(), "12345", "buy", 0.5, 10.0, "gtc", None)
    assert recorded == [12345]


def test_limit_sell_does_not_record(monkeypatch, capsys) -> None:
    """A limit SELL records nothing (no new token enters the DW)."""
    recorded = []
    monkeypatch.setattr(trade, "dw_or_exit", lambda cs: "0xdw")
    monkeypatch.setattr(trade, "make_clob_client", lambda cs, dw: _OrderClient())
    monkeypatch.setattr(trade, "clear_cached_creds", lambda cs: None)
    monkeypatch.setattr(
        trade.pm, "record_dw_token_best_effort", lambda cs, tid: recorded.append(tid)
    )
    trade.cmd_limit(object(), "12345", "sell", 0.5, 10.0, "gtc", None)
    assert recorded == []


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
