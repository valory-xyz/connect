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

"""Unit tests for the connect-polymarket skill's pure, money-critical logic.

These lock the bytes/behaviour a silent bug would corrupt: calldata encoders,
the EIP-712 DepositWallet batch digest, the dollar↔units conversion, the
approval-set decision, ``contract_owner``'s RPC-vs-revert distinction, the
relayer tx record selection, and ``_resolve_dw``'s safety branches. No
network and no funds. The order-signing tests run the pinned unified SDK
(``polymarket-client``, a dev dependency) against a stand-in for the Connect
signer, so the signatures they check are the SDK's own.
"""

# The skill modules are imported at runtime via a sys.path insert (they ship
# as bundled assets, not an installed package) and pull in the CLOB SDK —
# mypy can follow none of this, so skip the file.
# mypy: ignore-errors

import importlib
import importlib.util
import json
import os
import random
import re
import subprocess  # nosec B404 - runs the skill's own bootstrap script
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
import requests
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import (
    _hash_eip191_message,
    encode_defunct,
    encode_typed_data,
)
from eth_account.signers.local import LocalAccount
from eth_keys import keys as eth_keys
from eth_utils import is_address, keccak, to_checksum_address
from polymarket import SecureClient
from polymarket._internal.actions.orders import cache as sdk_order_cache
from polymarket._internal.actions.orders import orders as sdk_orders
from polymarket._internal.actions.orders.market_data import MarketInfo, PlatformFeeInfo
from polymarket._internal.l1_auth import build_api_key_auth_typed_data
from polymarket.environments import PRODUCTION
from web3.exceptions import ContractLogicError, TimeExhausted

from connect import workspace

# The skill ships as bundled assets, not an installed package; put its scripts
# dir on the path so we can import the modules under test. pm_common locates
# its sibling pearl-connect client relative to its own __file__, so that works
# without further setup.
_SCRIPTS = (
    Path(__file__).resolve().parent.parent
    / "connect"
    / "assets"
    / "skills"
    / "connect-polymarket"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS))

import deposit_wallet  # noqa: E402
import funds  # noqa: E402
import markets  # noqa: E402
import netcheck  # noqa: E402
import pm_common as pm  # noqa: E402
import positions  # noqa: E402
import redeem  # noqa: E402
import relayer_proxy  # noqa: E402


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly rather than reach the internet from a unit test.

    `markets.py`'s commands price live by default, so a test that drives one
    without stubbing the CLOB quietly makes a real request: it passes on a
    developer machine and hangs for HTTP_TIMEOUT on an isolated CI runner.
    Tests that need these install their own fakes, which override this.
    """

    def explode(*args, **kwargs):
        raise AssertionError(
            "a unit test tried to reach the network — stub pm.http_get_json / "
            "pm.http_post_json / pm.clob_live_prices in the test instead"
        )

    monkeypatch.setattr(pm, "http_get_json", explode)
    monkeypatch.setattr(pm, "http_post_json", explode)


ADDR_A = to_checksum_address("0x" + "11" * 20)
ADDR_B = to_checksum_address("0x" + "22" * 20)
DW_ADDR = to_checksum_address("0x" + "d0" * 20)
SAFE_ADDR = to_checksum_address("0x" + "5a" * 20)

# Polygon mainnet addresses, written out rather than read from the skill so a
# wrong constant there fails these tests instead of cancelling out. They match
# Polymarket's published deployments and the pinned SDK's production config
# (checked in test_dw_setup_includes_v2_approvals).
_PUSD = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB"
_CTF = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
_CTF_EXCHANGE = "0xE111180000d2663C0091e4f400237545B87B996B"
_NEG_RISK_CTF_EXCHANGE = "0xe2222d279d744050d28e00520010520000310F59"
_NEG_RISK_ADAPTER = "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296"
_EXCHANGE_V3 = "0xe3333700cA9d93003F00f0F71f8515005F6c00Aa"
_POSITION_MANAGER = "0x006F54F7f9A22e0000CC2AB60031000000ae9fEF"
_V2_ROUTER = "0x12121212006e4CD160D18e3f00711DA5c3372600"
_AUTO_REDEEMER = "0xa1200000d0002264C9a1698e001292D00E1b00af"
_MAX_UINT256 = 2**256 - 1


# The data API's v2 name for each v1 field the fixtures are written in. Kept
# literal, not derived from the skill's own map, so a wrong entry there fails
# these tests instead of cancelling out.
_POSITION_V1_TO_V2 = {
    "proxyWallet": "proxy_wallet",
    "asset": "token_id",
    "conditionId": "condition_id",
    "size": "current_size",
    "avgPrice": "avg_price",
    "initialValue": "entry_cost_usdc",
    "currentValue": "current_value",
    "cashPnl": "unrealized_pnl",
    "curPrice": "current_price",
    "redeemable": "redeemable",
    "mergeable": "mergeable",
    "title": "title",
    "slug": "slug",
    "eventSlug": "event_slug",
    "outcome": "outcome",
    "outcomeIndex": "outcome_index",
    "endDate": "end_date",
    "negativeRisk": "negative_risk",
}


def _v2_page(rows, next_cursor=None):
    """Wrap fixture rows, written with v1 names, as one data-API v2 page."""
    return {
        "data": [
            {_POSITION_V1_TO_V2.get(k, k): v for k, v in row.items()} for row in rows
        ],
        "pagination": {"next_cursor": next_cursor},
    }


def _paged(pages):
    """Serve `pages` (cursor -> page) and record each request's params."""
    seen = []

    def fake_get(url, params=None):
        seen.append(dict(params))
        return pages[params.get("cursor")]

    return fake_get, seen


# --- calldata encoders ----------------------------------------------------------


def test_encoder_selectors_are_the_canonical_four_bytes() -> None:
    """A typo'd function signature would change the selector and mis-target."""
    assert pm.encode_erc20_approve(ADDR_A, 5).startswith("0x095ea7b3")
    assert pm.encode_erc20_transfer(ADDR_A, 5).startswith("0xa9059cbb")
    assert pm.encode_set_approval_for_all(ADDR_A, True).startswith("0xa22cb465")
    assert pm.encode_erc1155_safe_transfer(ADDR_A, ADDR_B, 1, 2).startswith(
        "0xf242432a"
    )
    assert pm.encode_onramp_wrap(pm.USDC_E, ADDR_A, 5).startswith("0x62355638")
    assert pm.encode_redeem_positions("0x" + "22" * 32, [1]).startswith("0x01b7037c")


def test_encoder_arguments_round_trip() -> None:
    """The ABI-encoded tail decodes back to exactly what was passed."""
    data = pm.encode_erc20_approve(ADDR_A, 12345)
    spender, amount = abi_decode(["address", "uint256"], bytes.fromhex(data[10:]))
    assert to_checksum_address(spender) == ADDR_A
    assert amount == 12345

    data = pm.encode_erc1155_safe_transfer(ADDR_A, ADDR_B, 99, 7)
    frm, to, tid, amt, _ = abi_decode(
        ["address", "address", "uint256", "uint256", "bytes"],
        bytes.fromhex(data[10:]),
    )
    assert (to_checksum_address(frm), to_checksum_address(to), tid, amt) == (
        ADDR_A,
        ADDR_B,
        99,
        7,
    )


def test_encode_redeem_positions_uses_pusd_and_condition() -> None:
    """The collateral is pUSD and the condition bytes32 survives hex-stripping."""
    condition = "0x" + "ab" * 32
    data = pm.encode_redeem_positions(condition, [1 << 3])
    collateral, parent, cond, index_sets = abi_decode(
        ["address", "bytes32", "bytes32", "uint256[]"], bytes.fromhex(data[10:])
    )
    assert to_checksum_address(collateral) == pm.PUSD
    assert parent == pm.PARENT_COLLECTION_ID
    assert cond == bytes.fromhex("ab" * 32)
    assert list(index_sets) == [8]


# --- unit conversions -----------------------------------------------------------


@pytest.mark.parametrize(
    ("amount", "units"),
    [(0, 0), (1.0, 1_000_000), (0.005, 5_000), (0.000001, 1), (2.006992, 2_006_992)],
)
def test_usd_units_round_trip(amount: float, units: int) -> None:
    """Dollar amounts convert to 6-decimal base units and back exactly."""
    assert pm.usd_to_units(amount) == units
    assert pm.units_to_usd(units) == pytest.approx(amount)


# --- best-effort token recording (must not mask a completed action) -------------


def test_record_dw_token_best_effort_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """On success it records the token and returns True."""
    recorded = []
    monkeypatch.setattr(pm, "record_dw_token", lambda cs, tid: recorded.append(tid))
    assert pm.record_dw_token_best_effort(None, 123) is True
    assert recorded == [123]


def test_record_dw_token_best_effort_swallows_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A state-write failure after a completed action must NOT raise."""

    def _boom(cs, tid):
        raise OSError("disk full")

    monkeypatch.setattr(pm, "record_dw_token", _boom)
    assert pm.record_dw_token_best_effort(None, 123) is False
    assert "could not record" in capsys.readouterr().err


# --- approval-set decision ------------------------------------------------------


def test_missing_approval_calls_when_nothing_is_granted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All-missing yields 3 pUSD approvals and 3 operator grants, no more.

    pUSD goes to both current exchanges and ExchangeV3; the CTF grants go to
    the two current exchanges, and the PositionManager grant to ExchangeV3.
    """
    monkeypatch.setattr(pm, "erc20_allowance", lambda *a: 0)
    monkeypatch.setattr(pm, "is_approved_for_all", lambda *a: False)
    calls = pm.missing_approval_calls(None, ADDR_A)
    assert len(calls) == 6
    pusd_calls = [c for c in calls if c["target"] == pm.PUSD]
    ctf_calls = [c for c in calls if c["target"] == pm.CTF]
    position_calls = [c for c in calls if c["target"] == _POSITION_MANAGER]
    assert len(pusd_calls) == 3
    assert len(ctf_calls) == 2
    assert len(position_calls) == 1
    assert all(c["data"].startswith("0x095ea7b3") for c in pusd_calls)
    assert all(c["data"].startswith("0xa22cb465") for c in ctf_calls + position_calls)


def test_missing_approval_calls_skips_already_granted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The skip-when-approved path: a fully-approved wallet needs no calls."""
    monkeypatch.setattr(pm, "erc20_allowance", lambda *a: pm.MAX_UINT256)
    monkeypatch.setattr(pm, "is_approved_for_all", lambda *a: True)
    assert pm.missing_approval_calls(None, ADDR_A) == []


def test_missing_approval_calls_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the genuinely-missing grant is emitted."""
    granted_spender = pm.APPROVAL_SPENDERS_PUSD[0]
    monkeypatch.setattr(
        pm,
        "erc20_allowance",
        lambda w3, token, owner, spender: (
            pm.MAX_UINT256 if spender == granted_spender else 0
        ),
    )
    monkeypatch.setattr(pm, "is_approved_for_all", lambda *a: True)
    calls = pm.missing_approval_calls(None, ADDR_A)
    assert len(calls) == 2  # the two pUSD spenders that are NOT yet approved
    assert all(c["target"] == pm.PUSD for c in calls)


def test_collateral_adapters_absent_from_dw_approval_set() -> None:
    """The DW must not be granted operator rights on redemption-only adapters."""
    assert pm.CTF_COLLATERAL_ADAPTER not in pm.APPROVAL_OPERATORS_CTF
    assert pm.NEG_RISK_CTF_COLLATERAL_ADAPTER not in pm.APPROVAL_OPERATORS_CTF


# --- contract_owner: RPC failure must NOT look like "not owned" -----------------


def test_contract_owner_reads_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 32-byte return decodes to the checksummed owner address."""
    monkeypatch.setattr(
        pm, "_eth_call", lambda w3, to, data: bytes(12) + bytes.fromhex("11" * 20)
    )
    assert pm.contract_owner(None, ADDR_A) == ADDR_A


def test_contract_owner_none_on_revert(monkeypatch: pytest.MonkeyPatch) -> None:
    """A reverting owner() means not-Ownable, returned as None."""

    def _raise(*_a):
        raise ContractLogicError("execution reverted")

    monkeypatch.setattr(pm, "_eth_call", _raise)
    assert pm.contract_owner(None, ADDR_A) is None


def test_contract_owner_none_on_empty_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty return (no code) means not-Ownable, returned as None."""
    monkeypatch.setattr(pm, "_eth_call", lambda *a: b"")
    assert pm.contract_owner(None, ADDR_A) is None


def test_contract_owner_propagates_rpc_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transport error must raise, not be swallowed as None (would orphan a DW)."""

    def _raise(*_a):
        raise ConnectionError("rpc down")

    monkeypatch.setattr(pm, "_eth_call", _raise)
    with pytest.raises(ConnectionError):
        pm.contract_owner(None, ADDR_A)


# --- EIP-712 DepositWallet batch digest -----------------------------------------

# Golden digest for fixed inputs (dw, nonce=7, deadline=1800000000, one pUSD
# transfer of 1_000_000 to 0x22..). Any change to the typehashes, domain, or
# field order changes this — a regression that would sign the wrong batch.
_GOLDEN_BATCH_DIGEST = (
    "963de55ceeb9f6469c35e6a84d75b36a85837f475e14d8a9e2d382037139d1ea"
)
_DW = to_checksum_address("0x033c547383D6dE15E7BF95e60B947b98Bd0D23BD")


class _CapturingSigner:
    agent_eoa = "0x9EC5088Bee3eaDcEa7D1E59C0EBaCaD68afB9818"

    def __init__(self) -> None:
        self.digest: str | None = None

    def sign_digest(self, digest) -> str:
        self.digest = digest.hex() if isinstance(digest, (bytes, bytearray)) else digest
        return "0x" + "00" * 65


def _proxy_with(signer: _CapturingSigner) -> relayer_proxy.RelayerProxyClient:
    proxy = relayer_proxy.RelayerProxyClient.__new__(relayer_proxy.RelayerProxyClient)
    proxy._cs = signer  # noqa: SLF001 - test seam
    return proxy


def test_sign_batch_matches_golden_digest() -> None:
    """The EIP-712 batch digest for fixed inputs matches the captured golden."""
    signer = _CapturingSigner()
    calls = [{"target": pm.PUSD, "data": pm.encode_erc20_transfer(ADDR_B, 1_000_000)}]
    _proxy_with(signer)._sign_batch(_DW, 7, 1_800_000_000, calls)
    assert signer.digest == _GOLDEN_BATCH_DIGEST


def test_sign_batch_digest_depends_on_calls() -> None:
    """A different call target must produce a different digest."""
    base = _CapturingSigner()
    other = _CapturingSigner()
    calls_a = [{"target": pm.PUSD, "data": pm.encode_erc20_transfer(ADDR_B, 1)}]
    calls_b = [{"target": pm.CTF, "data": pm.encode_erc20_transfer(ADDR_B, 1)}]
    _proxy_with(base)._sign_batch(_DW, 7, 1_800_000_000, calls_a)
    _proxy_with(other)._sign_batch(_DW, 7, 1_800_000_000, calls_b)
    assert base.digest != other.digest


# --- relayer transaction record selection ---------------------------------------


def test_relayer_transaction_selects_matching_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The record whose transactionID matches is the one selected."""
    proxy = relayer_proxy.RelayerProxyClient.__new__(relayer_proxy.RelayerProxyClient)
    records = [
        {"transactionID": "other", "state": "STATE_MINED", "transactionHash": "0xdead"},
        {
            "transactionID": "want",
            "state": "STATE_CONFIRMED",
            "transactionHash": "0xbeef",
        },
    ]
    monkeypatch.setattr(proxy, "_request", lambda *a, **k: records)
    assert proxy.transaction("want") == ("STATE_CONFIRMED", "0xbeef")


def test_relayer_transaction_no_false_match(monkeypatch: pytest.MonkeyPatch) -> None:
    """An absent id must NOT bind an unrelated record's state/hash."""
    proxy = relayer_proxy.RelayerProxyClient.__new__(relayer_proxy.RelayerProxyClient)
    records = [
        {"transactionID": "other", "state": "STATE_MINED", "transactionHash": "0xdead"}
    ]
    monkeypatch.setattr(proxy, "_request", lambda *a, **k: records)
    assert proxy.transaction("missing") == ("", None)


# --- _resolve_dw safety branches ------------------------------------------------


class _StubCS:
    agent_eoa = to_checksum_address("0x" + "9e" * 20)
    w3 = object()


class _StubProxy:
    """Relayer proxy that answers the one question `cmd_status` asks it."""

    @staticmethod
    def deployed(dw: str) -> bool:
        return True


def test_resolve_dw_none_when_no_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """No persisted DW record resolves to None (a fresh deploy is safe)."""
    monkeypatch.setattr(pm, "load_state", lambda cs: {})
    assert deposit_wallet._resolve_dw(_StubCS()) is None


def test_resolve_dw_returns_owned(monkeypatch: pytest.MonkeyPatch) -> None:
    """A recorded DW still owned by the agent EOA resolves to its address."""
    dw = to_checksum_address("0x" + "de" * 20)
    monkeypatch.setattr(
        pm, "load_state", lambda cs: {"deposit_wallet": {"address": dw}}
    )
    monkeypatch.setattr(pm, "contract_owner", lambda w3, a: _StubCS.agent_eoa)
    assert deposit_wallet._resolve_dw(_StubCS()) == dw


def test_resolve_dw_raises_on_unreadable_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A recorded DW whose owner reads as None is fatal, never a silent redeploy."""
    dw = to_checksum_address("0x" + "de" * 20)
    monkeypatch.setattr(
        pm, "load_state", lambda cs: {"deposit_wallet": {"address": dw}}
    )
    monkeypatch.setattr(pm, "contract_owner", lambda w3, a: None)
    with pytest.raises(SystemExit):
        deposit_wallet._resolve_dw(_StubCS())


def test_resolve_dw_discards_foreign(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DW owned by another EOA is discarded (record cleared), returns None."""
    dw = to_checksum_address("0x" + "de" * 20)
    saved: dict = {}
    monkeypatch.setattr(
        pm,
        "load_state",
        lambda cs: {"deposit_wallet": {"address": dw}, "approvals_done": True},
    )
    monkeypatch.setattr(pm, "save_state", lambda cs, state: saved.update(state))
    monkeypatch.setattr(
        pm, "contract_owner", lambda w3, a: to_checksum_address("0x" + "ff" * 20)
    )
    assert deposit_wallet._resolve_dw(_StubCS()) is None
    assert "deposit_wallet" not in saved
    assert "approvals_done" not in saved


# --- check_mined (receipt-status enforcement) -----------------------------------


def test_check_mined_passes_on_success() -> None:
    """A status-1 receipt is returned unchanged."""
    receipt = {"status": 1, "tx_hash": "0x1"}
    assert pm.check_mined(receipt, "act") is receipt


@pytest.mark.parametrize("status", [0, None])
def test_check_mined_raises_on_failure(status) -> None:
    """A reverted or unconfirmed receipt raises (never silently passes)."""
    with pytest.raises(SystemExit):
        pm.check_mined({"status": status, "tx_hash": "0x1"}, "act")


# --- wait_receipt (web3-delegated) ----------------------------------------------


class _FakeEth:
    def __init__(self, receipt=None, timeout=False) -> None:
        self._receipt = receipt
        self._timeout = timeout

    def wait_for_transaction_receipt(self, tx_hash, timeout, poll_latency):
        if self._timeout:
            raise TimeExhausted()
        return self._receipt


def _cs_with_eth(eth):
    cs = pm.ConnectSigner.__new__(pm.ConnectSigner)
    cs._w3 = type("_W3", (), {"eth": eth})()
    cs._info = None
    return cs


def test_wait_receipt_returns_status() -> None:
    """A mined receipt's status is surfaced."""
    cs = _cs_with_eth(_FakeEth(receipt={"status": 1}))
    assert cs.wait_receipt("0xabc") == {"tx_hash": "0xabc", "status": 1}


def test_wait_receipt_timeout_is_status_none() -> None:
    """A web3 TimeExhausted becomes status None, not an exception."""
    cs = _cs_with_eth(_FakeEth(timeout=True))
    out = cs.wait_receipt("0xabc", timeout=0.01)
    assert out["status"] is None
    assert "timeout" in out["note"]


# --- state: atomic write, corrupt-raise, token hints ----------------------------


def _cs_with_workspace(tmp_path):
    cs = pm.ConnectSigner.__new__(pm.ConnectSigner)
    cs.workspace = tmp_path
    return cs


def test_state_round_trip_atomic(tmp_path) -> None:
    """save_state persists, leaves no temp file; a missing file loads as {}."""
    cs = _cs_with_workspace(tmp_path)
    assert pm.load_state(cs) == {}
    pm.save_state(cs, {"a": 1})
    assert pm.load_state(cs) == {"a": 1}
    assert not (tmp_path / "polymarket" / "state.json.tmp").exists()


def test_load_state_corrupt_raises(tmp_path) -> None:
    """A corrupt state file is a hard error, not a silent reset."""
    cs = _cs_with_workspace(tmp_path)
    path = pm.state_path(cs)
    path.parent.mkdir(parents=True)
    path.write_text("{ not json")
    with pytest.raises(SystemExit):
        pm.load_state(cs)


def test_dw_token_hint_round_trip(tmp_path) -> None:
    """record/forget maintain a deduped, sorted DW-holdings hint."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_token(cs, 5)
    pm.record_dw_token(cs, 5)
    pm.record_dw_token(cs, 9)
    assert pm.dw_open_tokens(cs) == [5, 9]
    pm.forget_dw_tokens(cs, [5])
    assert pm.dw_open_tokens(cs) == [9]


def test_dw_buy_intent_lifecycle(tmp_path) -> None:
    """A confirmed buy clears its pending intent but retains its hint."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_buy_intent(cs, 5)
    assert pm.dw_open_tokens(cs) == [5]
    assert pm.dw_pending_buy_tokens(cs) == [5]

    pm.confirm_dw_buy_intent(cs, 5)
    assert pm.dw_open_tokens(cs) == [5]
    assert pm.dw_pending_buy_tokens(cs) == []


def test_ambiguous_then_accepted_repeat_keeps_pending_intent(tmp_path) -> None:
    """Accepting repeat B must not erase ambiguous submission A."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_buy_intent(cs, 5)
    pm.record_dw_buy_intent(cs, 5)
    pm.confirm_dw_buy_intent(cs, 5)

    assert pm.dw_open_tokens(cs) == [5]
    assert pm.dw_pending_buy_tokens(cs) == [5]
    assert pm.load_state(cs)["dw_pending_buy_counts"] == {"5": 1}


def test_buy_intent_confirm_and_reject_share_one_implementation() -> None:
    """confirm_/reject_ are aliases: the resolution bookkeeping is identical."""
    assert pm.confirm_dw_buy_intent is pm.resolve_dw_buy_intent
    assert pm.reject_dw_buy_intent is pm.resolve_dw_buy_intent


def test_ambiguous_then_rejected_repeat_keeps_pending_intent(tmp_path) -> None:
    """Rejecting repeat B must not erase ambiguous submission A."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_buy_intent(cs, 5)
    pm.record_dw_buy_intent(cs, 5)
    pm.reject_dw_buy_intent(cs, 5)

    assert pm.dw_open_tokens(cs) == [5]
    assert pm.dw_pending_buy_tokens(cs) == [5]
    assert pm.load_state(cs)["dw_pending_buy_counts"] == {"5": 1}


def test_existing_hint_survives_rejected_repeat_buy(tmp_path) -> None:
    """A rejected repeat cannot delete a pre-existing holdings hint."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_token(cs, 5)
    pm.record_dw_buy_intent(cs, 5)
    pm.reject_dw_buy_intent(cs, 5)

    assert pm.dw_open_tokens(cs) == [5]
    assert pm.dw_pending_buy_tokens(cs) == []


def test_forget_dw_token_preserves_pending_intent(tmp_path) -> None:
    """Sweeping one fill must not erase another unresolved submission."""
    cs = _cs_with_workspace(tmp_path)
    pm.record_dw_buy_intent(cs, 5)
    pm.forget_dw_tokens(cs, [5])

    assert pm.dw_open_tokens(cs) == []
    assert pm.dw_pending_buy_tokens(cs) == [5]


# --- funds.cmd_sweep: state-union discovery + on-chain confirm (C1/A1) -----------


class _SweepCS:
    safe_address = SAFE_ADDR
    w3 = object()

    def __init__(self, receipt) -> None:
        self._receipt = receipt

    def wait_receipt(self, tx_hash, timeout=300):
        return self._receipt


class _FakeRelayer:
    result = (True, "STATE_MINED", "0xhash")

    def __init__(self, cs, base_url=None) -> None:
        pass

    def exec_wallet_batch(self, dw, nonce, calls):
        return "relayer-tx"

    def wait_terminal(self, tx_id):
        return _FakeRelayer.result


def test_dw_position_token_ids_fetches_every_page(monkeypatch) -> None:
    """Every indexed DW-position page contributes sweep candidates."""
    monkeypatch.setattr(funds, "POSITIONS_PAGE_LIMIT", 2, raising=False)
    fake_get, seen = _paged(
        {
            None: _v2_page([{"asset": "11"}, {"asset": "12"}], "c2"),
            "c2": _v2_page([{"asset": "13"}]),
        }
    )
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    assert funds._dw_position_token_ids(DW_ADDR) == [11, 12, 13]
    assert [params.get("cursor") for params in seen] == [None, "c2"]
    assert all(params["limit"] == 2 for params in seen)


@pytest.mark.parametrize(
    "payload", [None, {"positions": []}, [{"asset": "12"}], {"data": []}]
)
def test_dw_position_token_ids_rejects_malformed_page(monkeypatch, payload) -> None:
    """Malformed or v1-shaped pages cannot masquerade as completion."""
    pages = iter((_v2_page([{"asset": "11"}], "c2"), payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="malformed data"):
        funds._dw_position_token_ids(DW_ADDR)


def test_dw_position_token_ids_fails_at_the_page_cap(monkeypatch) -> None:
    """A read still paging at the cap cannot be mistaken for completion."""
    monkeypatch.setattr(pm, "DATA_API_MAX_PAGES", 2)
    cursors = iter(("c1", "c2", "c3"))
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _v2_page([{"asset": "11"}], next(cursors)),
    )

    with pytest.raises(SystemExit, match="pagination limit"):
        funds._dw_position_token_ids(DW_ADDR)


def _sweep_mocks(monkeypatch, *, pusd, ctf_balance, recorded, indexed, pending=()):
    # Bypass the open-orders guard here (it needs the CLOB SDK); it has its
    # own tests in test_connect_polymarket_sdk.py.
    monkeypatch.setattr(funds, "_abort_if_open_orders", lambda cs, dw: None)
    monkeypatch.setattr(funds, "dw_or_exit", lambda cs: DW_ADDR)
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, tok, dw: pusd)
    monkeypatch.setattr(pm, "erc1155_balance_of", lambda w3, ctf, dw, tid: ctf_balance)
    monkeypatch.setattr(pm, "dw_open_tokens", lambda cs: recorded)
    monkeypatch.setattr(pm, "dw_pending_buy_tokens", lambda cs: list(pending))
    monkeypatch.setattr(funds, "_dw_position_token_ids", lambda dw: indexed)
    monkeypatch.setattr(pm, "dw_nonce", lambda w3, dw: 1)
    monkeypatch.setattr(funds, "RelayerProxyClient", _FakeRelayer)


def test_sweep_empty_dw_warns(monkeypatch, capsys) -> None:
    """An empty DW with no discoverable positions reports not-swept + a warning."""
    _sweep_mocks(monkeypatch, pusd=0, ctf_balance=0, recorded=[], indexed=[])
    funds.cmd_sweep(_SweepCS({"status": 1}), None)
    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is False
    assert "warning" in out


def test_sweep_confirms_and_forgets(monkeypatch, capsys) -> None:
    """A recorded token is swept, confirmed on-chain, then dropped from the hint."""
    forgotten = []
    _sweep_mocks(monkeypatch, pusd=1_000_000, ctf_balance=500, recorded=[7], indexed=[])
    monkeypatch.setattr(pm, "forget_dw_tokens", lambda cs, ids: forgotten.extend(ids))
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")
    funds.cmd_sweep(_SweepCS({"status": 1, "tx_hash": "0xhash"}), None)
    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert out["positions"] == {"7": 500}
    assert forgotten == [7]


def test_sweep_checks_pending_token_without_holdings_hint(monkeypatch, capsys) -> None:
    """A pending-only token remains an on-chain sweep candidate."""
    forgotten = []
    _sweep_mocks(
        monkeypatch,
        pusd=0,
        ctf_balance=500,
        recorded=[],
        indexed=[],
        pending=[7],
    )
    monkeypatch.setattr(pm, "forget_dw_tokens", lambda cs, ids: forgotten.extend(ids))
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")

    funds.cmd_sweep(_SweepCS({"status": 1, "tx_hash": "0xhash"}), None)

    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert out["positions"] == {"7": 500}
    assert forgotten == [7]


def test_sweep_warns_after_sweeping_visible_pending_token(
    monkeypatch, capsys, tmp_path
) -> None:
    """A swept balance cannot suppress another unresolved buy submission."""
    cs = _SweepCS({"status": 1, "tx_hash": "0xhash"})
    cs.workspace = tmp_path
    pm.save_state(
        cs,
        {"dw_open_tokens": [7], "dw_pending_buy_counts": {"7": 1}},
    )
    monkeypatch.setattr(funds, "_abort_if_open_orders", lambda signer, dw: None)
    monkeypatch.setattr(funds, "dw_or_exit", lambda signer: DW_ADDR)
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, tok, dw: 0)
    monkeypatch.setattr(pm, "erc1155_balance_of", lambda w3, ctf, dw, tid: 500)
    monkeypatch.setattr(funds, "_dw_position_token_ids", lambda dw: [])
    monkeypatch.setattr(pm, "dw_nonce", lambda w3, dw: 1)
    monkeypatch.setattr(funds, "RelayerProxyClient", _FakeRelayer)
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")

    funds.cmd_sweep(cs, None)

    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert out["positions"] == {"7": 500}
    assert pm.dw_pending_buy_tokens(cs) == [7]
    assert "unresolved buy" in out["warning"]
    assert "was swept" in out["warning"]
    assert "7" in out["warning"]


def test_sweep_reports_confirmed_result_when_hint_cleanup_fails(
    monkeypatch, capsys
) -> None:
    """A post-confirmation state-write failure cannot hide the on-chain result."""
    _sweep_mocks(
        monkeypatch,
        pusd=0,
        ctf_balance=500,
        recorded=[7],
        indexed=[],
        pending=[7],
    )

    def fail_cleanup(cs, token_ids):
        raise OSError("disk full")

    monkeypatch.setattr(pm, "forget_dw_tokens", fail_cleanup)
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")

    funds.cmd_sweep(_SweepCS({"status": 1, "tx_hash": "0xhash"}), None)

    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert out["tx_hash"] == "0xhash"
    assert out["onchain_status"] == 1
    assert "state bookkeeping" in out["warning"]


def test_sweep_falls_back_when_pending_state_reload_fails(monkeypatch, capsys) -> None:
    """A post-confirmation state-read failure uses the pre-sweep snapshot."""
    _sweep_mocks(
        monkeypatch,
        pusd=0,
        ctf_balance=500,
        recorded=[7],
        indexed=[],
        pending=[7],
    )
    reads = iter(([7], SystemExit("corrupt state")))

    def read_pending(cs):
        result = next(reads)
        if isinstance(result, BaseException):
            raise result
        return result

    monkeypatch.setattr(pm, "dw_pending_buy_tokens", read_pending)
    monkeypatch.setattr(pm, "forget_dw_tokens", lambda cs, token_ids: None)
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")

    funds.cmd_sweep(_SweepCS({"status": 1, "tx_hash": "0xhash"}), None)

    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert out["tx_hash"] == "0xhash"
    assert out["onchain_status"] == 1
    assert "unresolved buy" in out["warning"]
    assert "pre-sweep pending state" in out["warning"]


def test_sweep_raises_when_not_confirmed_onchain(monkeypatch) -> None:
    """Relayer 'mined' but a status-0 receipt must fail loud (funds not moved)."""
    _sweep_mocks(monkeypatch, pusd=1_000_000, ctf_balance=0, recorded=[], indexed=[])
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")
    with pytest.raises(SystemExit):
        funds.cmd_sweep(_SweepCS({"status": 0, "tx_hash": "0xhash"}), None)


def test_sweep_warns_when_ambiguous_buy_has_not_settled(monkeypatch, capsys) -> None:
    """Moving residual pUSD must disclose a still-unresolved buy intent."""
    _sweep_mocks(
        monkeypatch,
        pusd=1_000_000,
        ctf_balance=0,
        recorded=[7],
        indexed=[],
        pending=[7],
    )
    _FakeRelayer.result = (True, "STATE_MINED", "0xhash")

    funds.cmd_sweep(_SweepCS({"status": 1, "tx_hash": "0xhash"}), None)

    out = json.loads(capsys.readouterr().out)
    assert out["swept"] is True
    assert "unresolved buy" in out["warning"]
    assert "7" in out["warning"]


# --- redeem.cmd_all: attempt all, fail loud if any failed (I1) -------------------


def test_redeem_all_raises_if_any_failed(monkeypatch, capsys) -> None:
    """One reverted redemption in a batch makes the command exit non-zero."""
    positions = [
        {"conditionId": "0x" + "11" * 32, "outcomeIndex": 0, "negativeRisk": False},
        {"conditionId": "0x" + "22" * 32, "outcomeIndex": 1, "negativeRisk": True},
    ]
    results = iter([{"status": 1}, {"status": 0}])
    monkeypatch.setattr(redeem, "_redeemable", lambda cs: positions)
    monkeypatch.setattr(redeem, "_ensure_adapter_approvals", lambda cs: [])
    monkeypatch.setattr(redeem, "_redeem_one", lambda cs, cid, idx, nr: next(results))
    with pytest.raises(SystemExit):
        redeem.cmd_all(object())
    assert json.loads(capsys.readouterr().out)["failed"] == 1


def test_redeem_all_success(monkeypatch, capsys) -> None:
    """All-confirmed redemptions exit cleanly."""
    positions = [
        {"conditionId": "0x" + "11" * 32, "outcomeIndex": 0, "negativeRisk": False}
    ]
    monkeypatch.setattr(redeem, "_redeemable", lambda cs: positions)
    monkeypatch.setattr(redeem, "_ensure_adapter_approvals", lambda cs: [])
    monkeypatch.setattr(redeem, "_redeem_one", lambda cs, cid, idx, nr: {"status": 1})
    redeem.cmd_all(object())
    assert json.loads(capsys.readouterr().out)["failed"] == 0


def test_redeemable_fetches_every_page(monkeypatch) -> None:
    """Redeemable discovery follows the cursor until the API stops paging."""
    monkeypatch.setattr(redeem, "POSITIONS_PAGE_LIMIT", 2)
    settled = {"redeemable": True}
    fake_get, seen = _paged(
        {
            None: _v2_page(
                [{"conditionId": "0x1", **settled}, {"conditionId": "0x2", **settled}],
                "c2",
            ),
            "c2": _v2_page([{"conditionId": "0x3", **settled}]),
        }
    )
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    assert [p["conditionId"] for p in redeem._redeemable(_SweepCS({}))] == [
        "0x1",
        "0x2",
        "0x3",
    ]
    assert [params.get("cursor") for params in seen] == [None, "c2"]
    assert all(params["status"] == "REDEEMABLE" for params in seen)


def test_redeemable_fails_on_a_repeated_cursor(monkeypatch) -> None:
    """A cursor the API already served stops the read instead of looping."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _v2_page([{"conditionId": "0x1"}], "same"),
    )

    with pytest.raises(SystemExit, match="repeated a pagination cursor"):
        redeem._redeemable(_SweepCS({}))


def test_positions_command_fetches_every_page(monkeypatch, capsys) -> None:
    """Portfolio reporting pages through instead of showing only page one."""
    monkeypatch.setattr(positions, "POSITIONS_PAGE_LIMIT", 2)
    fake_get, seen = _paged(
        {
            None: _v2_page([{"asset": "11"}, {"asset": "12"}], "c2"),
            "c2": _v2_page([{"asset": "13"}]),
        }
    )
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    positions.cmd_positions(_SweepCS({}), "safe", False, None, False)

    reported = json.loads(capsys.readouterr().out)
    assert [p["token_id"] for p in reported["positions"]] == ["11", "12", "13"]
    assert [params.get("cursor") for params in seen] == [None, "c2"]


@pytest.mark.parametrize("payload", [None, {"positions": []}, [{"asset": "12"}]])
def test_positions_command_rejects_malformed_page(monkeypatch, payload) -> None:
    """A malformed portfolio page must not read as an empty portfolio."""
    pages = iter((_v2_page([{"asset": "11"}], "c2"), payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="malformed data"):
        positions.cmd_positions(_SweepCS({}), "safe", False)


# --- positions: the indexer lags the chain (OPE-1862 #5) ------------------------


class _ChainCS:
    """A signer whose CTF reads are scripted and whose state is on disk."""

    safe_address = SAFE_ADDR
    w3 = object()

    def __init__(self, workspace) -> None:
        self.workspace = workspace


DW_HELD = to_checksum_address("0x" + "dd" * 20)


def _positions_mocks(monkeypatch, *, indexed, chain_balances, dw=DW_HELD):
    """Mock the indexer and the chain.

    `chain_balances` is keyed by (owner, token_id): a balance belongs to ONE
    wallet, and a mock that ignored the owner would pass whichever address the
    code read — which is how a safe/DW mix-up stayed invisible.
    """
    monkeypatch.setattr(
        pm, "http_get_json", lambda url, params=None: _v2_page(list(indexed))
    )
    monkeypatch.setattr(positions, "_resolve_dw", lambda cs: dw)
    monkeypatch.setattr(
        pm,
        "erc1155_balance_of",
        lambda w3, token, owner, token_id: chain_balances.get((owner, token_id), 0),
    )


def test_positions_confirms_a_fill_the_indexer_has_not_caught_up_to(
    monkeypatch, capsys, tmp_path
) -> None:
    """The reported failure: [] right after a confirmed fill.

    The position was on-chain the whole time; only the indexer was behind.
    An empty list reads as "the buy did not fill".
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    # the hint says the DW holds it — that is where a just-filled buy lands,
    # and the safe holds nothing until a sweep runs
    _positions_mocks(
        monkeypatch, indexed=[], chain_balances={(DW_HELD, 77): 12_500_000}
    )

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert out["positions"] == []
    assert out["onchain_check"]["held"] == [
        {
            "token_id": "77",  # nosec B105
            "address": DW_HELD,
            "location": "deposit_wallet",
            "size": 12.5,
            "size_base_units": 12_500_000,
        }
    ]
    assert [a["address"] for a in out["onchain_check"]["addresses"]] == [
        SAFE_ADDR,
        DW_HELD,
    ]
    assert out["onchain_check"]["held"][0]["address"] == DW_HELD
    assert "held in another wallet" in out["warning"]  # not lag: it is in the DW
    assert "funds.py sweep" in out["warning"]
    # the lag note is for a genuinely empty portfolio, not this one
    assert "note" not in out


def test_recorded_hints_are_checked_at_the_deposit_wallet_not_the_safe(
    monkeypatch, capsys, tmp_path
) -> None:
    """The hints describe the DW, so reading the safe finds nothing.

    A hint exists only while the position is unswept, i.e. at the DW.
    Confirming it against the default `--wallet safe` reads the wrong
    contract, always finds zero, and the fresh fill looks like it never
    happened.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    # ONLY the DW holds it; the safe's balance for the same token is zero
    _positions_mocks(monkeypatch, indexed=[], chain_balances={(DW_HELD, 77): 5_000_000})

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert [h["token_id"] for h in out["onchain_check"]["held"]] == ["77"]
    assert out["address"] == SAFE_ADDR  # the portfolio asked about
    assert out["onchain_check"]["held"][0]["address"] == DW_HELD  # found there


def test_onchain_check_is_present_whenever_verification_ran(
    monkeypatch, capsys, tmp_path
) -> None:
    """Absence must mean --no-onchain and nothing else.

    Otherwise "verified, found nothing" and "never verified" are the same JSON.
    """
    _positions_mocks(monkeypatch, indexed=[{"asset": "77"}], chain_balances={})

    positions.cmd_positions(_ChainCS(tmp_path), "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert out["onchain_check"] == {
        "addresses": [
            {"address": SAFE_ADDR, "location": "service_safe"},
            {"address": DW_HELD, "location": "deposit_wallet"},
        ],
        "checked_token_ids": [],
        "held": [],
    }


def test_positions_says_empty_may_only_mean_unindexed(
    monkeypatch, capsys, tmp_path
) -> None:
    """Nothing anywhere still has to disclose that the source lags."""
    _positions_mocks(monkeypatch, indexed=[], chain_balances={})

    positions.cmd_positions(_ChainCS(tmp_path), "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert out["positions"] == []
    assert "lags the chain" in out["note"]
    assert out["source"] == "data-api (indexer)"


def test_a_repeat_buy_is_confirmed_even_though_the_indexer_lists_the_token(
    monkeypatch, capsys, tmp_path
) -> None:
    """Buying more of a position you already hold must still be confirmed.

    A second buy re-records the hint while the indexer still shows the OLD
    size, so skipping already-reported tokens drops exactly the fresh
    quantity — and silently no-ops an explicit --token-ids.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)  # bought again; indexer still shows the old size
    _positions_mocks(
        monkeypatch,
        indexed=[{"asset": "77", "size": 3}],
        chain_balances={(DW_HELD, 77): 9_000_000},
    )

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert out["onchain_check"]["checked_token_ids"] == ["77"]
    assert out["onchain_check"]["held"][0]["size"] == 9.0
    assert out["onchain_check"]["held"][0]["location"] == "deposit_wallet"
    # the indexer listed this token, but at the pre-buy size — a caller gating
    # on `warning` must still be told its 3.0 is stale against the chain's 9.0
    assert "held in another wallet" in out["warning"]


def test_no_warning_when_the_indexer_and_the_chain_agree(
    monkeypatch, capsys, tmp_path
) -> None:
    """A matching size is not a discrepancy — don't cry wolf."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(
        monkeypatch,
        indexed=[{"asset": "77", "size": 4.0}],
        chain_balances={(SAFE_ADDR, 77): 4_000_000},
    )

    positions.cmd_positions(cs, "safe", False)

    assert "warning" not in json.loads(capsys.readouterr().out)


def test_a_half_swept_position_is_one_holding_not_a_disagreement(
    monkeypatch, capsys, tmp_path
) -> None:
    """Balances split across both wallets sum before being compared."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(
        monkeypatch,
        indexed=[{"asset": "77", "size": 10.0}],
        chain_balances={(SAFE_ADDR, 77): 6_000_000, (DW_HELD, 77): 4_000_000},
    )

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert len(out["onchain_check"]["held"]) == 2  # both legs still reported
    assert "warning" not in out  # 6 + 4 == the indexer's 10


@pytest.mark.parametrize(
    ("chain_size", "indexer_size"),
    [
        # real values observed live: the indexer truncates size to 4 decimals
        # while the chain carries 6. An exact comparison called every healthy
        # position a disagreement — a warning that always fires is ignored.
        (411.435578, 411.4355),
        (358.836593, 358.8365),
        (342.138861, 342.1388),
    ],
)
def test_indexer_rounding_is_not_a_disagreement(chain_size, indexer_size) -> None:
    """Display precision must not read as the chain and indexer disagreeing."""
    assert (
        positions._indexer_disagrees(
            [{"token_id": "77", "size": indexer_size}],  # nosec B105
            [{"token_id": "77", "size": chain_size}],  # nosec B105
            ["77"],
        )
        == set()
    )


def test_a_real_size_change_still_disagrees() -> None:
    """The tolerance must not grow big enough to swallow an actual top-up."""
    assert positions._indexer_disagrees(
        [{"token_id": "77", "size": 3.0}],  # nosec B105
        [{"token_id": "77", "size": 9.0}],  # nosec B105
        ["77"],
    ) == {"77"}


@pytest.mark.parametrize("bad_size", [float("nan"), float("inf"), "nan", None])
def test_an_unusable_indexer_size_counts_as_a_disagreement(bad_size) -> None:
    """A size that is not a usable number must not read as agreement.

    NaN survives `float()` and `json.loads`, and every comparison against it
    is False — so the check would silently pass on it.
    """
    held = [{"token_id": "77", "size": 9.0}]  # nosec B105
    assert positions._indexer_disagrees(
        [{"token_id": "77", "size": bad_size}], held, ["77"]  # nosec B105
    ) == {"77"}


def test_the_warning_names_the_cause_that_actually_applies(
    monkeypatch, capsys, tmp_path
) -> None:
    """Held-in-the-DW is not indexer lag, and must not be reported as it.

    The default read asks the indexer about the safe, but an unswept buy is in
    the DW — so the indexer is correct about the address it was asked about.
    Calling that "the API has not caught up" states a false thing as fact,
    which is the failure this whole command exists to remove.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(monkeypatch, indexed=[], chain_balances={(DW_HELD, 77): 5_000_000})

    positions.cmd_positions(cs, "safe", False)

    warning = json.loads(capsys.readouterr().out)["warning"]
    assert "held in another wallet (deposit_wallet)" in warning
    assert "not lag" in warning
    assert "funds.py sweep" in warning  # the hint fits this direction
    assert "has not caught up" not in warning  # the false cause is gone


def test_an_already_swept_position_is_not_told_to_sweep(
    monkeypatch, capsys, tmp_path
) -> None:
    """The mirror: queried the DW, found it in the safe — already swept.

    The sweep hint only fits the unswept direction, and a trailing clause that
    assumes a direction is the same false-cause bug one level down.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(
        monkeypatch, indexed=[], chain_balances={(SAFE_ADDR, 77): 5_000_000}
    )
    monkeypatch.setattr(positions, "dw_or_exit", lambda cs: DW_HELD)

    positions.cmd_positions(cs, "dw", False)

    warning = json.loads(capsys.readouterr().out)["warning"]
    assert "held in another wallet (service_safe)" in warning
    assert "funds.py sweep" not in warning  # it is already swept


def test_a_genuine_lag_is_still_called_lag(monkeypatch, capsys, tmp_path) -> None:
    """When the requested wallet really does hold it, the indexer IS behind."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(
        monkeypatch, indexed=[], chain_balances={(SAFE_ADDR, 77): 5_000_000}
    )

    positions.cmd_positions(cs, "safe", False)

    warning = json.loads(capsys.readouterr().out)["warning"]
    assert "the indexer has not caught up on" in warning
    assert "another wallet" not in warning


def test_a_position_gone_on_chain_but_still_listed_is_flagged(
    monkeypatch, capsys, tmp_path
) -> None:
    """The post-sell mirror of the post-buy lag.

    After a sell or redeem the chain reads zero while the indexer still lists
    the position. Only hits survive `_onchain_holdings`, so that zero was
    already read and then dropped — leaving the agent free to try selling
    shares it no longer holds.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    _positions_mocks(
        monkeypatch,
        indexed=[{"asset": "77", "size": 5.0}],
        chain_balances={},  # sold: nothing left anywhere
    )

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert out["onchain_check"]["held"] == []
    assert "already gone on-chain" in out["warning"]


def test_a_token_nobody_checked_is_not_called_a_disagreement() -> None:
    """Unknown is not absent — only checked ids can be judged."""
    assert (
        positions._indexer_disagrees(
            [{"token_id": "99", "size": 5.0}],  # nosec B105
            [],
            [],  # never read on-chain
        )
        == set()
    )


def test_explicit_token_ids_are_never_filtered_by_the_indexer(
    monkeypatch, capsys, tmp_path
) -> None:
    """An explicit request is a question, and it must always be answered."""
    cs = _ChainCS(tmp_path)
    _positions_mocks(
        monkeypatch,
        indexed=[{"asset": "55", "size": 1}],
        chain_balances={(SAFE_ADDR, 55): 2_000_000},
    )

    positions.cmd_positions(cs, "safe", False, [55])

    out = json.loads(capsys.readouterr().out)
    assert out["onchain_check"]["checked_token_ids"] == ["55"]
    assert out["onchain_check"]["held"][0]["size"] == 2.0


def test_positions_explicit_token_ids_override_the_hints(
    monkeypatch, capsys, tmp_path
) -> None:
    """--token-ids is the escape hatch when the hints are gone (post-sweep)."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    # explicit ids are the caller's own question, so they follow --wallet
    _positions_mocks(
        monkeypatch, indexed=[], chain_balances={(SAFE_ADDR, 99): 1_000_000}
    )

    positions.cmd_positions(cs, "safe", False, [99])

    out = json.loads(capsys.readouterr().out)
    assert out["onchain_check"]["checked_token_ids"] == ["99"]
    assert out["onchain_check"]["held"][0]["address"] == SAFE_ADDR
    assert out["onchain_check"]["held"][0]["size"] == 1.0


def test_documented_recovery_command_finds_an_unswept_buy(
    monkeypatch, capsys, tmp_path
) -> None:
    """`positions.py positions --token-ids <id>` must work as documented.

    INDEXER_LAG_NOTE and SKILL.md send the caller here with no --wallet, but a
    fresh buy is unswept and --wallet defaults to the safe: reading only the
    safe returns held: [] and the caller may buy again with real funds.
    """
    cs = _ChainCS(tmp_path)
    _positions_mocks(monkeypatch, indexed=[], chain_balances={(DW_HELD, 42): 7_000_000})

    positions.cmd_positions(cs, "safe", False, [42])

    out = json.loads(capsys.readouterr().out)
    assert [h["token_id"] for h in out["onchain_check"]["held"]] == ["42"]
    assert out["onchain_check"]["held"][0]["address"] == DW_HELD
    assert "note" not in out  # never "may not be indexed yet" for a real hit


def test_an_rpc_failure_does_not_discard_the_portfolio(
    monkeypatch, capsys, tmp_path
) -> None:
    """The confirmation is advisory; a chain blip must not lose the read.

    `_resolve_dw` raises SystemExit to abort a DW *deployment*. Letting that
    escape a read-only query threw away positions already fetched.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _v2_page([{"asset": "55", "size": 2}]),
    )

    def boom(_cs):
        raise SystemExit("persisted DepositWallet has no readable owner()")

    monkeypatch.setattr(positions, "_resolve_dw", boom)

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert [p["token_id"] for p in out["positions"]] == ["55"]  # not discarded
    assert "could not confirm on-chain" in out["onchain_check"]["error"]
    assert "held" not in out["onchain_check"]  # never reads as "checked, none"


def test_a_failed_read_never_calls_a_token_gone(monkeypatch, capsys, tmp_path) -> None:
    """The error path must not contradict itself.

    With the token ALSO listed by the indexer, marking ids checked before the
    reads ran let the reverse direction report "already gone on-chain" in the
    same response whose onchain_check.error says nothing could be read.
    """
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _v2_page([{"asset": "77", "size": 5.0}]),
    )

    def boom(_cs):
        raise SystemExit("persisted DepositWallet has no readable owner()")

    monkeypatch.setattr(positions, "_resolve_dw", boom)

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert "could not confirm on-chain" in out["onchain_check"]["error"]
    assert "warning" not in out  # nothing was read, so nothing can be "gone"


def test_positions_no_onchain_flag_trusts_the_indexer(
    monkeypatch, capsys, tmp_path
) -> None:
    """--no-onchain must not silently still hit the chain."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    called = []
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page([]))
    monkeypatch.setattr(
        pm,
        "erc1155_balance_of",
        lambda *a: called.append(a) or 0,
    )

    positions.cmd_positions(cs, "safe", False, None, False)

    assert called == []
    assert "onchain_check" not in json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1,2", [1, 2]), ("1 2", [1, 2]), ("3", [3]), (None, []), ("", [])],
)
def test_parse_token_ids_accepts_commas_and_spaces(raw, expected) -> None:
    """Both separators an operator might reasonably type."""
    assert positions._parse_token_ids(raw) == expected


def test_parse_token_ids_rejects_junk() -> None:
    """A typo must fail loudly, not silently check nothing."""
    with pytest.raises(SystemExit, match="comma/space separated"):
        positions._parse_token_ids("77,abc")


def test_trades_discloses_the_same_lag(monkeypatch, capsys, tmp_path) -> None:
    """Trade history is indexed too, so an empty answer proves nothing."""
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page([]))

    positions.cmd_trades(_ChainCS(tmp_path), "safe", 10)

    out = json.loads(capsys.readouterr().out)
    assert out["trades"] == []
    assert "lags the chain" in out["note"]


@pytest.mark.parametrize("payload", [None, {"positions": []}, [{"conditionId": "0x2"}]])
def test_redeemable_rejects_malformed_page(monkeypatch, payload) -> None:
    """A malformed later page cannot masquerade as pagination completion."""
    pages = iter((_v2_page([{"conditionId": "0x1"}], "c2"), payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="malformed data"):
        redeem._redeemable(_SweepCS({}))


# --- markets.cmd_market: events-index fallback ----------------------------------


def test_market_events_fallback(monkeypatch, capsys) -> None:
    """When /markets is empty, the market is found via the /events index."""
    seen = []

    def fake_get(url, params=None):
        seen.append(url)
        if url.endswith("/markets"):
            return []
        return [
            {
                "markets": [
                    {
                        "question": "Q",
                        "slug": "s",
                        "conditionId": "0xc",
                        "clobTokenIds": '["1","2"]',
                        "outcomes": '["Yes","No"]',
                    }
                ]
            }
        ]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    # cmd_market now prices live by default; without this the test would make a
    # real POST to the CLOB — fine here, a 30s hang on an isolated CI runner.
    monkeypatch.setattr(pm, "clob_live_prices", lambda tokens: {})
    markets.cmd_market("s", None)
    out = json.loads(capsys.readouterr().out)
    assert out[0]["question"] == "Q"
    assert any(u.endswith("/events") for u in seen)


# --- deposit_wallet._deploy: owner-confirm retry, None-owner fatal (C2/A1) -------


class _DeployCS:
    agent_eoa = to_checksum_address("0x" + "9e" * 20)
    w3 = object()

    def __init__(self, tmp_path) -> None:
        self.workspace = tmp_path

    def wait_receipt(self, tx_hash, timeout=300):
        return {"status": 1, "tx_hash": tx_hash}


class _DeployProxy:
    def deploy_dw(self):
        return "deploy-tx"

    def wait_terminal(self, tx_id):
        return (True, "STATE_MINED", "0xhash")


def test_deploy_confirms_owner_after_lag(monkeypatch, tmp_path) -> None:
    """A None owner (indexing lag) is retried, then the matching owner persists."""
    cs = _DeployCS(tmp_path)
    monkeypatch.setattr(deposit_wallet, "OWNER_CONFIRM_BACKOFF", 0)
    monkeypatch.setattr(deposit_wallet, "extract_dw_from_receipt", lambda c, h: DW_ADDR)
    owners = iter([None, cs.agent_eoa])
    monkeypatch.setattr(pm, "contract_owner", lambda w3, a: next(owners))
    assert deposit_wallet._deploy(cs, _DeployProxy()) == DW_ADDR
    assert pm.load_state(cs)["deposit_wallet"]["address"] == DW_ADDR


def test_deploy_fatal_when_owner_never_reads(monkeypatch, tmp_path) -> None:
    """If the owner never reads back, the DW is NOT persisted (fatal)."""
    cs = _DeployCS(tmp_path)
    monkeypatch.setattr(deposit_wallet, "OWNER_CONFIRM_BACKOFF", 0)
    monkeypatch.setattr(deposit_wallet, "extract_dw_from_receipt", lambda c, h: DW_ADDR)
    monkeypatch.setattr(pm, "contract_owner", lambda w3, a: None)
    with pytest.raises(SystemExit):
        deposit_wallet._deploy(cs, _DeployProxy())
    assert pm.load_state(cs) == {}


# --- the published constants table ----------------------------------------------


def test_contracts_table_covers_every_address_constant_exactly_once() -> None:
    """A constant missing from the table is one the next reader mislabels.

    The declared set is read out of the module rather than restated here, so
    a new address constant fails this until it is named in the table — a
    hand-kept list would just be a third copy to forget.
    """
    tabled = {c.address for c in pm.CONTRACTS}
    declared = {
        value
        for name, value in vars(pm).items()
        if not name.startswith("_") and isinstance(value, str) and is_address(value)
    }
    assert tabled == declared
    names = [c.name for c in pm.CONTRACTS]
    assert len(names) == len(set(names)) == len(pm.CONTRACTS)
    assert all(c.role for c in pm.CONTRACTS)


def test_contract_label_names_the_two_that_were_confused() -> None:
    """The CTF and the collateral onramp are the pair that got swapped."""
    assert pm.contract_label(pm.CTF) == "CTF"
    assert pm.contract_label(pm.COLLATERAL_ONRAMP) == "CollateralOnramp"
    assert pm.contract_label(pm.CTF.lower()) == "CTF"  # however it is cased
    assert pm.contract_label(ADDR_A) == ADDR_A  # unknown: echoed, never guessed
    assert pm.labelled([pm.CTF, ADDR_A]) == {pm.CTF: "CTF", ADDR_A: ADDR_A}


def test_constants_report_publishes_the_addresses_and_hosts() -> None:
    """`python pm_common.py` must answer without a network or a signer."""
    report = pm.constants_report()
    assert report["chain"] == {"name": pm.CHAIN, "chain_id": pm.CHAIN_ID}
    assert [entry["address"] for entry in report["contracts"]] == [
        c.address for c in pm.CONTRACTS
    ]
    assert pm.CLOB_HOST in report["api_hosts"].values()
    # the approval set, named: the DW's three venues, not the two adapters,
    # and not the retired NegRiskAdapter
    approvals = report["dw_trading_approvals"]
    assert set(approvals["pusd_allowances"].values()) == {
        "CTFExchange",
        "NegRiskCTFExchange",
        "ExchangeV3",
    }
    named = {name for section in approvals.values() for name in section.values()}
    assert named == {"CTFExchange", "NegRiskCTFExchange", "ExchangeV3"}


def test_constants_report_describes_the_protocol_v2_contracts() -> None:
    """The published rows for the V2 venue, its positions and the retired adapter.

    These are the rows Protocol V2 adds or changes, and the roles are what
    tells them apart: two settle orders, one holds positions, one holds no
    approval any more.
    """
    rows = {entry["name"]: entry for entry in pm.constants_report()["contracts"]}
    assert rows["ExchangeV3"] == {
        "name": "ExchangeV3",
        "address": pm.EXCHANGE_V3,
        "role": "CLOB settlement for Protocol V2 markets",
    }
    assert rows["PositionManager"] == {
        "name": "PositionManager",
        "address": pm.POSITION_MANAGER,
        "role": "The ERC-1155 holding every Protocol V2 position",
    }
    assert rows["NegRiskAdapter"] == {
        "name": "NegRiskAdapter",
        "address": pm.NEG_RISK_ADAPTER,
        "role": (
            "Wraps neg-risk positions (CLOB v1, deprecated); "
            "no longer granted a DW approval"
        ),
    }
    assert pm.contract_label(pm.POSITION_MANAGER) == "PositionManager"
    assert pm.contract_label(pm.EXCHANGE_V3) == "ExchangeV3"


def test_status_prints_the_labels_beside_the_approvals(monkeypatch, capsys) -> None:
    """The one production caller: names must actually reach the printed report.

    ``approval_contracts`` being right is no use if ``status`` drops it, and
    the two maps are only readable together — a name in one, its flag in the
    other, under the same key.
    """
    monkeypatch.setattr(deposit_wallet, "_resolve_dw", lambda cs: DW_ADDR)
    monkeypatch.setattr(deposit_wallet, "RelayerProxyClient", lambda cs: _StubProxy())
    monkeypatch.setattr(pm, "contract_owner", lambda w3, a: _StubCS.agent_eoa)
    monkeypatch.setattr(pm, "_eth_call", lambda w3, to, data: bytes(32))
    deposit_wallet.cmd_status(_StubCS())

    report = json.loads(capsys.readouterr().out)
    assert report["approval_contracts"] == pm.approval_contracts()
    for section, names in report["approval_contracts"].items():
        assert names.keys() == report["approvals"][section].keys()


def test_approval_labels_are_keyed_like_the_approval_status(monkeypatch) -> None:
    """The names must land beside the flags they describe, at every level.

    ``deposit_wallet.py status`` prints both maps side by side; if their keys
    or addresses drifted apart the reader would match a name to the wrong
    flag — worse than no name at all.
    """
    monkeypatch.setattr(pm, "_eth_call", lambda w3, to, data: bytes(32))
    status = pm.approvals_status(None, ADDR_A)
    labels = pm.approval_contracts()
    assert labels.keys() == status.keys()
    assert all(labels[key].keys() == status[key].keys() for key in status)


# --- /wallet shape: one reader, and errors that are sure of their cause ----------


def _cs_with_info(info: dict):
    """Build a ConnectSigner with the /wallet response already cached."""
    cs = pm.ConnectSigner.__new__(pm.ConnectSigner)
    cs._info = info
    cs._w3 = None
    cs.chain = pm.CHAIN
    return cs


def _wallet_payload(**entry) -> dict:
    """Build the connect server's /wallet shape, one entry for Polygon."""
    return {
        "agent_eoa": ADDR_A,
        "actionable_chains": [pm.CHAIN] if entry.get("safe") else [],
        "chains": {pm.CHAIN: entry},
    }


def test_safe_address_reads_the_nested_chain_entry() -> None:
    """The safe comes from chains[polygon].safe, not a flat safes map."""
    cs = _cs_with_info(_wallet_payload(safe=SAFE_ADDR, rpc="https://rpc.example"))
    assert cs.safe_address == SAFE_ADDR


def test_w3_reads_the_rpc_from_the_nested_chain_entry() -> None:
    """The RPC comes from chains[polygon].rpc, not a flat rpcs map."""
    cs = _cs_with_info(_wallet_payload(safe=SAFE_ADDR, rpc="https://rpc.example"))
    assert cs.w3.provider.endpoint_uri == "https://rpc.example"


def test_deployed_chain_without_a_safe_blames_deployment_not_the_rpc() -> None:
    """A configured chain missing only its safe says so, precisely."""
    cs = _cs_with_info(_wallet_payload(safe=None, rpc="https://rpc.example"))
    with pytest.raises(pm.ConnectError, match="no service safe"):
        _ = cs.safe_address


def test_unconfigured_chain_names_the_chains_that_are() -> None:
    """An absent chain is reported as absent, and lists what is configured."""
    cs = _cs_with_info(
        {"agent_eoa": ADDR_A, "chains": {"gnosis": {"rpc": "https://g"}}}
    )
    with pytest.raises(pm.ConnectError) as excinfo:
        _ = cs.safe_address
    assert "not configured" in str(excinfo.value)
    assert "gnosis" in str(excinfo.value)


def test_chain_info_defaults_to_the_client_s_own_chain() -> None:
    """Called with no argument it reads self.chain, not a hardcoded default."""
    cs = _cs_with_info(_wallet_payload(safe=SAFE_ADDR, rpc="https://rpc.example"))
    assert cs.chain_info()["rpc"] == "https://rpc.example"


def test_unconfigured_chain_on_an_empty_deployment_says_none() -> None:
    """A server reporting no chains at all still gives a usable message."""
    cs = _cs_with_info({"agent_eoa": ADDR_A, "chains": {}})
    with pytest.raises(pm.ConnectError, match="configured: none"):
        _ = cs.safe_address


def test_unrecognised_wallet_payload_is_not_reported_as_missing_config() -> None:
    """The pre-#34 flat shape must read as client/server drift, not bad config.

    This is the exact failure the live QA run chased: a parsing fault that
    named operator configuration as the cause and sent the agent hunting a
    Polygon setup problem that did not exist.
    """
    cs = _cs_with_info({"agent_eoa": ADDR_A, "safes": {}, "rpcs": {}})
    with pytest.raises(pm.ConnectError) as excinfo:
        _ = cs.safe_address
    assert "out of step" in str(excinfo.value)
    assert "not configured" not in str(excinfo.value)


# --- balances: the USDC that was there all along -------------------------


class _BalancesW3:
    class eth:  # noqa: D106 - test double
        @staticmethod
        def get_balance(address):
            return 2 * 10**18

    @staticmethod
    def from_wei(value, unit):
        return value / 10**18


class _BalancesCS:
    safe_address = SAFE_ADDR
    agent_eoa = ADDR_A
    w3 = _BalancesW3()


def _only_usdc(w3, token, owner):
    """Report a safe holding USDC and nothing else the onramp accepts."""
    return 5_000_000 if token == pm.USDC else 0


def test_balances_report_usdc(monkeypatch, capsys) -> None:
    """USDC appears; omitting it read as "no USDC" and blocked a run."""
    monkeypatch.setattr(funds, "_resolve_dw", lambda cs: None)
    monkeypatch.setattr(pm, "erc20_balance_of", _only_usdc)
    funds.cmd_balances(_BalancesCS())
    safe = json.loads(capsys.readouterr().out)["safe"]
    assert safe["usdc"] == 5.0
    assert safe["usdc_e"] == 0.0
    assert safe["pusd"] == 0.0


def test_wrap_refusal_names_the_usdc_it_cannot_use(monkeypatch) -> None:
    """Name what the safe does hold, and why the onramp cannot use it."""
    monkeypatch.setattr(pm, "erc20_balance_of", _only_usdc)
    with pytest.raises(SystemExit) as excinfo:
        funds.cmd_wrap(_BalancesCS(), None)
    assert "5.0 USDC" in str(excinfo.value)
    assert "USDC.e" in str(excinfo.value)


def test_wrap_refusal_survives_an_rpc_failure_while_building_its_hint(
    monkeypatch,
) -> None:
    """A flaky RPC must not replace the real refusal with its own traceback.

    Only the hint's read is allowed to fail quietly: the USDC.e read is the
    actual operation, and its failure has to propagate.
    """

    def _hint_read_fails(w3, token, owner):
        if token == pm.USDC:
            raise ConnectionError("RPC unavailable")
        return 0

    monkeypatch.setattr(pm, "erc20_balance_of", _hint_read_fails)
    with pytest.raises(SystemExit) as excinfo:
        funds.cmd_wrap(_BalancesCS(), None)
    assert "nothing to wrap" in str(excinfo.value)
    assert "does hold" not in str(excinfo.value)


def test_wrap_propagates_a_failure_of_the_read_it_actually_needs(
    monkeypatch,
) -> None:
    """The USDC.e read is the operation, not a hint — it must not be swallowed."""

    def _boom(w3, token, owner):
        raise ConnectionError("RPC unavailable")

    monkeypatch.setattr(pm, "erc20_balance_of", _boom)
    with pytest.raises(ConnectionError):
        funds.cmd_wrap(_BalancesCS(), None)


def test_wrap_refusal_stays_quiet_when_there_is_no_usdc(monkeypatch) -> None:
    """An empty safe gets no misleading "but you do hold" clause."""
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: 0)
    with pytest.raises(SystemExit) as excinfo:
        funds.cmd_wrap(_BalancesCS(), None)
    # "USDC.e" is in the base message either way — what must be absent is the
    # hint clause, which would name a balance the safe does not have
    assert "does hold" not in str(excinfo.value)


# --- markets list: "resolves within N" ------------------------------------------

NOW = datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc)


def test_ends_within_bounds_start_now_and_span_the_window() -> None:
    """The window runs from now (never re-admitting ended markets) to now+N."""
    assert markets._ends_within_params(*markets._ends_within_bounds("48h", NOW)) == {
        "end_date_min": "2026-07-23T12:00:00Z",
        "end_date_max": "2026-07-25T12:00:00Z",
    }


@pytest.mark.parametrize("window", ["7d", "2w", "1h"])
def test_ends_within_accepts_hours_days_weeks(window) -> None:
    """Each supported unit parses and yields an ordered pair of bounds."""
    start, end = markets._ends_within_bounds(window, NOW)
    assert end > start


@pytest.mark.parametrize("window", ["0h", "0d", "00w"])
def test_ends_within_rejects_an_empty_window(window) -> None:
    """A zero-length window matches nothing; that must not read as "none"."""
    with pytest.raises(SystemExit, match="positive window"):
        markets._ends_within_bounds(window)


@pytest.mark.parametrize("window", ["7", "3mo", "", "-1d", "d7", "48 h"])
def test_ends_within_rejects_what_it_cannot_parse(window) -> None:
    """An unparseable window fails loudly rather than silently not filtering."""
    with pytest.raises(SystemExit, match="ends-within"):
        markets._ends_within_bounds(window)


@pytest.mark.parametrize(
    ("end_date", "inside"),
    [
        ("2026-07-24T12:00:00Z", True),
        ("2026-07-23T12:00:00Z", True),  # the lower bound itself
        ("2026-07-25T12:00:00Z", True),  # the upper bound itself
        ("2026-07-26T12:00:00Z", False),  # after the window
        ("2026-07-22T12:00:00Z", False),  # already ended
        ("2026-07-24T12:00:00.500Z", True),  # fractional seconds
        ("2026-07-24T12:00:00+00:00", True),  # explicit offset
        ("not-a-date", False),
        (None, False),
    ],
)
def test_ends_in_window_judges_each_market_by_its_own_end_date(
    end_date, inside
) -> None:
    """The local check must handle every endDate shape Gamma may return."""
    start, end = markets._ends_within_bounds("48h", NOW)
    assert markets._ends_in_window({"endDate": end_date}, start, end) is inside


def test_cmd_list_sends_the_end_date_bounds(monkeypatch, capsys) -> None:
    """--ends-within reaches Gamma as query params."""
    seen: dict = {}

    def fake_get(url, params=None):
        seen.update(params or {})
        return []

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_list(5, None, None, "48h")
    capsys.readouterr()
    assert "end_date_min" in seen
    assert "end_date_max" in seen


def test_cmd_list_drops_markets_gamma_should_have_filtered(monkeypatch, capsys) -> None:
    """The window holds even if Gamma ignored the parameters entirely.

    Gamma drops query parameters it does not recognise, so a server that never
    applied the filter returns a full unfiltered page. Reporting those as
    "resolves within N" would be a silent, invisible lie.
    """
    far_future = (datetime.now(timezone.utc) + timedelta(days=400)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    soon = (datetime.now(timezone.utc) + timedelta(hours=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [
            {"question": "resolves soon", "endDate": soon, "version": "v1"},
            {"question": "resolves next year", "endDate": far_future, "version": "v1"},
            {"question": "no end date at all", "version": "v1"},
        ],
    )
    markets.cmd_list(10, None, None, "48h")
    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["resolves soon"]


def test_main_wires_ends_within_through_the_parser(monkeypatch, capsys) -> None:
    """The CLI is the only way this runs in production, so parse it for real.

    cmd_list is tested directly above; that would not notice the flag being
    renamed or never forwarded, which would silently filter nothing.
    """
    seen: dict = {}

    def fake_get(url, params=None):
        seen.update(params or {})
        return []

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    monkeypatch.setattr(
        sys, "argv", ["markets.py", "list", "--limit", "3", "--ends-within", "48h"]
    )
    markets.main()
    capsys.readouterr()
    assert "end_date_min" in seen
    assert "end_date_max" in seen


def test_cmd_list_without_the_flag_sends_no_bounds(monkeypatch, capsys) -> None:
    """The filter is opt-in — an unfiltered list keeps its previous query."""
    seen: dict = {}

    def fake_get(url, params=None):
        seen.update(params or {})
        return []

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_list(5, None, None)
    capsys.readouterr()
    assert "end_date_min" not in seen


# --- live prices vs Gamma's cache (OPE-1862 #1) ---------------------------------


def test_clob_live_prices_names_each_side_for_what_it_is() -> None:
    """The CLOB's BUY side is the best *bid*; mislabelling it misprices trades.

    Verified against the raw book: side=BUY is max(bids), side=SELL is
    min(asks). A taker pays the ask.
    """
    captured = {}

    def fake_post(url, payload):
        captured["url"] = url
        captured["payload"] = payload
        return {"7": {"BUY": "0.85", "SELL": "0.86"}}

    original = pm.http_post_json
    try:
        pm.http_post_json = fake_post
        live = pm.clob_live_prices(["7"])
    finally:
        pm.http_post_json = original

    assert live == {"7": {"best_bid": 0.85, "best_ask": 0.86, "mid": 0.855}}
    assert captured["url"].endswith("/prices")
    assert captured["payload"] == [
        {"token_id": "7", "side": "BUY"},  # nosec B105
        {"token_id": "7", "side": "SELL"},  # nosec B105
    ]


def test_clob_live_prices_batches_and_dedupes(monkeypatch) -> None:
    """One call prices a whole listing; a repeated token is asked for once."""
    seen = {}

    def fake_post(url, payload):
        seen["payload"] = payload
        return {}

    monkeypatch.setattr(pm, "http_post_json", fake_post)
    pm.clob_live_prices(["7", "8", "7"])
    assert [entry["token_id"] for entry in seen["payload"]] == ["7", "7", "8", "8"]


def test_clob_live_prices_empty_input_makes_no_call(monkeypatch) -> None:
    """No tokens, no HTTP."""
    monkeypatch.setattr(
        pm,
        "http_post_json",
        lambda url, payload: pytest.fail("should not have called the CLOB"),
    )
    assert pm.clob_live_prices([]) == {}


def test_clob_live_prices_leaves_an_empty_side_as_none(monkeypatch) -> None:
    """A one-sided book must not fabricate a mid."""
    monkeypatch.setattr(
        pm, "http_post_json", lambda url, payload: {"7": {"BUY": "0.4", "SELL": ""}}
    )
    assert pm.clob_live_prices(["7"])["7"] == {
        "best_bid": 0.4,
        "best_ask": None,
        "mid": None,
    }


def test_clob_live_prices_rejects_a_non_object_payload(monkeypatch) -> None:
    """A malformed response must not read as "no prices"."""
    monkeypatch.setattr(pm, "http_post_json", lambda url, payload: ["nope"])
    with pytest.raises(ValueError, match="expected an object"):
        pm.clob_live_prices(["7"])


def test_slim_renames_gammas_cache_so_it_cannot_pass_as_live() -> None:
    """Gamma's outcomePrices was quoted as fact at 0.45 against a 0.24 book."""
    slim = markets._slim({"outcomePrices": '["0.45", "0.55"]'})
    assert slim["outcome_prices_indicative"] == ["0.45", "0.55"]
    assert "outcome_prices" not in slim


def test_attach_live_prices_keys_each_quote_by_outcome(monkeypatch) -> None:
    """The live book is reported per outcome name, next to the cache."""
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: {
            "1": {"best_bid": 0.24, "best_ask": 0.30, "mid": 0.27},
            "2": {"best_bid": 0.70, "best_ask": 0.76, "mid": 0.73},
        },
    )
    [slim] = markets._attach_live_prices(
        [markets._slim({"outcomes": '["Yes","No"]', "clobTokenIds": '["1","2"]'})]
    )
    assert slim["live_prices"]["Yes"]["mid"] == 0.27
    assert slim["live_prices"]["No"]["best_ask"] == 0.76


def test_attach_live_prices_reports_failure_instead_of_falling_back(
    monkeypatch,
) -> None:
    """An unchecked book must never look like a current one."""

    def boom(tokens):
        raise RuntimeError("clob down")

    monkeypatch.setattr(pm, "clob_live_prices", boom)
    [slim] = markets._attach_live_prices(
        [markets._slim({"outcomes": '["Yes","No"]', "clobTokenIds": '["1","2"]'})]
    )
    assert "live_prices" not in slim
    assert "clob down" in slim["live_prices_error"]
    assert "cached snapshot" in slim["live_prices_error"]


def test_a_market_with_no_tokens_still_gets_the_key(monkeypatch) -> None:
    """The never-neither guarantee must not depend on the rest of the batch.

    A market with no clobTokenIds would otherwise carry the key when listed
    beside tradeable ones and lack it when looked up alone.
    """
    monkeypatch.setattr(pm, "clob_live_prices", lambda tokens: {})
    [alone] = markets._attach_live_prices([markets._slim({"question": "no tokens"})])
    assert alone["live_prices"] is None

    beside = markets._attach_live_prices(
        [
            markets._slim({"question": "no tokens"}),
            markets._slim({"outcomes": '["Yes"]', "clobTokenIds": '["1"]'}),
        ]
    )
    assert beside[0]["live_prices"] is None


def test_no_live_skips_the_clob_entirely(monkeypatch) -> None:
    """--no-live is opt-out, and it really opts out."""
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: pytest.fail("should not have priced anything"),
    )
    [slim] = markets._attach_live_prices(
        [markets._slim({"clobTokenIds": '["1","2"]'})], live=False
    )
    assert "live_prices" not in slim


def test_cmd_price_labels_both_sides_and_takes_no_side_flag(
    monkeypatch, capsys
) -> None:
    """`price --side buy` used to return the best bid under a buyer's name."""
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: {"7": {"best_bid": 0.85, "best_ask": 0.86, "mid": 0.855}},
    )
    markets.cmd_price("7")
    out = json.loads(capsys.readouterr().out)
    assert out["7"]["best_ask"] == 0.86


def test_cmd_price_fails_loudly_when_the_clob_says_nothing(monkeypatch) -> None:
    """An unknown token is an error, not an empty object."""
    monkeypatch.setattr(pm, "clob_live_prices", lambda tokens: {})
    with pytest.raises(SystemExit, match="no prices"):
        markets.cmd_price("7")


# --- search: --query returned [] for markets that exist (OPE-1862 #2) -----------


def _search_payload(*events):
    """Wrap events as a public-search response; markets default to version v1."""
    for event in events:
        for market in event.get("markets") or []:
            market.setdefault("version", pm.SUPPORTED_MARKET_VERSION)
    return {"events": list(events)}


def test_query_searches_the_index_instead_of_scanning_a_page(
    monkeypatch, capsys
) -> None:
    """The reported failure: --query "largest company" returned [].

    /markets has no text parameter at all, so the old substring scan could
    only match inside the volume-ordered head.
    """
    calls = []

    def fake_get(url, params=None):
        calls.append((url, dict(params or {})))
        return _search_payload(
            {
                "markets": [
                    {
                        "question": "Will NVIDIA be the largest company?",
                        "volumeNum": 272080.0,
                    }
                ]
            }
        )

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_list(5, "largest company", None, None, False)

    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["Will NVIDIA be the largest company?"]
    url, params = calls[0]
    assert url.endswith("/public-search")
    assert params["q"] == "largest company"


def test_search_drops_resolved_markets(monkeypatch, capsys) -> None:
    """public-search returns closed markets even asked for active events."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _search_payload(
            {
                "markets": [
                    {"question": "open", "volumeNum": 1},
                    {"question": "resolved", "closed": True, "volumeNum": 999},
                    {"question": "inactive", "active": False, "volumeNum": 998},
                ]
            }
        ),
    )
    markets.cmd_list(5, "anything", None, None, False)
    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["open"]


def test_search_orders_by_volume_so_limit_keeps_the_biggest(
    monkeypatch, capsys
) -> None:
    """Relevance order would otherwise let --limit drop the liquid markets."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _search_payload(
            {
                "markets": [
                    {"question": "small", "volumeNum": 10},
                    {"question": "big", "volumeNum": 5000},
                    {"question": "unparseable volume", "volumeNum": "oops"},
                ]
            }
        ),
    )
    markets.cmd_list(2, "anything", None, None, False)
    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["big", "small"]


def test_search_can_still_be_narrowed_by_tag(monkeypatch, capsys) -> None:
    """--tag filters on the event's tags, since search is event-shaped."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _search_payload(
            {"tags": [{"slug": "tech"}], "markets": [{"question": "kept"}]},
            {"tags": [{"slug": "sports"}], "markets": [{"question": "dropped"}]},
            {"markets": [{"question": "untagged"}]},
        ),
    )
    markets.cmd_list(5, "anything", "tech", None, False)
    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["kept"]


def test_search_survives_a_shapeless_response(monkeypatch, capsys) -> None:
    """A payload without events is no results, not a crash."""
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: [])
    markets.cmd_list(5, "anything", None, None, False)
    assert json.loads(capsys.readouterr().out) == []


def test_query_and_ends_within_compose(monkeypatch, capsys) -> None:
    """A searched market still has to resolve inside the window."""
    soon = (datetime.now(timezone.utc) + timedelta(hours=5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    later = (datetime.now(timezone.utc) + timedelta(days=40)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: _search_payload(
            {
                "markets": [
                    {"question": "soon", "endDate": soon},
                    {"question": "later", "endDate": later},
                ]
            }
        ),
    )
    markets.cmd_list(5, "anything", None, "48h", False)
    out = json.loads(capsys.readouterr().out)
    assert [m["question"] for m in out] == ["soon"]


# --- group: neg-risk siblings (OPE-1862 #3) ------------------------------------


def _group_event(*markets_):
    return {
        "title": "Largest Company end of August?",
        "slug": "largest-company",
        "negRisk": True,
        "markets": list(markets_),
    }


def test_group_lists_siblings_and_sums_their_first_outcome(monkeypatch, capsys) -> None:
    """The sum is the sanity check that was previously found by accident."""

    def fake_get(url, params=None):
        if url.endswith("/markets"):
            return [{"slug": "apple", "events": [{"slug": "largest-company"}]}]
        return [
            _group_event(
                {
                    "question": "Apple?",
                    "groupItemTitle": "Apple",
                    "outcomes": '["Yes","No"]',
                    "clobTokenIds": '["1","2"]',
                },
                {
                    "question": "Alphabet?",
                    "groupItemTitle": "Alphabet",
                    "outcomes": '["Yes","No"]',
                    "clobTokenIds": '["3","4"]',
                },
            )
        ]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: {
            "1": {"best_bid": 0.55, "best_ask": 0.57, "mid": 0.56},
            "3": {"best_bid": 0.41, "best_ask": 0.43, "mid": 0.42},
        },
    )

    markets.cmd_group("apple", None, None)

    out = json.loads(capsys.readouterr().out)
    assert [s["group_item_title"] for s in out["siblings"]] == ["Apple", "Alphabet"]
    assert out["first_outcome_price_sum"] == 0.98
    assert out["priced_markets"] == 2
    assert out["neg_risk"] is True


def test_group_sums_live_prices_not_the_stale_cache(monkeypatch, capsys) -> None:
    """Summing cached prices would give a confident number that means nothing."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: (
            [{"events": [{"slug": "e"}]}]
            if url.endswith("/markets")
            else [
                _group_event(
                    {
                        "outcomes": '["Yes","No"]',
                        "outcomePrices": '["0.45","0.55"]',
                        "clobTokenIds": '["1","2"]',
                    }
                )
            ]
        ),
    )
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: {"1": {"best_bid": 0.24, "best_ask": 0.30, "mid": 0.27}},
    )

    markets.cmd_group("s", None, None)

    assert json.loads(capsys.readouterr().out)["first_outcome_price_sum"] == 0.27


def test_group_falls_back_to_the_cache_only_when_live_is_off(
    monkeypatch, capsys
) -> None:
    """With --no-live there is nothing but the cache, so say the sum anyway."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: (
            [{"events": [{"slug": "e"}]}]
            if url.endswith("/markets")
            else [
                _group_event(
                    {"outcomes": '["Yes","No"]', "outcomePrices": '["0.45","0.55"]'}
                )
            ]
        ),
    )
    markets.cmd_group("s", None, None, False)
    assert json.loads(capsys.readouterr().out)["first_outcome_price_sum"] == 0.45


def test_group_accepts_the_event_slug_directly(monkeypatch, capsys) -> None:
    """--event-slug skips the market lookup entirely."""
    calls = []

    def fake_get(url, params=None):
        calls.append(url)
        return [_group_event({"question": "Apple?"})]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_group(None, None, "largest-company", False)
    assert all(url.endswith("/events") for url in calls)
    assert json.loads(capsys.readouterr().out)["markets"] == 1


def test_group_says_so_when_a_market_belongs_to_no_group(monkeypatch) -> None:
    """A standalone market has no siblings; invent none."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        # /markets finds the market, /events knows no such event
        lambda url, params=None: (
            [{"slug": "solo", "events": []}] if url.endswith("/markets") else []
        ),
    )
    with pytest.raises(SystemExit, match="not part of a market group"):
        markets.cmd_group("solo", None, None, False)


def test_group_resolves_a_slug_the_events_index_served(monkeypatch, capsys) -> None:
    """The recurring series /markets doesn't serve must still reach its group.

    Their markets come from the /events fallback and carry no `events` key, so
    keying only on that made `group` impossible for them — even though the
    fallback had already proved the slug names an event.
    """
    calls = []

    def fake_get(url, params=None):
        calls.append(url)
        if url.endswith("/markets"):
            return []  # not served here — the documented fallback case
        return [_group_event({"question": "Apple?"})]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_group("btc-updown-5m-1234567890", None, None, False)

    assert json.loads(capsys.readouterr().out)["markets"] == 1


def test_group_reports_an_unknown_event_slug(monkeypatch) -> None:
    """An empty events index is an error, not an empty group."""
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: [])
    with pytest.raises(SystemExit, match="no event found"):
        markets.cmd_group(None, None, "nope", False)


def test_main_wires_group_and_no_live(monkeypatch, capsys) -> None:
    """The CLI is the only way this runs in production, so parse it for real."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [_group_event({"question": "Apple?"})],
    )
    monkeypatch.setattr(
        pm,
        "clob_live_prices",
        lambda tokens: pytest.fail("--no-live must reach cmd_group"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["markets.py", "group", "--event-slug", "largest-company", "--no-live"],
    )
    markets.main()
    assert json.loads(capsys.readouterr().out)["markets"] == 1


# --- quote: the buy math, before the buy (OPE-1862 #4) --------------------------


class _QuoteClient:
    """The two SDK sizing calls quote_buy leans on, with a flat 3% taker fee."""

    def __init__(self, price=0.5, fee_rate=0.03) -> None:
        self.price = price
        self.fee_rate = fee_rate

    def calculate_market_price(self, token_id, side, amount, order_type):
        return self.price

    def _adjust_buy_amount_for_balance(self, token_id, amount, price, balance, _):
        # mirrors py_clob_client_v2 fees.py: the fee is charged on
        # min(amount, balance) and SUBTRACTED from the balance
        fee = self.fee_rate * min(amount, balance)
        return min(amount, max(balance - fee, 0.0))


def test_quote_surfaces_price_fee_shares_and_topup() -> None:
    """The numbers existed only inside the buy preflight's error message."""
    quote = pm.quote_buy(_QuoteClient(), "7", 10.0, 100.0, "FOK")

    assert quote["fill_price"] == 0.5
    assert quote["estimated_shares"] == 20.0
    assert quote["estimated_fee_usd"] == pytest.approx(0.30, abs=1e-6)
    assert quote["required_dw_balance_usd"] == pytest.approx(10.30, abs=1e-6)
    assert quote["shortfall_usd"] == 0.0
    assert quote["blocked"] is False


def test_quote_names_the_exact_topup_when_the_balance_is_short() -> None:
    """shortfall_usd goes straight to `funds.py top-up --amount`."""
    quote = pm.quote_buy(_QuoteClient(), "7", 10.0, 4.0, "FOK")
    assert quote["dw_balance_usd"] == 4.0
    assert quote["shortfall_usd"] == pytest.approx(6.30, abs=1e-6)


def test_quote_flags_the_dollar_minimum_that_breaks_small_bets() -> None:
    """A $1 bet on a $1 balance is fee-shrunk under the CLOB's minimum."""
    quote = pm.quote_buy(_QuoteClient(), "7", 1.0, 1.0, "FOK")
    assert quote["spendable_now_usd"] < 1.0
    assert quote["blocked"] is True
    assert quote["shortfall_usd"] > 0


def test_a_bet_under_the_minimum_is_blocked_even_with_a_fat_balance() -> None:
    """A $0.50 order is affordable in full and still bounced by the venue.

    Comparing only the fee-shrunk figure to the minimum called this "fine":
    affordable == usd, so the old `affordable < usd` guard was false and the
    quote published a verdict the CLOB would reject.
    """
    quote = pm.quote_buy(_QuoteClient(), "7", 0.50, 100.0, "FOK")

    assert quote["shortfall_usd"] == 0.0  # money is not the problem
    assert quote["blocked"] is True
    assert "raise it" in quote["blocked_reason"]
    assert "more pUSD will not help" in quote["blocked_reason"]


def test_a_fee_shrunk_bet_is_told_to_add_funds_not_to_raise_the_bet() -> None:
    """The two block causes need opposite fixes, so they must read differently."""
    quote = pm.quote_buy(_QuoteClient(), "7", 1.0, 1.0, "FOK")

    assert quote["blocked"] is True
    assert "can be funded once the taker fee is held back" in quote["blocked_reason"]
    assert f"{quote['shortfall_usd']:.4f}" in quote["blocked_reason"]


def test_a_healthy_quote_has_no_blocked_reason() -> None:
    """`blocked_reason` is None exactly when the order would go through."""
    quote = pm.quote_buy(_QuoteClient(), "7", 10.0, 100.0, "FOK")
    assert quote["blocked"] is False
    assert quote["blocked_reason"] is None


def test_quote_works_against_an_empty_deposit_wallet() -> None:
    """How much do I need? is the question an empty DW most needs answered."""
    quote = pm.quote_buy(_QuoteClient(), "7", 10.0, 0.0, "FOK")
    assert quote["spendable_now_usd"] == 0.0
    assert quote["shortfall_usd"] == quote["required_dw_balance_usd"]


def test_quote_does_not_divide_by_a_zero_price() -> None:
    """An empty book must not turn a quote into a ZeroDivisionError."""
    quote = pm.quote_buy(_QuoteClient(price=0), "7", 10.0, 50.0, "FOK")
    assert quote["estimated_shares"] is None


# --- netcheck: the DNS heuristic was inverted (OPE-1862 #7) ---------------------


def _netcheck_hosts(monkeypatch, *, addresses, probe):
    monkeypatch.setattr(
        netcheck, "_resolve", lambda host: {"addresses": list(addresses), "error": None}
    )
    monkeypatch.setattr(netcheck, "_probe", lambda host: dict(probe))


def test_identical_cloudflare_addresses_are_healthy(monkeypatch) -> None:
    """The reported false positive, inverted.

    All three hosts share one Cloudflare address on a healthy machine; the old
    check called exactly that "the ISP is intercepting your DNS".
    """
    _netcheck_hosts(
        monkeypatch,
        addresses=["172.64.153.51"],
        probe={"state": "reachable", "status_code": 200},
    )
    report = netcheck.check()

    assert report["ok"] is True
    assert "NOT evidence of DNS interception" in report["shared_addresses_note"]
    assert "Cloudflare" in report["shared_addresses_note"]


def test_a_403_still_counts_as_reachable(monkeypatch) -> None:
    """Geoblocking is the venue's policy, not a broken network."""
    _netcheck_hosts(
        monkeypatch,
        addresses=["172.64.153.51"],
        probe={"state": "reachable", "status_code": 403},
    )
    assert netcheck.check()["ok"] is True


def test_tls_failure_points_at_the_ca_bundle_first(monkeypatch) -> None:
    """A trust-store gap is far likelier than interception, and it's fixable."""
    _netcheck_hosts(
        monkeypatch,
        addresses=["172.64.153.51"],
        probe={"state": "tls_failed", "detail": "CERTIFICATE_VERIFY_FAILED"},
    )
    report = netcheck.check()

    assert report["ok"] is False
    assert "bootstrap_env.sh" in report["next_step"]


def test_unresolvable_hosts_are_reported_as_dns(monkeypatch) -> None:
    """A real DNS failure still has to be named."""
    monkeypatch.setattr(
        netcheck,
        "_resolve",
        lambda host: {"addresses": [], "error": "gaierror: nope"},
    )
    monkeypatch.setattr(
        netcheck, "_probe", lambda host: {"state": "unreachable", "detail": "no"}
    )
    report = netcheck.check()

    assert report["ok"] is False
    assert "do not resolve" in report["conclusion"]


def test_resolving_but_unreachable_is_a_block(monkeypatch) -> None:
    """Resolution working while connections die is the blocking signature."""
    _netcheck_hosts(
        monkeypatch,
        addresses=["172.64.153.51"],
        probe={"state": "timeout", "detail": "timed out"},
    )
    report = netcheck.check()

    assert report["ok"] is False
    assert "blocking traffic" in report["conclusion"]


def test_distinct_addresses_get_no_shared_note(monkeypatch) -> None:
    """Nothing shared, nothing to explain."""
    counter = iter(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    monkeypatch.setattr(
        netcheck, "_resolve", lambda host: {"addresses": [next(counter)], "error": None}
    )
    monkeypatch.setattr(
        netcheck, "_probe", lambda host: {"state": "reachable", "status_code": 200}
    )
    assert "shared_addresses_note" not in netcheck.check()


def test_a_shared_non_cloudflare_address_is_still_not_a_verdict(
    monkeypatch,
) -> None:
    """Any CDN can front several hosts; that is not evidence of hijacking."""
    _netcheck_hosts(
        monkeypatch,
        addresses=["203.0.113.7"],
        probe={"state": "reachable", "status_code": 200},
    )
    note = netcheck.check()["shared_addresses_note"]
    assert "single CDN" in note
    assert "NOT evidence of DNS interception" in note


@pytest.mark.parametrize(
    ("exc", "state"),
    [
        (netcheck.requests.exceptions.SSLError("bad cert"), "tls_failed"),
        (netcheck.requests.exceptions.ConnectTimeout("slow"), "timeout"),
        (netcheck.requests.exceptions.ConnectionError("refused"), "unreachable"),
        (netcheck.requests.exceptions.TooManyRedirects("loop"), "error"),
    ],
)
def test_probe_names_the_layer_that_failed(monkeypatch, exc, state) -> None:
    """Each failure mode maps to a distinct, actionable state."""

    def boom(url, timeout=None):
        raise exc

    monkeypatch.setattr(netcheck.requests, "get", boom)
    assert netcheck._probe("clob.polymarket.com")["state"] == state


def test_probe_reports_the_status_code_on_success(monkeypatch) -> None:
    """A completed request is the whole point of the check."""

    class _Response:
        status_code = 200

    monkeypatch.setattr(netcheck.requests, "get", lambda url, timeout=None: _Response())
    assert netcheck._probe("clob.polymarket.com") == {
        "state": "reachable",
        "status_code": 200,
    }


def test_resolve_returns_every_address(monkeypatch) -> None:
    """Both A and AAAA records, deduped."""
    monkeypatch.setattr(
        netcheck.socket,
        "getaddrinfo",
        lambda host, port, proto=None: [
            (None, None, None, None, ("172.64.153.51", 443)),
            (None, None, None, None, ("172.64.153.51", 443)),
            (None, None, None, None, ("2606:4700::1", 443, 0, 0)),
        ],
    )
    assert netcheck._resolve("clob.polymarket.com") == {
        "addresses": ["172.64.153.51", "2606:4700::1"],
        "error": None,
    }


def test_resolve_reports_the_resolver_error(monkeypatch) -> None:
    """A resolver failure is data for the verdict, not an exception."""

    def boom(host, port, proto=None):
        raise netcheck.socket.gaierror("Name or service not known")

    monkeypatch.setattr(netcheck.socket, "getaddrinfo", boom)
    result = netcheck._resolve("clob.polymarket.com")
    assert result["addresses"] == []
    assert "gaierror" in result["error"]


def test_netcheck_main_exits_nonzero_when_unreachable(monkeypatch, capsys) -> None:
    """The exit code has to make a broken network scriptable."""
    monkeypatch.setattr(
        netcheck,
        "check",
        lambda: {"ok": False, "hosts": [], "conclusion": "nope", "next_step": None},
    )
    monkeypatch.setattr(sys, "argv", ["netcheck.py"])
    with pytest.raises(SystemExit) as exc:
        netcheck.main()
    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["conclusion"] == "nope"


# --- the bundled skill ships what SKILL.md tells the agent to run ---------------


def test_skill_ships_the_scripts_its_docs_reference() -> None:
    """A documented command that isn't installed is a dead end mid-session."""
    skill = _SCRIPTS.parent
    doc = (skill / "SKILL.md").read_text(encoding="utf-8")
    for script in ("bootstrap_env.sh", "netcheck.py", "markets.py", "trade.py"):
        assert (skill / "scripts" / script).is_file()
        assert script in doc


# --- bootstrap_env.sh: the venv is .venv in the workspace (OPE-1862 #6) --------


BOOTSTRAP = _SCRIPTS / "bootstrap_env.sh"


def _posix_shell_available() -> bool:
    """Whether `bash` on this machine is actually a POSIX shell.

    Windows has a `bash` on PATH, but it is the WSL launcher: with no
    distribution installed it answers every invocation with an error message
    instead of running the script. Probing beats checking sys.platform, so
    these still run on a Windows box that does have a real bash.
    """
    try:
        probe = subprocess.run(  # nosec B603 B607 - fixed argv
            ["bash", "-c", "printf ok"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.stdout.strip() == "ok"


requires_posix_shell = pytest.mark.skipif(
    not _posix_shell_available(),
    reason="bootstrap_env.sh is a POSIX shell script and this `bash` is not a "
    "POSIX shell (on Windows CI it is the WSL launcher, no distribution)",
)


def _fake_pip(venv: Path, exit_code: int = 0) -> Path:
    """Put a stub pip in the venv so no real install is attempted."""
    pip = venv / "bin" / "pip"
    pip.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    pip.chmod(0o755)
    return pip


def _fake_venv(root: Path, complete: bool = True) -> Path:
    """Build a venv stub whose python answers the certifi query.

    `complete=False` reproduces a venv whose pip install died partway: the
    interpreter exists, the sentinel does not.
    """
    venv = root / ".venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\necho /fake/cacert.pem\n", encoding="utf-8")
    python.chmod(0o755)
    _fake_pip(venv)  # creation is gated on pip, so the stub needs one
    if complete:
        (venv / ".bootstrap-complete").touch()
    return venv


def _run_bootstrap(cwd: Path, env_extra: dict | None = None):
    return subprocess.run(  # nosec B603 B607 - fixed argv, test-controlled paths
        ["bash", str(BOOTSTRAP)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "HOME": str(cwd), **(env_extra or {})},
        check=False,
    )


@requires_posix_shell
def test_bootstrap_puts_the_venv_in_the_workspace(tmp_path) -> None:
    """`.venv` at the workspace root — persistent, and beside the skill state."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path)

    result = _run_bootstrap(tmp_path)

    assert result.returncode == 0, result.stderr
    assert f"export PY={venv / 'bin' / 'python'}" in result.stdout
    assert "export SSL_CERT_FILE=/fake/cacert.pem" in result.stdout
    assert "export REQUESTS_CA_BUNDLE=/fake/cacert.pem" in result.stdout
    assert "reusing venv" in result.stderr


@requires_posix_shell
def test_bootstrap_finds_the_root_from_a_nested_directory(tmp_path) -> None:
    """The scripts are run from anywhere in the workspace, so this must be too."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path)
    nested = tmp_path / ".claude" / "skills" / "connect-polymarket"
    nested.mkdir(parents=True)

    result = _run_bootstrap(nested)

    assert result.returncode == 0, result.stderr
    assert f"export PY={venv / 'bin' / 'python'}" in result.stdout


@requires_posix_shell
def test_bootstrap_refuses_when_there_is_no_workspace(tmp_path) -> None:
    """Guessing a location would strand the venv somewhere nothing looks."""
    result = _run_bootstrap(tmp_path)

    assert result.returncode == 1
    assert "could not be located" in result.stderr
    assert not (tmp_path / ".venv").exists()


@requires_posix_shell
def test_bootstrap_retries_a_venv_whose_install_died_partway(tmp_path) -> None:
    """An interpreter without the sentinel is a half-built venv, not a ready one.

    `python3 -m venv` writes bin/python before the packages land, so gating on
    the interpreter alone would call a broken venv "ready" forever.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path, complete=False)
    _fake_pip(venv)

    result = _run_bootstrap(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "installing dependencies" in result.stderr
    assert (venv / ".bootstrap-complete").is_file()


@requires_posix_shell
@requires_posix_shell
def test_a_venv_without_pip_is_rebuilt_not_reused(tmp_path) -> None:
    """An interpreter alone does not prove a venv works.

    A `python3 -m venv` that dies at ensurepip leaves bin/python behind; if
    that satisfied the gate, every later run would report only "bin/pip: No
    such file" and bury the actionable error the first attempt printed.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path)
    (venv / "bin" / "pip").unlink()

    result = _run_bootstrap(tmp_path)

    assert "creating venv" in result.stderr


@requires_posix_shell
def test_bootstrap_failure_makes_the_callers_eval_fail(tmp_path) -> None:
    """`eval "$(...)"` discards the exit status, so stdout has to carry it.

    Without this the caller sees exit 0 and an unset $PY after a failed
    install.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path, complete=False)
    _fake_pip(venv, exit_code=1)

    result = _run_bootstrap(tmp_path)

    assert result.returncode != 0
    assert "false" in result.stdout  # eval'ing this fails the caller too
    assert "export PY=" not in result.stdout
    assert not (venv / ".bootstrap-complete").exists()

    # prove the emitted snippet really does fail the caller's eval
    evaled = subprocess.run(  # nosec B603 B607 - fixed argv, test-controlled input
        ["bash", "-c", f"eval \"$(cat <<'EOF'\n{result.stdout}\nEOF\n)\""],
        capture_output=True,
        text=True,
        check=False,
    )
    assert evaled.returncode != 0
    assert "bootstrap FAILED" in evaled.stderr


@requires_posix_shell
def test_bootstrap_override_wins_over_the_workspace(tmp_path) -> None:
    """CONNECT_POLYMARKET_VENV stays the escape hatch, workspace or not."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    _fake_venv(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "bin").mkdir(parents=True)
    python = elsewhere / "bin" / "python"
    python.write_text("#!/bin/sh\necho /other/cacert.pem\n", encoding="utf-8")
    python.chmod(0o755)
    (elsewhere / ".bootstrap-complete").touch()

    result = _run_bootstrap(tmp_path, {"CONNECT_POLYMARKET_VENV": str(elsewhere)})

    assert result.returncode == 0, result.stderr
    assert f"export PY={python}" in result.stdout


@requires_posix_shell
def test_bootstrap_emits_only_shell_assignments_on_stdout(tmp_path) -> None:
    """The stdout is eval'd, so a stray log line there would be executed."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    _fake_venv(tmp_path)

    result = _run_bootstrap(tmp_path)

    assert all(
        line.startswith("export ") for line in result.stdout.splitlines() if line
    )


def test_workspace_gitignores_the_skill_venv() -> None:
    """A `git init` in the workspace must not be able to stage the venv."""
    assert ".venv/" in workspace.GITIGNORE_ENTRIES


def test_skill_no_longer_teaches_the_inverted_dns_rule() -> None:
    """Three identical IPs is the healthy result, and the doc must not say otherwise."""
    doc = (_SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert "one address for all three means" not in doc
    assert "Identical IP addresses across the three hosts are normal" in doc


# --- data API v2: positions and trades ------------------------------------------

V2_POSITION_ROW = {
    "proxy_wallet": SAFE_ADDR,
    "token_id": "1948",  # nosec B105
    "condition_id": "0x61c2",
    "current_size": 1705.62,
    "avg_price": 0.0193,
    "entry_cost_usdc": 33.0839,
    "current_value": 0.0,
    "unrealized_pnl": -33.0839,
    "current_price": 0.0,
    "redeemable": True,
    "status": "REDEEMABLE",
    "archived": False,
    "title": "US x Iran Effective Ceasefire by August 31?",
    "outcome": "No",
    "outcome_index": 1,
    "negative_risk": False,
    "mergeable": False,
    "slug": "us-x-iran-ceasefire",
    "event_slug": "us-x-iran",
    "end_date": "2026-08-31",
    "total_pnl": -33.0839,
}


def _literal_page(rows, next_cursor=None):
    """One data-API v2 page of rows exactly as the API returns them."""
    return {"data": rows, "pagination": {"next_cursor": next_cursor}}


def test_positions_map_v2_rows_to_the_names_the_scripts_read(monkeypatch) -> None:
    """Each field a script reads arrives under its v1 name with its value."""
    monkeypatch.setattr(
        pm, "http_get_json", lambda url, params=None: _literal_page([V2_POSITION_ROW])
    )

    assert pm.fetch_all_positions({"user": SAFE_ADDR}, label="t", page_limit=10) == [
        {
            "proxyWallet": SAFE_ADDR,
            "asset": "1948",
            "conditionId": "0x61c2",
            "size": 1705.62,
            "avgPrice": 0.0193,
            "initialValue": 33.0839,
            "currentValue": 0.0,
            "cashPnl": -33.0839,
            "curPrice": 0.0,
            "redeemable": True,
            "title": "US x Iran Effective Ceasefire by August 31?",
            "outcome": "No",
            "outcomeIndex": 1,
            "negativeRisk": False,
            "mergeable": False,
            "slug": "us-x-iran-ceasefire",
            "eventSlug": "us-x-iran",
            "endDate": "2026-08-31",
        }
    ]


def test_positions_query_reads_every_holding(monkeypatch) -> None:
    """v2 is asked for dust too, with no v1 parameters and no archived markets."""
    fake_get, seen = _paged({None: _literal_page([])})
    urls = []
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: urls.append(url) or fake_get(url, params),
    )

    pm.fetch_all_positions({"user": SAFE_ADDR}, label="t", page_limit=7)

    assert urls == [f"{pm.DATA_API}/v2/positions"]
    assert seen == [
        {
            "user": SAFE_ADDR,
            "limit": 7,
            "filter_type": "TOKENS",
            "filter_amount": 0,
        }
    ]


@pytest.mark.parametrize(
    ("redeemable", "status", "archived", "kept"),
    [(True, "REDEEMABLE", "true", [True]), (False, None, None, [True, False])],
)
def test_redeemable_selects_rows_whatever_the_server_sends(
    monkeypatch, redeemable, status, archived, kept
) -> None:
    """v2 ignores a `redeemable` parameter, so the row flag decides.

    Only the redeemable read reaches into archived markets: a settled position
    there is still redeemed, while an open one has no order book to sell into.
    """
    open_row = {**V2_POSITION_ROW, "token_id": "2"}  # nosec B105
    rows = [V2_POSITION_ROW, {**open_row, "redeemable": False}]
    fake_get, seen = _paged({None: _literal_page(rows)})
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    found = pm.fetch_all_positions(
        {"user": SAFE_ADDR}, label="t", page_limit=10, redeemable=redeemable
    )

    assert seen[0].get("status") == status
    assert seen[0].get("include_archived") == archived
    assert [p["redeemable"] for p in found] == kept


def test_null_data_is_an_empty_portfolio(monkeypatch) -> None:
    """`data: null` is the API's documented miss, not malformed data."""
    monkeypatch.setattr(
        pm, "http_get_json", lambda url, params=None: _literal_page(None)
    )

    assert pm.fetch_all_positions({"user": SAFE_ADDR}, label="t", page_limit=10) == []


def test_trades_read_v2_and_keep_the_v1_names(monkeypatch, capsys, tmp_path) -> None:
    """Trade history comes from /v2/trades, renamed to the v1 field names."""
    calls = []
    row = {
        "side": "BUY",
        "token_id": "1948",  # nosec B105
        "condition_id": "0x61c2",
        "size": 150.0,
        "price": 0.3,
        "outcome_index": 1,
        "transaction_hash": "0x85eb",
        "pseudonym": "Admirable-Child",
    }

    def fake_get(url, params=None):
        calls.append((url, dict(params)))
        return _literal_page([row])

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    positions.cmd_trades(_ChainCS(tmp_path), "safe", 10)

    assert calls == [(f"{pm.DATA_API}/v2/trades", {"user": SAFE_ADDR, "limit": 10})]
    assert json.loads(capsys.readouterr().out)["trades"] == [
        {
            "side": "BUY",
            "asset": "1948",
            "conditionId": "0x61c2",
            "size": 150.0,
            "price": 0.3,
            "outcomeIndex": 1,
            "transactionHash": "0x85eb",
        }
    ]


def _trade_rows(*sizes):
    """Literal v2 trade rows, one per size."""
    return [{"side": "BUY", "size": size} for size in sizes]


def test_trades_follow_the_cursor_up_to_the_limit(monkeypatch, capsys, tmp_path):
    """`--limit` is met across pages and the extra row is not reported."""
    fake_get, seen = _paged(
        {
            None: _literal_page(_trade_rows(1.0, 2.0), "c2"),
            "c2": _literal_page(_trade_rows(3.0, 4.0), "c3"),
        }
    )
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    positions.cmd_trades(_ChainCS(tmp_path), "safe", 3)

    trades = json.loads(capsys.readouterr().out)["trades"]
    assert [t["size"] for t in trades] == [1.0, 2.0, 3.0]
    assert [params.get("cursor") for params in seen] == [None, "c2"]


def test_trades_stop_once_the_limit_is_met(monkeypatch, capsys, tmp_path):
    """A full first page ends the read even when the API has more."""
    fake_get, seen = _paged({None: _literal_page(_trade_rows(1.0, 2.0), "c2")})
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    positions.cmd_trades(_ChainCS(tmp_path), "safe", 2)

    assert len(json.loads(capsys.readouterr().out)["trades"]) == 2
    assert len(seen) == 1


@pytest.mark.parametrize(("limit", "page_size"), [(50, 50), (1000, 1000), (5000, 1000)])
def test_trades_never_ask_for_a_page_above_the_api_max(
    monkeypatch, tmp_path, limit, page_size
):
    """v2 rejects a `limit` above 1000, so larger asks page instead."""
    fake_get, seen = _paged({None: _literal_page([])})
    monkeypatch.setattr(pm, "http_get_json", fake_get)

    positions.cmd_trades(_ChainCS(tmp_path), "safe", limit)

    assert seen[0]["limit"] == page_size


@pytest.mark.parametrize("payload", [[{"side": "BUY"}], None, {"trades": []}])
def test_trades_reject_a_malformed_page(monkeypatch, tmp_path, payload) -> None:
    """A v1-shaped or broken trades page is refused, not shown as no trades."""
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: payload)

    with pytest.raises(SystemExit, match="malformed data"):
        positions.cmd_trades(_ChainCS(tmp_path), "safe", 10)


# --- Gamma market version: only v1 markets are tradeable -------------------------


@pytest.mark.parametrize(
    ("version", "tradeable"),
    [("v1", True), ("v2", False), ("V1", False), ("", False), (None, False)],
)
def test_only_supported_version_markets_are_tradeable(version, tradeable) -> None:
    """Markets on another protocol version, or with none, are not tradeable."""
    market = {"active": True, "closed": False}
    if version is not None:
        market["version"] = version

    assert markets._tradeable(market) is tradeable


def test_cmd_list_fills_the_limit_past_markets_of_another_version(
    monkeypatch, capsys
) -> None:
    """Gamma is over-asked, so v2 markets ranked first don't shorten the list."""
    seen = []

    def fake_get(url, params=None):
        seen.append(dict(params))
        ranked = [{"question": f"v2 {i}", "version": "v2"} for i in range(3)]
        return ranked + [{"question": f"v1 {i}", "version": "v1"} for i in range(3)]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    markets.cmd_list(3, None, None, None, False)

    assert [m["question"] for m in json.loads(capsys.readouterr().out)] == [
        "v1 0",
        "v1 1",
        "v1 2",
    ]
    assert seen[0]["limit"] == 100


def test_cmd_list_drops_markets_of_another_version(monkeypatch, capsys) -> None:
    """The volume listing never offers a market this skill cannot trade."""
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [
            {"question": "v1 market", "version": "v1"},
            {"question": "v2 market", "version": "v2"},
            {"question": "unversioned"},
        ],
    )
    markets.cmd_list(10, None, None, None, False)

    assert [m["question"] for m in json.loads(capsys.readouterr().out)] == ["v1 market"]


def test_require_supported_market_accepts_a_v1_token(monkeypatch) -> None:
    """A token an open v1 market lists passes, looked up by its CLOB id."""
    seen = []

    def fake_get(url, params=None):
        seen.append((url, dict(params)))
        return [{"version": "v1"}]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    pm.require_supported_market("1948")

    lookup = {"clob_token_ids": "1948"}  # nosec B105
    assert seen == [(f"{pm.GAMMA_API}/markets", lookup)]


@pytest.mark.parametrize(
    "listed",
    [[{"version": "v2"}], [], None, [{"version": "v1"}, {"version": "v2"}], [{}]],
)
def test_require_supported_market_refuses_anything_else(monkeypatch, listed) -> None:
    """Another version, no open market, or an ambiguous answer is refused."""
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: listed)

    with pytest.raises(SystemExit, match="no open v1 market lists token 1948"):
        pm.require_supported_market("1948")


# --- Protocol V2 trading approvals on the DepositWallet ---------------------------

_SEL_APPROVE = keccak(text="approve(address,uint256)")[:4]
_SEL_SET_APPROVAL_FOR_ALL = keccak(text="setApprovalForAll(address,bool)")[:4]
_SEL_ALLOWANCE = keccak(text="allowance(address,address)")[:4]
_SEL_IS_APPROVED_FOR_ALL = keccak(text="isApprovedForAll(address,address)")[:4]
_SEL_OWNER = keccak(text="owner()")[:4]
_SEL_NONCE = keccak(text="nonce()")[:4]

# Each approval is (standard, token, spender-or-operator).
_V1_APPROVALS = (
    ("erc20", _PUSD, _CTF_EXCHANGE),
    ("erc20", _PUSD, _NEG_RISK_CTF_EXCHANGE),
    ("erc1155", _CTF, _CTF_EXCHANGE),
    ("erc1155", _CTF, _NEG_RISK_CTF_EXCHANGE),
)
_V2_APPROVALS = (
    ("erc20", _PUSD, _EXCHANGE_V3),
    ("erc1155", _POSITION_MANAGER, _EXCHANGE_V3),
)
_DW_APPROVALS = _V1_APPROVALS + _V2_APPROVALS
# Granted by the code before Protocol V2; no longer part of the set.
_RETIRED_APPROVALS = (
    ("erc20", _PUSD, _NEG_RISK_ADAPTER),
    ("erc1155", _CTF, _NEG_RISK_ADAPTER),
)
# The Router approvals belong to the trading change, and the AutoRedeemer is
# never approved: none of these may come out of the DW setup.
_NEVER_FROM_DW_SETUP = (
    ("erc20", _PUSD, _V2_ROUTER),
    ("erc1155", _POSITION_MANAGER, _V2_ROUTER),
    ("erc1155", _CTF, _AUTO_REDEEMER),
    ("erc1155", _POSITION_MANAGER, _AUTO_REDEEMER),
)


def _hex_bytes(data) -> bytes:
    """Bytes of 0x-hex or raw calldata, however the caller spelled it."""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return bytes.fromhex(str(data).removeprefix("0x"))


def _word(address: str) -> str:
    """Return an address as one left-padded ABI word, lowercase hex."""
    return "0" * 24 + address.removeprefix("0x").lower()


def _expected_call(approval: tuple) -> tuple:
    """Return the exact (target, calldata) that grants one approval.

    Spelled out byte by byte rather than through the skill's encoders, so a
    wrong selector, spender, amount or flag there cannot cancel out here.
    """
    standard, token, party = approval
    if standard == "erc20":  # approve(party, MaxUint256)
        return token, "0x095ea7b3" + _word(party) + "f" * 64
    return token, "0xa22cb465" + _word(party) + "0" * 63 + "1"  # (party, true)


def _as_calls(calls: list) -> list:
    """Normalise {"target", "data"[, "value"]} calls to sorted (target, data)."""
    for call in calls:
        assert int(call.get("value", 0)) == 0, call
    return sorted(
        (to_checksum_address(c["target"]), "0x" + _hex_bytes(c["data"]).hex())
        for c in calls
    )


class _ApprovalChain:
    """Polygon as the approval flow reads it, and as a mined batch changes it.

    Holds ERC-20 allowances and ERC-1155 operator grants keyed by (token,
    owner, spender-or-operator), plus each DW's owner(); nonce() reads 0. Any
    other eth_call fails the test, so a read nobody planned for is caught.
    Passed wherever the code expects a web3 instance: it is its own ``eth``.
    """

    def __init__(self) -> None:
        self.allowances: dict = {}
        self.operators: dict = {}
        self.owners: dict = {}
        self.eth = self

    def grant(self, approval: tuple, owner: str) -> None:
        """Record one approval as already granted by `owner`."""
        standard, token, party = approval
        if standard == "erc20":
            self.allowances[(token, owner, party)] = _MAX_UINT256
        else:
            self.operators[(token, owner, party)] = True

    def call(self, tx: dict, *args, **kwargs) -> bytes:
        """Answer one eth_call from the recorded state."""
        to = to_checksum_address(tx["to"])
        data = _hex_bytes(tx["data"])
        selector, body = data[:4], data[4:]
        if selector in (_SEL_ALLOWANCE, _SEL_IS_APPROVED_FOR_ALL):
            owner, party = (
                to_checksum_address(a) for a in abi_decode(["address", "address"], body)
            )
            if selector == _SEL_ALLOWANCE:
                value = self.allowances.get((to, owner, party), 0)
            else:
                value = int(self.operators.get((to, owner, party), False))
            return value.to_bytes(32, "big")
        if selector == _SEL_OWNER and to in self.owners:
            return bytes(12) + _hex_bytes(self.owners[to])
        if selector == _SEL_NONCE:
            return bytes(32)
        raise AssertionError(f"unexpected eth_call to {to}: 0x{data.hex()}")

    def apply(self, owner: str, calls: list) -> None:
        """Mine a DW batch: every call must be a value-0 approval."""
        for call in calls:
            assert int(call.get("value", 0)) == 0, call
            target = to_checksum_address(call["target"])
            data = _hex_bytes(call["data"])
            selector, body = data[:4], data[4:]
            if selector == _SEL_APPROVE:
                spender, amount = abi_decode(["address", "uint256"], body)
                self.allowances[(target, owner, to_checksum_address(spender))] = amount
            elif selector == _SEL_SET_APPROVAL_FOR_ALL:
                operator, approved = abi_decode(["address", "bool"], body)
                self.operators[(target, owner, to_checksum_address(operator))] = (
                    approved
                )
            else:
                raise AssertionError(f"DW batch call is not an approval: {call}")


class _EnsureCS:
    """The signer surface `deposit_wallet.py ensure` touches, on a fake chain."""

    agent_eoa = _StubCS.agent_eoa

    def __init__(self, chain: _ApprovalChain, workspace: Path) -> None:
        """Bind the fake chain and a workspace for the state file."""
        self.w3 = chain
        self.workspace = workspace

    def wait_receipt(self, tx_hash: str, timeout: float = 300) -> dict:
        """Every relayed batch confirms."""
        return {"tx_hash": tx_hash, "status": 1}

    def personal_sign(self, message: str) -> str:
        """Return a placeholder challenge signature (the relayer is a fake)."""
        return "0x" + "11" * 65

    def sign_digest(self, digest) -> str:
        """Return a placeholder batch signature (the relayer is a fake)."""
        return "0x" + "22" * 65


class _MiningRelayer:
    """Relayer proxy stand-in that mines each batch onto the fake chain."""

    def __init__(self, chain: _ApprovalChain) -> None:
        """Start with no batches relayed."""
        self.chain = chain
        self.batches: list = []

    def exec_wallet_batch(self, dw, nonce, calls, deadline=None) -> str:
        """Record and mine the batch; return a relayer tx id."""
        self.batches.append(list(calls))
        self.chain.apply(to_checksum_address(dw), calls)
        return f"relayer-tx-{len(self.batches)}"

    def wait_terminal(self, tx_id: str) -> tuple:
        """Every batch mines."""
        return True, "STATE_MINED", "0x" + "ab" * 32


def _last_json(out: str) -> dict:
    """Parse the JSON report a command printed after its progress lines."""
    return json.loads(out[out.index("{") :])


def test_dw_setup_includes_v2_approvals() -> None:
    """A fresh DW gets both V2 approvals and the V1 set, none to the NegRiskAdapter.

    The pUSD approval to ExchangeV3 must be exactly MaxUint256: Polymarket's
    relayer refuses the whole batch for anything less ("approve to exchange
    0xe3333700... must be MaxUint256").
    """
    sdk_config = PRODUCTION._config  # noqa: SLF001 - the pinned SDK's addresses
    assert to_checksum_address(sdk_config.exchange_v3) == _EXCHANGE_V3
    assert to_checksum_address(sdk_config.position_manager) == _POSITION_MANAGER

    calls = pm.missing_approval_calls(_ApprovalChain(), DW_ADDR)

    assert _as_calls(calls) == sorted(_expected_call(a) for a in _DW_APPROVALS)
    (v3_approval,) = (
        c
        for c in calls
        if to_checksum_address(c["target"]) == _PUSD
        and _hex_bytes(c["data"])[:4] == _SEL_APPROVE
        and to_checksum_address(
            abi_decode(["address", "uint256"], _hex_bytes(c["data"])[4:])[0]
        )
        == _EXCHANGE_V3
    )
    _, amount = abi_decode(["address", "uint256"], _hex_bytes(v3_approval["data"])[4:])
    assert amount == 2**256 - 1
    (v3_operator,) = (
        c for c in calls if to_checksum_address(c["target"]) == _POSITION_MANAGER
    )
    assert abi_decode(["address", "bool"], _hex_bytes(v3_operator["data"])[4:]) == (
        _EXCHANGE_V3.lower(),
        True,
    )
    retired = _NEG_RISK_ADAPTER.removeprefix("0x").lower()
    for call in calls:
        assert to_checksum_address(call["target"]) != _NEG_RISK_ADAPTER
        assert retired not in _hex_bytes(call["data"]).hex()


def test_existing_wallet_gets_v2_approvals_once(monkeypatch, tmp_path, capsys) -> None:
    """A DW holding the pre-V2 set gets exactly the two V2 approvals, then nothing.

    Driven through `deposit_wallet.py ensure`, the command that grants them,
    on a workspace that already recorded its approvals as done: the first run
    relays one batch of the two V2 calls, the second relays nothing.
    """
    chain = _ApprovalChain()
    chain.owners[DW_ADDR] = _EnsureCS.agent_eoa
    for approval in _V1_APPROVALS + _RETIRED_APPROVALS:
        chain.grant(approval, DW_ADDR)
    v2_calls = sorted(_expected_call(a) for a in _V2_APPROVALS)
    assert _as_calls(pm.missing_approval_calls(chain, DW_ADDR)) == v2_calls

    cs = _EnsureCS(chain, tmp_path)
    pm.save_state(
        cs,
        {
            "deposit_wallet": {"address": DW_ADDR, "owner": cs.agent_eoa},
            "approvals_done": True,
        },
    )
    relayer = _MiningRelayer(chain)
    monkeypatch.setattr(deposit_wallet, "RelayerProxyClient", lambda cs: relayer)

    deposit_wallet.cmd_ensure(cs)
    first = _last_json(capsys.readouterr().out)
    assert [_as_calls(batch) for batch in relayer.batches] == [v2_calls]
    assert first["deposit_wallet"] == DW_ADDR
    assert first["deployed_now"] is False

    deposit_wallet.cmd_ensure(cs)
    second = _last_json(capsys.readouterr().out)
    assert len(relayer.batches) == 1
    assert second["approvals"] == "already complete"
    assert pm.missing_approval_calls(chain, DW_ADDR) == []


def test_v2_approvals_missing_calls_randomized() -> None:
    """Every set/unset mix of the DW approvals yields exactly the missing calls.

    All 64 combinations of the six approvals the DW needs, each under four
    random owners and random states of approvals that must never matter (the
    retired NegRiskAdapter pair, the Router, the AutoRedeemer), from a fixed
    seed: 256 cases. Once the returned calls are mined, none are missing.
    """
    rng = random.Random(20260806)  # nosec B311 - test data, not secrets
    irrelevant = _RETIRED_APPROVALS + _NEVER_FROM_DW_SETUP
    cases = 0
    for mask in range(2 ** len(_DW_APPROVALS)):
        for _ in range(4):
            owner = to_checksum_address(rng.getrandbits(160).to_bytes(20, "big"))
            chain = _ApprovalChain()
            unset = []
            for bit, approval in enumerate(_DW_APPROVALS):
                if mask >> bit & 1:
                    chain.grant(approval, owner)
                else:
                    unset.append(approval)
            for approval in irrelevant:
                if rng.random() < 0.5:
                    chain.grant(approval, owner)

            calls = pm.missing_approval_calls(chain, owner)
            assert _as_calls(calls) == sorted(_expected_call(a) for a in unset), (
                mask,
                owner,
            )
            chain.apply(owner, calls)
            assert pm.missing_approval_calls(chain, owner) == [], (mask, owner)
            cases += 1
    assert cases >= 200


# --- relayer proxy errors keep the relayer's own words ----------------------------

# What Polymarket's relayer answered, through the proxy, to a bounded pUSD
# approval of ExchangeV3.
_RELAYER_REFUSAL_REASON = (
    "call blocked: call[0] blocked: approve to exchange "
    "0xe3333700cA9d93003F00f0F71f8515005F6c00Aa must be MaxUint256"
)
_RELAYER_REFUSAL = json.dumps({"error": _RELAYER_REFUSAL_REASON}, separators=(",", ":"))


class _RelayerHttp:
    """Answers every request the relayer proxy client sends with one response."""

    def __init__(self, status: int, reason: str, body: str, content_type: str) -> None:
        """Fix the response every request gets."""
        self.status, self.reason = status, reason
        self.body, self.content_type = body, content_type
        self.paths: list = []

    def send(self, request: requests.PreparedRequest) -> requests.Response:
        """Stand in for HTTPAdapter.send: no socket, the canned response."""
        self.paths.append(requests.utils.urlparse(request.url).path)
        response = requests.Response()
        response.status_code = self.status
        response.reason = self.reason
        response._content = self.body.encode("utf-8")  # noqa: SLF001
        response.headers["Content-Type"] = self.content_type
        response.encoding = "utf-8"
        response.url = request.url
        response.request = request
        return response


def test_relayer_error_body_surfaced(monkeypatch, tmp_path, capsys) -> None:
    """A 4xx from the relayer proxy shows what it said, not only the status.

    The approval batch `deposit_wallet.py ensure` relays is refused with the
    relayer's JSON reason, which must reach the error the command ends with;
    a plain-text 403 on a read must reach the RelayerProxyError the same way.
    """
    monkeypatch.delenv("POLYMARKET_RELAYER_PROXY_URL", raising=False)
    chain = _ApprovalChain()
    chain.owners[DW_ADDR] = _EnsureCS.agent_eoa
    cs = _EnsureCS(chain, tmp_path)
    pm.save_state(cs, {"deposit_wallet": {"address": DW_ADDR}})

    refusal = _RelayerHttp(400, "Bad Request", _RELAYER_REFUSAL, "application/json")
    monkeypatch.setattr(
        requests.adapters.HTTPAdapter,
        "send",
        lambda adapter, request, **kwargs: refusal.send(request),
    )
    with pytest.raises((relayer_proxy.RelayerProxyError, SystemExit)) as refused:
        deposit_wallet.cmd_ensure(cs)
    printed = capsys.readouterr()
    shown = " ".join([str(refused.value), printed.out, printed.err])
    assert refusal.paths == ["/polymarket/relayer/exec_wallet_batch"]
    assert _RELAYER_REFUSAL_REASON in shown
    assert "400" in shown

    body = "wallet signature rejected: challenge timestamp outside the window"
    forbidden = _RelayerHttp(403, "Forbidden", body, "text/plain")
    monkeypatch.setattr(
        requests.adapters.HTTPAdapter,
        "send",
        lambda adapter, request, **kwargs: forbidden.send(request),
    )
    with pytest.raises(relayer_proxy.RelayerProxyError) as rejected:
        relayer_proxy.RelayerProxyClient(cs).deployed(DW_ADDR)
    assert forbidden.paths == ["/polymarket/relayer/deployed"]
    assert body in str(rejected.value)
    assert "403" in str(rejected.value)


def test_relayer_error_names_the_call_then_the_body(monkeypatch, tmp_path) -> None:
    """The error reads ``Relayer proxy <method> <endpoint> failed: <error>: <body>``.

    With no response at all (the proxy unreachable) there is no body to add,
    and the message ends at the error.
    """
    monkeypatch.delenv("POLYMARKET_RELAYER_PROXY_URL", raising=False)
    cs = _EnsureCS(_ApprovalChain(), tmp_path)
    body = "wallet signature rejected: challenge timestamp outside the window"
    forbidden = _RelayerHttp(403, "Forbidden", body, "text/plain")
    monkeypatch.setattr(
        requests.adapters.HTTPAdapter,
        "send",
        lambda adapter, request, **kwargs: forbidden.send(request),
    )
    with pytest.raises(relayer_proxy.RelayerProxyError) as rejected:
        relayer_proxy.RelayerProxyClient(cs).deployed(DW_ADDR)
    assert re.fullmatch(
        r"Relayer proxy GET deployed failed: 403 Client Error: Forbidden for url: "
        rf"\S+/polymarket/relayer/deployed\?\S+: {re.escape(body)}",
        str(rejected.value),
    )

    def unreachable(adapter, request, **kwargs):
        raise requests.exceptions.ConnectionError("proxy unreachable")

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", unreachable)
    with pytest.raises(relayer_proxy.RelayerProxyError) as failed:
        relayer_proxy.RelayerProxyClient(cs).deployed(DW_ADDR)
    assert str(failed.value) == "Relayer proxy GET deployed failed: proxy unreachable"


def test_relayer_error_bounds_a_huge_body(monkeypatch, tmp_path) -> None:
    """A huge error page is cut down: the error keeps its start, not 100 KB.

    A proxy or gateway in front of the relayer can answer with a whole HTML
    page. The agent reads the error the command prints, so the message names
    the call and the status in full, then only the first few hundred
    characters of the body.
    """
    monkeypatch.delenv("POLYMARKET_RELAYER_PROXY_URL", raising=False)
    cs = _EnsureCS(_ApprovalChain(), tmp_path)
    head = (
        "<html><head><title>502 Bad Gateway</title></head><body>"
        "<h1>502 Bad Gateway</h1><p>The upstream relayer did not answer in time."
        "</p><p>Request id 7f3a9c2e41b8d605; retry after a short wait.</p>"
    )
    body = head + "<!-- padding -->" * (100_000 // 16) + "</body></html>"
    assert len(body) > 100_000
    gateway = _RelayerHttp(502, "Bad Gateway", body, "text/html")
    monkeypatch.setattr(
        requests.adapters.HTTPAdapter,
        "send",
        lambda adapter, request, **kwargs: gateway.send(request),
    )
    with pytest.raises(relayer_proxy.RelayerProxyError) as failed:
        relayer_proxy.RelayerProxyClient(cs).deployed(DW_ADDR)
    message = str(failed.value)
    assert message.startswith(
        "Relayer proxy GET deployed failed: 502 Server Error: Bad Gateway for url: "
    )
    assert head[:200] in message
    assert len(message) < 1200, f"the error carries {len(message)} characters"


# --- remote signer on the unified SDK ----------------------------------------------

# A throwaway, publicly known test key. Only the Connect stand-in below holds
# it, the way the Connect server is the only holder of the agent's key.
_CONNECT_KEY = bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
)
_AGENT_EOA = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
# The DepositWallet Polymarket's factory derives for _AGENT_EOA, its owner.
_AGENT_DW = "0xd2C50736787e5eeefA6c2E81496AE56d51D6b7B1"
_V1_TOKEN = (  # nosec B105 - an outcome token id, not a password
    "71321045679252212594626385532706912750332728571942532289631379312455583992563"
)
# A protocol V2 position id: module 1, the reserved bits clear, outcome 0.
_V2_TOKEN = str(int("01" + "ab" * 18 + "00" * 13, 16))
_ORDER_SALT = 123456789
_ORDER_TIMESTAMP_MS = 1_800_000_000_000
_CACHED_CREDS = {
    "api_key": "cached-key",
    "api_secret": "Y2FjaGVkLXNlY3JldA==",  # nosec B105 - a fake, base64 like a real one
    "api_passphrase": "cached-passphrase",  # nosec B105
}

# Captured from the code this replaces (RemoteSigner on py_clob_client_v2
# 1.0.2, POLY_1271 funded by _AGENT_DW): the digest Connect was asked to sign
# and the order signature it produced for a GTC BUY of 10 _V1_TOKEN at 0.50
# with _ORDER_SALT and _ORDER_TIMESTAMP_MS. A V1 order on the new SDK must
# match both, byte for byte.
_V1_GOLDEN_DIGEST = "0x5253886c32ea78ebf65a8a427ba9e2b9933c5e947f15b7e5be7bff836a099fa2"
_V1_GOLDEN_SIGNATURE = (
    "0xf30cb504a98efc00e00d1d6adf9907082af48a5c291e253d5ab9bec39515464d5e8feef8568e"
    "84b9df2e200be08116dc62d235ee22d574d2db0e78eab023c8531b3264e159346253e26a64e00b"
    "69032db0e7d32f94628de3e6eecb50304d7af3d2f2e81f819fc723d708509aa07d9b8300a86396"
    "585213189e722a5e0da4d252394f726465722875696e743235362073616c742c61646472657373"
    "206d616b65722c61646472657373207369676e65722c75696e7432353620746f6b656e49642c75"
    "696e74323536206d616b6572416d6f756e742c75696e743235362074616b6572416d6f756e742c"
    "75696e743820736964652c75696e7438207369676e6174757265547970652c75696e7432353620"
    "74696d657374616d702c62797465733332206d657461646174612c62797465733332206275696c"
    "6465722900ba"
)

_ORDER_TYPE = (
    "Order(uint256 salt,address maker,address signer,uint256 tokenId,"
    "uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,"
    "uint256 timestamp,bytes32 metadata,bytes32 builder)"
)
_TYPED_DATA_SIGN_TYPE = (
    "TypedDataSign(Order contents,string name,string version,uint256 chainId,"
    "address verifyingContract,bytes32 salt)" + _ORDER_TYPE
)
_DOMAIN_TYPE = (
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)


def _exchange_domain_separator(version: str, exchange: str) -> bytes:
    """EIP-712 domain separator of a Polymarket exchange on Polygon."""
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                keccak(text=_DOMAIN_TYPE),
                keccak(text="Polymarket CTF Exchange"),
                keccak(text=version),
                137,
                exchange,
            ],
        )
    )


def _order_contents_hash(token_id: str) -> bytes:
    """Struct hash of the fixed test order: BUY 10 at 0.50, made by the agent DW."""
    return keccak(
        abi_encode(
            [
                "bytes32",
                "uint256",
                "address",
                "address",
                "uint256",
                "uint256",
                "uint256",
                "uint8",
                "uint8",
                "uint256",
                "bytes32",
                "bytes32",
            ],
            [
                keccak(text=_ORDER_TYPE),
                _ORDER_SALT,
                _AGENT_DW,  # maker
                _AGENT_DW,  # signer: the DW itself under POLY_1271
                int(token_id),
                5_000_000,  # makerAmount: 5 pUSD
                10_000_000,  # takerAmount: 10 shares
                0,  # BUY
                3,  # POLY_1271
                _ORDER_TIMESTAMP_MS,
                bytes(32),
                bytes(32),
            ],
        )
    )


def _poly_1271_digest(version: str, exchange: str, token_id: str) -> bytes:
    """Return the digest the DW owner signs: the order in the DW's TypedDataSign."""
    struct_hash = keccak(
        abi_encode(
            [
                "bytes32",
                "bytes32",
                "bytes32",
                "bytes32",
                "uint256",
                "address",
                "bytes32",
            ],
            [
                keccak(text=_TYPED_DATA_SIGN_TYPE),
                _order_contents_hash(token_id),
                keccak(text="DepositWallet"),
                keccak(text="1"),
                137,
                _AGENT_DW,
                bytes(32),
            ],
        )
    )
    return keccak(
        b"\x19\x01" + _exchange_domain_separator(version, exchange) + struct_hash
    )


def _poly_1271_trailer(version: str, exchange: str, token_id: str) -> str:
    """Return what the DepositWallet wrapping appends to the owner's signature."""
    return (
        _exchange_domain_separator(version, exchange).hex()
        + _order_contents_hash(token_id).hex()
        + _ORDER_TYPE.encode("utf-8").hex()
        + f"{len(_ORDER_TYPE):04x}"
    )


# Built once, up front, so the tests that forbid creating a key in the
# skill's process can still answer as Connect.
_CONNECT_PRIVATE_KEY = eth_keys.PrivateKey(_CONNECT_KEY)


def _connect_sign(digest: bytes) -> str:
    """Sign a raw digest the way connect/signer.py does: unprefixed, v in {27, 28}."""
    sig = _CONNECT_PRIVATE_KEY.sign_msg_hash(digest)
    return (
        "0x"
        + sig.r.to_bytes(32, "big").hex()
        + sig.s.to_bytes(32, "big").hex()
        + f"{sig.v + 27:02x}"
    )


class _ConnectServer:
    """Stand-in for the Connect server, the only holder of the agent key.

    Answers ``POST /sign-message`` as connect/signer.py does and records each
    request, so a test sees exactly what Connect was asked to sign.
    """

    def __init__(self) -> None:
        """Start with no requests."""
        self.requests: list = []

    def post(self, path: str, payload: dict) -> dict:
        """Answer the signer client's one HTTP call in-process."""
        self.requests.append((path, dict(payload)))
        assert path == "/sign-message", f"unexpected Connect request {path}"
        return {"signature": _connect_sign(_hex_bytes(payload["digest"]))}

    @property
    def digests(self) -> list:
        """Each digest Connect signed, as 0x-hex, in order."""
        return ["0x" + _hex_bytes(p["digest"]).hex() for _, p in self.requests]


def _connect_signer(tmp_path, monkeypatch, server, creds=_CACHED_CREDS):
    """Build a real ConnectSigner whose HTTP hop lands on `server`.

    `creds`, when given, are stored the way the workspace keeps them today.
    """
    cs = pm.ConnectSigner("http://127.0.0.1:8716", "test-bearer", tmp_path)
    cs._info = {"agent_eoa": _AGENT_EOA}  # noqa: SLF001 - /wallet, pre-answered
    monkeypatch.setattr(cs, "_post", server.post)
    if creds is not None:
        pm.save_state(cs, {"clob_creds": dict(creds)})
    return cs


_DERIVE_PATHS = ("/auth/api-key", "/auth/derive-api-key")


class _SdkHttp:
    """Every HTTP request the SDK makes, answered with no network.

    Credential creation or derivation issues `issued`; a credentials check
    (``GET /auth/api-keys``) lists `active`; a DepositWallet deployment check
    reads deployed. Anything else fails the test.
    """

    def __init__(self) -> None:
        """Start with no requests and nothing to issue."""
        self.requests: list = []
        self.issued: dict | None = None
        self.active: list = [_CACHED_CREDS["api_key"]]

    def send(self, request: httpx.Request) -> httpx.Response:
        """Answer one request."""
        self.requests.append(request)
        path = request.url.path
        if path in _DERIVE_PATHS and self.issued is not None:
            return httpx.Response(200, json=self.issued, request=request)
        if path == "/auth/api-keys":
            return httpx.Response(200, json={"apiKeys": self.active}, request=request)
        if path == "/deployed":
            return httpx.Response(200, json={"deployed": True}, request=request)
        raise AssertionError(f"unexpected SDK request: {request.method} {request.url}")

    def derivations(self) -> list:
        """Return the requests that created or derived API credentials."""
        return [r for r in self.requests if r.url.path in _DERIVE_PATHS]


@pytest.fixture
def sdk_http(monkeypatch: pytest.MonkeyPatch) -> _SdkHttp:
    """Route the SDK's HTTP client to an in-process fake."""
    http = _SdkHttp()
    monkeypatch.setattr(
        httpx.Client, "send", lambda self, request, **kwargs: http.send(request)
    )
    return http


@pytest.fixture
def _fixed_orders(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin each order's salt and timestamp, and answer the SDK's market lookups."""
    monkeypatch.setattr(sdk_orders, "_generate_salt", lambda: _ORDER_SALT)
    monkeypatch.setattr(
        sdk_orders, "_current_timestamp_ms", lambda: _ORDER_TIMESTAMP_MS
    )
    market = MarketInfo(
        fee_info=PlatformFeeInfo(rate=Decimal(0), exponent=Decimal(1)),
        neg_risk=False,
        tick_size=Decimal("0.01"),
        token_ids=frozenset({_V1_TOKEN, _V2_TOKEN}),
    )
    monkeypatch.setattr(
        sdk_order_cache,
        "resolve_condition_by_token_sync",
        lambda ctx, token_id: "0x" + "cd" * 32,
    )
    monkeypatch.setattr(
        sdk_order_cache, "fetch_market_info_sync", lambda ctx, condition_id: market
    )


_PY_CLOB_IMPORT = re.compile(r"^\s*(from|import)\s+py_clob_client_v2\b", re.MULTILINE)


def _remote_signer():
    """Import remote_signer, which must stand on polymarket-client alone."""
    source = (_SCRIPTS / "remote_signer.py").read_text(encoding="utf-8")
    assert not _PY_CLOB_IMPORT.search(source), (
        "remote_signer.py still imports py_clob_client_v2; it must build its "
        "client on polymarket-client==0.13.0"
    )
    return importlib.import_module("remote_signer")


def _limit_buy(client, token_id: str):
    """Sign, without posting, the fixed test order: BUY 10 at 0.50."""
    return client.create_limit_order(
        token_id=token_id, price="0.5", size="10", side="BUY"
    )


@pytest.mark.usefixtures("_fixed_orders")
def test_remote_signer_signs_v1_and_v2_orders(tmp_path, monkeypatch, sdk_http) -> None:
    """Both order kinds sign through RemoteSigner, each on its own exchange domain.

    The V1 order is byte-identical to what the py_clob_client_v2 path signed
    for the same order. The V2 order signs the V2 domain: version "3" on
    ExchangeV3. Both carry the DepositWallet POLY_1271 wrapping the SDK
    applies: the owner's signature, then the exchange's domain separator, the
    order's contents hash, the Order type string and its length.
    """
    remote_signer = _remote_signer()
    server = _ConnectServer()
    cs = _connect_signer(tmp_path, monkeypatch, server)
    client = remote_signer.make_clob_client(cs, _AGENT_DW)
    assert isinstance(client, SecureClient)
    assert client.wallet == _AGENT_DW

    v1 = _limit_buy(client, _V1_TOKEN)
    assert server.digests == [_V1_GOLDEN_DIGEST]
    assert v1.signature == _V1_GOLDEN_SIGNATURE
    # the golden is that same wrapping, on the current exchange's version "2"
    assert _poly_1271_digest("2", _CTF_EXCHANGE, _V1_TOKEN).hex() == (
        _V1_GOLDEN_DIGEST.removeprefix("0x")
    )
    assert v1.signature == (
        _connect_sign(_hex_bytes(_V1_GOLDEN_DIGEST))
        + _poly_1271_trailer("2", _CTF_EXCHANGE, _V1_TOKEN)
    )

    v2 = _limit_buy(client, _V2_TOKEN)
    v2_digest = _poly_1271_digest("3", _EXCHANGE_V3, _V2_TOKEN)
    assert server.digests == [_V1_GOLDEN_DIGEST, "0x" + v2_digest.hex()]
    assert v2.signature == (
        _connect_sign(v2_digest) + _poly_1271_trailer("3", _EXCHANGE_V3, _V2_TOKEN)
    )

    for order, token_id, digest in (
        (v1, _V1_TOKEN, _hex_bytes(_V1_GOLDEN_DIGEST)),
        (v2, _V2_TOKEN, v2_digest),
    ):
        assert to_checksum_address(order.maker) == _AGENT_DW
        assert to_checksum_address(order.signer) == _AGENT_DW
        assert order.signature_type == 3
        assert str(order.token_id) == token_id
        assert (order.maker_amount, order.taker_amount) == (5_000_000, 10_000_000)
        assert (order.salt, order.timestamp) == (_ORDER_SALT, _ORDER_TIMESTAMP_MS)
        owner_signature = _hex_bytes(order.signature)[:65]
        assert Account._recover_hash(digest, signature=owner_signature) == _AGENT_EOA


@pytest.fixture
def _no_local_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the skill creates, loads or signs with a key itself.

    Covers eth_account's key entry points and eth_keys' PrivateKey, which
    eth_account builds every LocalAccount on. Connect's stand-in signs with a
    key object made before this runs.
    """

    def key_used(*args, **kwargs):
        raise AssertionError("key material was used in the skill's process")

    for name in (
        "create",
        "create_with_mnemonic",
        "decrypt",
        "from_key",
        "from_mnemonic",
        "_sign_hash",
        "sign_message",
        "sign_transaction",
        "sign_typed_data",
        "unsafe_sign_hash",
    ):
        monkeypatch.setattr(Account, name, key_used)
    monkeypatch.setattr(LocalAccount, "__init__", key_used)
    monkeypatch.setattr(eth_keys.PrivateKey, "__init__", key_used)


@pytest.mark.usefixtures("_fixed_orders", "_no_local_keys")
def test_no_private_key_in_process(tmp_path, monkeypatch, sdk_http) -> None:
    """The SDK holds a RemoteSigner, and every signature it gets is Connect's.

    Every eth_account entry point that takes a key fails the test if reached,
    yet the client is built and signs a typed message, an EIP-191 message and
    an order, each through Connect's ``/sign-message`` with only a digest.
    """

    def key_used(*args, **kwargs):
        raise AssertionError("key material was used in the skill's process")

    for name in (
        "create",
        "create_with_mnemonic",
        "decrypt",
        "from_key",
        "from_mnemonic",
        "_sign_hash",
        "sign_message",
        "sign_transaction",
        "sign_typed_data",
        "unsafe_sign_hash",
    ):
        monkeypatch.setattr(Account, name, key_used)
    monkeypatch.setattr(LocalAccount, "__init__", key_used)

    remote_signer = _remote_signer()
    server = _ConnectServer()
    cs = _connect_signer(tmp_path, monkeypatch, server)
    client = remote_signer.make_clob_client(cs, _AGENT_DW)

    held = client._ctx.signer  # noqa: SLF001 - the object the SDK signs with
    assert isinstance(held, remote_signer.RemoteSigner)
    assert not isinstance(held, LocalAccount)
    assert held.address == _AGENT_EOA
    assert client.signer == _AGENT_EOA
    for name in ("key", "private_key", "_private_key"):
        assert not isinstance(getattr(held, name, None), (bytes, bytearray, str, int))
    assert server.requests == []  # cached creds: building asked Connect nothing

    typed = build_api_key_auth_typed_data(
        address=_AGENT_EOA, chain_id=137, timestamp=1_800_000_000, nonce=0
    )
    typed_digest = _hash_eip191_message(encode_typed_data(full_message=typed))
    signed = held.sign_typed_data(full_message=typed)
    assert server.digests == ["0x" + typed_digest.hex()]
    assert "0x" + signed.signature.hex() == _connect_sign(typed_digest)

    text = b"Connect holds the key"
    message_digest = keccak(
        b"\x19Ethereum Signed Message:\n" + str(len(text)).encode() + text
    )
    signed = held.sign_message(encode_defunct(primitive=text))
    assert server.digests[-1] == "0x" + message_digest.hex()
    assert "0x" + signed.signature.hex() == _connect_sign(message_digest)

    _limit_buy(client, _V2_TOKEN)
    order_digest = _poly_1271_digest("3", _EXCHANGE_V3, _V2_TOKEN)
    assert server.digests[-1] == "0x" + order_digest.hex()
    assert len(server.requests) == 3
    assert all(set(payload) == {"digest"} for _, payload in server.requests)


@pytest.mark.usefixtures("_no_local_keys")
def test_cached_api_credentials_reused(tmp_path, monkeypatch, sdk_http) -> None:
    """Workspace creds are reused as they are, run after run, never re-derived.

    Only a workspace without creds derives them: once, with an L1 signature
    Connect makes, kept in the same workspace format for the next run, next to
    whatever else the workspace state already holds.
    """
    remote_signer = _remote_signer()
    server = _ConnectServer()
    cs = _connect_signer(tmp_path, monkeypatch, server)
    stored = pm.state_path(cs).read_bytes()
    for _ in range(2):
        creds = remote_signer.make_clob_client(cs, _AGENT_DW).credentials
        assert (creds.key, creds.secret, creds.passphrase) == (
            _CACHED_CREDS["api_key"],
            _CACHED_CREDS["api_secret"],
            _CACHED_CREDS["api_passphrase"],
        )
    assert sdk_http.derivations() == []
    assert server.requests == []  # no L1 signature: nothing was derived
    assert pm.state_path(cs).read_bytes() == stored

    fresh = tmp_path / "fresh"
    fresh.mkdir()
    fresh_server = _ConnectServer()
    fresh_cs = _connect_signer(fresh, monkeypatch, fresh_server, creds=None)
    dw_record = {"address": _AGENT_DW, "owner": _AGENT_EOA}
    pm.save_state(fresh_cs, {"deposit_wallet": dict(dw_record)})
    sdk_http.issued = {
        "apiKey": "derived-key",
        "secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
        "passphrase": "derived-passphrase",  # nosec B105
    }
    sdk_http.active = ["derived-key"]
    for _ in range(2):
        creds = remote_signer.make_clob_client(fresh_cs, _AGENT_DW).credentials
        assert (creds.key, creds.secret, creds.passphrase) == (
            "derived-key",
            "ZGVyaXZlZC1zZWNyZXQ=",
            "derived-passphrase",
        )
    (derivation,) = sdk_http.derivations()
    # stored beside, not over, the rest of the workspace state
    assert pm.load_state(fresh_cs) == {
        "deposit_wallet": dw_record,
        "clob_creds": {
            "api_key": "derived-key",
            "api_secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
            "api_passphrase": "derived-passphrase",  # nosec B105
        },
    }
    # the derivation was authorised by Connect's signature over the ClobAuth
    # message for the agent EOA: nonce 0, the one the workspace's key was
    # always derived with, signed now
    assert derivation.headers["POLY_NONCE"] == "0"
    assert abs(int(derivation.headers["POLY_TIMESTAMP"]) - time.time()) < 300
    clob_auth = build_api_key_auth_typed_data(
        address=_AGENT_EOA,
        chain_id=137,
        timestamp=int(derivation.headers["POLY_TIMESTAMP"]),
        nonce=int(derivation.headers["POLY_NONCE"]),
    )
    clob_auth_digest = _hash_eip191_message(encode_typed_data(full_message=clob_auth))
    assert fresh_server.digests == ["0x" + clob_auth_digest.hex()]
    assert derivation.headers["POLY_ADDRESS"] == _AGENT_EOA
    assert derivation.headers["POLY_SIGNATURE"] == _connect_sign(clob_auth_digest)


_DERIVED_CREDS = {
    "apiKey": "derived-key",
    "secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
    "passphrase": "derived-passphrase",  # nosec B105
}


class _CreateFails(_SdkHttp):
    """The SDK fake, but creating an API key fails the way `failure` says.

    Deriving (``GET /auth/derive-api-key``) still issues `issued`.
    """

    def __init__(self, failure) -> None:
        """Fail every ``POST /auth/api-key`` with `failure(request)`."""
        super().__init__()
        self.failure = failure

    def send(self, request: httpx.Request) -> httpx.Response:
        """Answer a create with the failure, anything else as the SDK fake."""
        if (request.method, request.url.path) == ("POST", "/auth/api-key"):
            self.requests.append(request)
            return self.failure(request)
        return super().send(request)


def _create_answers(status: int, body: dict | str):
    """Return a failure that answers the create with `status` and `body`."""

    def answer(request: httpx.Request) -> httpx.Response:
        if isinstance(body, dict):
            return httpx.Response(status, json=body, request=request)
        return httpx.Response(
            status, text=body, headers={"Content-Type": "text/html"}, request=request
        )

    return answer


def _create_unreachable(request: httpx.Request) -> httpx.Response:
    """Fail the create before any answer arrives."""
    raise httpx.ConnectError("connection reset by peer", request=request)


@pytest.mark.parametrize(
    "failure",
    [
        _create_answers(500, {"error": "internal server error"}),
        _create_answers(503, "<html><body>503 Service Unavailable</body></html>"),
        _create_unreachable,
        # answered, but with no credentials in it
        _create_answers(200, {}),
    ],
    ids=["500", "503", "transport-error", "no-credentials"],
)
@pytest.mark.usefixtures("_no_local_keys")
def test_first_credentials_are_derived_when_creating_fails(
    tmp_path, monkeypatch, failure
) -> None:
    """Any failure to create the workspace's API key falls back to deriving it.

    py-clob-client-v2==1.0.2's ``create_or_derive_api_key`` derived after any
    failure of the create, not only a 400. The derived creds are the ones the
    client uses, and they are kept, so the next run derives nothing.
    """
    remote_signer = _remote_signer()
    http = _CreateFails(failure)
    http.issued = dict(_DERIVED_CREDS)
    http.active = ["derived-key"]
    monkeypatch.setattr(
        httpx.Client, "send", lambda self, request, **kwargs: http.send(request)
    )
    server = _ConnectServer()
    cs = _connect_signer(tmp_path, monkeypatch, server, creds=None)

    for _ in range(2):
        try:
            creds = remote_signer.make_clob_client(cs, _AGENT_DW).credentials
        except Exception as error:  # noqa: BLE001 - the failure under test
            pytest.fail(f"a failed create did not fall back to a derive: {error!r}")
        assert (creds.key, creds.secret, creds.passphrase) == (
            "derived-key",
            "ZGVyaXZlZC1zZWNyZXQ=",
            "derived-passphrase",
        )
    assert [(r.method, r.url.path) for r in http.derivations()] == [
        ("POST", "/auth/api-key"),
        ("GET", "/auth/derive-api-key"),
    ]
    assert pm.load_state(cs)["clob_creds"] == {
        "api_key": "derived-key",
        "api_secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
        "api_passphrase": "derived-passphrase",  # nosec B105
    }
    derivation = http.derivations()[-1]
    clob_auth = build_api_key_auth_typed_data(
        address=_AGENT_EOA,
        chain_id=137,
        timestamp=int(derivation.headers["POLY_TIMESTAMP"]),
        nonce=0,
    )
    clob_auth_digest = _hash_eip191_message(encode_typed_data(full_message=clob_auth))
    assert derivation.headers["POLY_NONCE"] == "0"
    assert derivation.headers["POLY_SIGNATURE"] == _connect_sign(clob_auth_digest)


# --- one SDK across the skill --------------------------------------------------------


def test_bootstrap_installs_the_unified_sdk_only() -> None:
    """The agent's venv gets polymarket-client at the pinned version, not the old SDK."""
    script = BOOTSTRAP.read_text(encoding="utf-8")
    assert '"polymarket-client==0.13.0"' in script
    assert "py-clob-client-v2" not in script


def test_no_skill_file_mentions_py_clob_client_v2() -> None:
    """No script imports the old SDK, and no doc tells the agent to use it."""
    skill = _SCRIPTS.parent
    mentions = [
        str(path.relative_to(skill))
        for path in sorted(skill.rglob("*"))
        if path.is_file()
        and "__pycache__" not in path.parts
        and "py_clob_client_v2" in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert mentions == []


# --- trade.py and funds.py on the unified SDK ---------------------------------------

_ORDER_ID = "0x" + "0e" * 32
_ACCEPTED = {
    "success": True,
    "errorMsg": "",
    "orderID": _ORDER_ID,
    "status": "live",
    "makingAmount": "",
    "takingAmount": "",
    "tradeIDs": [],
    "transactionsHashes": [],
}
_OPEN_ORDER = {
    "id": _ORDER_ID,
    "market": "0x" + "cd" * 32,
    "asset_id": _V1_TOKEN,
    "owner": _CACHED_CREDS["api_key"],
    "maker_address": _AGENT_DW,
    "side": "BUY",
    "price": "0.5",
    "original_size": "10",
    "size_matched": "0",
    "outcome": "Yes",
    "order_type": "GTC",
    "status": "LIVE",
    "associate_trades": [],
    "created_at": 1_800_000_000,
    "expiration": "0",
}

# One level each side, deep enough for every test order: asks at 0.50, bids
# at 0.40.
_BOOK = {
    "market": "0x" + "cd" * 32,
    "asset_id": _V1_TOKEN,
    "timestamp": "1800000000000",
    "hash": "0x" + "00" * 20,
    "bids": [{"price": "0.4", "size": "1000"}],
    "asks": [{"price": "0.5", "size": "1000"}],
    "min_order_size": "1",
    "tick_size": "0.01",
    "neg_risk": False,
}


class _ClobHttp(_SdkHttp):
    """The CLOB's order endpoints on top of the SDK fake, recording each call.

    ``POST /order`` answers `posted` (accepted by default) and snapshots the
    workspace state at that moment, so a test can see what was persisted
    before the order left; reads and cancels answer for `_ORDER_ID`, and
    ``GET /book`` answers `book` (`_BOOK` by default). A
    request sent with the API key in `refused_key` is answered with the
    `refusal` (status, JSON body) instead.
    """

    def __init__(self, cs, open_orders: list) -> None:
        """Bind the workspace the snapshots read; start with nothing posted."""
        super().__init__()
        self.cs = cs
        self.open_orders = open_orders
        self.posted = dict(_ACCEPTED)
        self.orders: list = []
        self.state_at_post: list = []
        self.calls: list = []
        self.refused_key: str | None = None
        self.refusal: tuple = (401, {"error": "Unauthorized"})
        self.book: dict = _BOOK

    def send(self, request: httpx.Request) -> httpx.Response:
        """Answer an order request, or defer to the SDK fake."""
        path = request.url.path
        self.calls.append((request.method, path))
        if request.method == "POST" and path == "/order":
            self.requests.append(request)
            self.orders.append(json.loads(request.content))
            self.state_at_post.append(pm.load_state(self.cs))
        refused = self.refused_key is not None and path not in (
            *_DERIVE_PATHS,
            "/auth/api-keys",
            "/deployed",
        )
        if refused and request.headers.get("POLY_API_KEY") == self.refused_key:
            if path != "/order" or request.method != "POST":
                self.requests.append(request)
            status, body = self.refusal
            return httpx.Response(status, json=body, request=request)
        if request.method == "POST" and path == "/order":
            return httpx.Response(200, json=self.posted, request=request)
        if request.method == "GET" and path == f"/data/order/{_ORDER_ID}":
            self.requests.append(request)
            return httpx.Response(200, json=_OPEN_ORDER, request=request)
        if request.method == "DELETE" and path == "/order":
            self.requests.append(request)
            assert json.loads(request.content) == {"orderID": _ORDER_ID}
            body = {"canceled": [_ORDER_ID], "not_canceled": {}}
            return httpx.Response(200, json=body, request=request)
        if request.method == "GET" and path == "/book":
            self.requests.append(request)
            return httpx.Response(200, json=self.book, request=request)
        if request.method == "GET" and path == "/data/orders":
            self.requests.append(request)
            body = {"data": self.open_orders, "next_cursor": "LTE="}
            return httpx.Response(200, json=body, request=request)
        return super().send(request)


def _clob_script(name: str):
    """Import a skill script that trades through the SDK client.

    The script and the remote signer it builds its client with must stand on
    polymarket-client alone.
    """
    _remote_signer()
    path = _SCRIPTS / f"{name}.py"
    assert not _PY_CLOB_IMPORT.search(path.read_text(encoding="utf-8")), (
        f"{name}.py still imports py_clob_client_v2; it must call "
        "polymarket-client==0.13.0"
    )
    # loaded under its own name: connect-pons' scripts, first on sys.path in
    # the shared conftest, have a trade.py of their own
    spec = importlib.util.spec_from_file_location(f"connect_polymarket_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def clob(tmp_path, monkeypatch, _no_local_keys):
    """Return a workspace with cached creds and a DW, its CLOB faked over HTTP."""
    server = _ConnectServer()
    cs = _connect_signer(tmp_path, monkeypatch, server)
    http = _ClobHttp(cs, open_orders=[])
    monkeypatch.setattr(
        httpx.Client, "send", lambda self, request, **kwargs: http.send(request)
    )
    monkeypatch.setattr(deposit_wallet, "_resolve_dw", lambda cs: _AGENT_DW)
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [{"version": pm.SUPPORTED_MARKET_VERSION}],
    )
    http.server = server
    return http


def _printed_json(out: str):
    """Parse what a command printed as its result."""
    return json.loads(out)


def _mentions(value, needle: str) -> bool:
    """Whether a parsed JSON value holds `needle` as one of its strings."""
    if isinstance(value, dict):
        return any(_mentions(v, needle) for v in value.values())
    if isinstance(value, list):
        return any(_mentions(v, needle) for v in value)
    return isinstance(value, str) and value.lower() == needle.lower()


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_limit_buy_posts_the_signed_order_once(clob, capsys) -> None:
    """`trade.py limit` BUY signs on the SDK and posts one GTC order.

    The order is the one the signer test pins (BUY 10 at 0.50 on the current
    exchange), so its signature is the golden. The buy's recovery hint is in
    the workspace before the order leaves, and resolved once it is accepted.
    The command prints the CLOB's answer as a JSON object.
    """
    trade = _clob_script("trade")
    trade.cmd_limit(clob.cs, _V1_TOKEN, "buy", 0.5, 10.0, "gtc", None)

    (posted,) = clob.orders
    assert posted["orderType"] == "GTC"
    assert posted["owner"] == _CACHED_CREDS["api_key"]
    order = posted["order"]
    assert to_checksum_address(order["maker"]) == _AGENT_DW
    assert to_checksum_address(order["signer"]) == _AGENT_DW
    assert str(order["tokenId"]) == _V1_TOKEN
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        "5000000",
        "10000000",
    )
    assert str(order["side"]).upper() in ("BUY", "0")
    assert int(order["signatureType"]) == 3
    assert str(order["expiration"]) == "0"
    assert order["signature"] == _V1_GOLDEN_SIGNATURE
    assert clob.server.digests == [_V1_GOLDEN_DIGEST]

    (before,) = clob.state_at_post
    token = int(_V1_TOKEN)
    assert token in before["dw_open_tokens"]
    assert pm._dw_pending_buy_counts(before) == {token: 1}  # noqa: SLF001
    after = pm.load_state(clob.cs)
    assert token in after["dw_open_tokens"]
    assert pm._dw_pending_buy_counts(after) == {}  # noqa: SLF001
    assert after["clob_creds"] == _CACHED_CREDS

    printed = _printed_json(capsys.readouterr().out)
    assert isinstance(printed, dict)
    assert _mentions(printed, _ORDER_ID)


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_limit_sell_gtd_carries_its_expiry_and_no_buy_hint(clob, capsys) -> None:
    """`trade.py limit` SELL GTD signs a sell expiring --expires-in from now.

    A sell is not a buy: no recovery hint is written for it.
    """
    trade = _clob_script("trade")
    start = int(time.time())
    trade.cmd_limit(clob.cs, _V1_TOKEN, "sell", 0.42, 7.0, "gtd", 3600)
    end = int(time.time())

    (posted,) = clob.orders
    assert posted["orderType"] == "GTD"
    order = posted["order"]
    assert to_checksum_address(order["maker"]) == _AGENT_DW
    assert str(order["tokenId"]) == _V1_TOKEN
    # a SELL gives 7 shares for 7 x 0.42 pUSD
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        "7000000",
        "2940000",
    )
    assert str(order["side"]).upper() in ("SELL", "1")
    assert start + 3600 <= int(order["expiration"]) <= end + 3600
    assert int(order["signatureType"]) == 3
    (digest,) = clob.server.digests
    owner_signature = _hex_bytes(order["signature"])[:65]
    assert Account._recover_hash(_hex_bytes(digest), signature=owner_signature) == (
        _AGENT_EOA
    )

    state = pm.load_state(clob.cs)
    assert not state.get("dw_open_tokens")
    assert pm._dw_pending_buy_counts(state) == {}  # noqa: SLF001
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_rejected_buy_reports_the_clob_and_drops_its_marker(clob, capsys) -> None:
    """A buy the CLOB answers with ``success: false`` ends with its reason.

    The pending marker written before the post is resolved, as for any
    definitive answer, and the order is not posted a second time.
    """
    trade = _clob_script("trade")
    reason = "not enough balance / allowance"
    clob.posted = {
        "success": False,
        "errorMsg": reason,
        "orderID": "",
        "status": "",
        "makingAmount": "",
        "takingAmount": "",
    }
    with pytest.raises(SystemExit) as rejected:
        trade.cmd_limit(clob.cs, _V1_TOKEN, "buy", 0.5, 10.0, "gtc", None)
    printed = capsys.readouterr()
    assert reason in " ".join([str(rejected.value.code), printed.out, printed.err])
    assert rejected.value.code not in (None, 0)
    assert len(clob.orders) == 1
    token = int(_V1_TOKEN)
    assert pm._dw_pending_buy_counts(clob.state_at_post[0]) == {
        token: 1
    }  # noqa: SLF001
    assert pm._dw_pending_buy_counts(pm.load_state(clob.cs)) == {}  # noqa: SLF001


def test_trade_order_status_and_cancel_go_through_the_sdk(clob, capsys) -> None:
    """`trade.py order` reads one order and `trade.py cancel` cancels it, by id."""
    trade = _clob_script("trade")

    trade.cmd_order(clob.cs, _ORDER_ID)
    status = _printed_json(capsys.readouterr().out)
    assert isinstance(status, dict)
    assert _mentions(status, _ORDER_ID)

    trade.cmd_cancel(clob.cs, _ORDER_ID)
    cancelled = _printed_json(capsys.readouterr().out)
    assert isinstance(cancelled, dict)
    assert _mentions(cancelled, _ORDER_ID)

    order_calls = [c for c in clob.calls if c[1] not in ("/auth/api-keys", "/deployed")]
    assert order_calls == [
        ("GET", f"/data/order/{_ORDER_ID}"),
        ("DELETE", "/order"),
    ]
    assert clob.server.requests == []  # reads and cancels sign nothing


def test_sweep_refuses_while_orders_rest_against_the_dw(clob) -> None:
    """The open-orders check behind `funds.py sweep` reads the CLOB on the SDK.

    No open order lets the sweep go on; one names the order and refuses; a
    CLOB that cannot be read refuses too, rather than sweeping blind.
    """
    _remote_signer()

    assert funds._abort_if_open_orders(clob.cs, _AGENT_DW) is None
    assert ("GET", "/data/orders") in clob.calls

    other_id = "0x" + "0f" * 32
    clob.open_orders = [_OPEN_ORDER, dict(_OPEN_ORDER, id=other_id)]
    with pytest.raises(SystemExit, match=r"2 open CLOB order\(s\)") as refused:
        funds._abort_if_open_orders(clob.cs, _AGENT_DW)
    assert f"({_ORDER_ID}, {other_id})" in str(refused.value)

    clob.open_orders = "not a list"
    with pytest.raises(SystemExit, match="could not verify open CLOB orders"):
        funds._abort_if_open_orders(clob.cs, _AGENT_DW)


def test_sweep_names_the_first_five_open_orders(clob) -> None:
    """More than five open orders: the refusal counts them all, names five."""
    _remote_signer()
    ids = ["0x" + f"{n:02x}" * 32 for n in range(1, 7)]
    clob.open_orders = [dict(_OPEN_ORDER, id=order_id) for order_id in ids]

    with pytest.raises(SystemExit) as refused:
        funds._abort_if_open_orders(clob.cs, _AGENT_DW)

    message = str(refused.value)
    assert message.startswith(
        f"6 open CLOB order(s) rest against the DW ({', '.join(ids[:5])}) "
    )
    assert ids[5] not in message


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_market_buy_spends_the_usd_asked_for(clob, monkeypatch, capsys) -> None:
    """`trade.py buy` signs a FOK market BUY of exactly --usd and posts it once.

    The DW holds far more pUSD than the buy and the market charges no fee, so
    nothing is held back: 7.30 pUSD at the 0.50 ask buys 14.6 shares. The recovery
    hint is in place before the post and resolved after it.
    """
    trade = _clob_script("trade")
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: 500_000_000)

    trade.cmd_buy(clob.cs, _V1_TOKEN, 7.3, "fok")

    (posted,) = clob.orders
    assert posted["orderType"] == "FOK"
    order = posted["order"]
    assert to_checksum_address(order["maker"]) == _AGENT_DW
    assert str(order["tokenId"]) == _V1_TOKEN
    assert str(order["side"]).upper() in ("BUY", "0")
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        "7300000",
        "14600000",
    )
    token = int(_V1_TOKEN)
    assert pm._dw_pending_buy_counts(clob.state_at_post[0]) == {
        token: 1
    }  # noqa: SLF001
    assert pm._dw_pending_buy_counts(pm.load_state(clob.cs)) == {}  # noqa: SLF001
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_market_sell_moves_the_shares_asked_for(clob, capsys) -> None:
    """`trade.py sell` signs a FAK market SELL of exactly --shares, no buy hint."""
    trade = _clob_script("trade")

    trade.cmd_sell(clob.cs, _V1_TOKEN, 12.5, "fak")

    (posted,) = clob.orders
    assert posted["orderType"] == "FAK"
    order = posted["order"]
    assert to_checksum_address(order["maker"]) == _AGENT_DW
    assert str(order["tokenId"]) == _V1_TOKEN
    assert str(order["side"]).upper() in ("SELL", "1")
    # 12.5 shares at the 0.40 bid
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        "12500000",
        "5000000",
    )
    assert not pm.load_state(clob.cs).get("dw_open_tokens")
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)


# A market that charges a taker fee: rate 0.25 at exponent 2, priced off the
# 0.50 midpoint (asks at 0.30), so p * (1 - p) differs from every nearby
# expression. py-clob-client-v2==1.0.2, the SDK the skill used before, sized
# each market buy below from the same rate, exponent, book and balance; its
# results are the literal amounts these tests pin.
_FEE_RATE = Decimal("0.25")
_FEE_EXPONENT = Decimal(2)
_FEE_BOOK = dict(_BOOK, asks=[{"price": "0.3", "size": "1000"}])


def _fee_market(monkeypatch, clob, rate=_FEE_RATE, exponent=_FEE_EXPONENT) -> None:
    """Answer the SDK's market lookups with a fee-charging market at a 0.30 ask."""
    market = MarketInfo(
        fee_info=PlatformFeeInfo(rate=rate, exponent=exponent),
        neg_risk=False,
        tick_size=Decimal("0.01"),
        token_ids=frozenset({_V1_TOKEN, _V2_TOKEN}),
    )
    monkeypatch.setattr(
        sdk_order_cache, "fetch_market_info_sync", lambda ctx, condition_id: market
    )
    clob.book = _FEE_BOOK


@pytest.mark.parametrize(
    ("usd", "balance_units", "maker_amount", "taker_amount"),
    [
        # the balance covers the buy and its fee: the whole --usd is spent
        (10.0, 500_000_000, "10000000", "33333300"),
        # a balance of exactly --usd spends --usd less the fee (0.3675)
        (10.0, 10_000_000, "9630000", "32100000"),
        # short of --usd: the fee is charged on the balance, then held back
        (10.0, 9_500_000, "9150000", "30500000"),
        # exactly --usd plus its fee (2.03203) is still held back from
        (1.96, 2_032_030, "1950000", "6500000"),
        # one base unit more covers it, and the whole --usd is spent
        (1.96, 2_032_031, "1960000", "6533300"),
    ],
)
@pytest.mark.usefixtures("_fixed_orders")
def test_trade_market_buy_holds_back_the_taker_fee(
    clob, monkeypatch, capsys, usd, balance_units, maker_amount, taker_amount
) -> None:
    """`trade.py buy` sizes a fee-charging buy exactly as the old SDK did.

    The fee rate is ``rate * (p * (1 - p)) ** exponent`` at the fill price p,
    charged on what the buy spends, in shares: min(--usd, balance) / p times
    the rate. A balance above --usd plus that fee spends --usd; any other
    balance spends what is left of it once the fee is held back.
    """
    trade = _clob_script("trade")
    _fee_market(monkeypatch, clob)
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: balance_units)

    trade.cmd_buy(clob.cs, _V1_TOKEN, usd, "fok")

    (posted,) = clob.orders
    order = posted["order"]
    assert str(order["tokenId"]) == _V1_TOKEN
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        maker_amount,
        taker_amount,
    )
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)


@pytest.mark.parametrize(
    ("rate", "exponent", "usd", "balance", "spend"),
    [
        (_FEE_RATE, _FEE_EXPONENT, 10.0, 500.0, 10.0),
        (_FEE_RATE, _FEE_EXPONENT, 10.0, 10.0, 9.6325),
        (_FEE_RATE, _FEE_EXPONENT, 10.0, 9.5, 9.150875),
        (_FEE_RATE, _FEE_EXPONENT, 10.0, 0.2, 0.19265000000000002),
        # the balance is exactly --usd plus the fee: the fee is still held back
        (_FEE_RATE, _FEE_EXPONENT, 1.96, 2.03203, 1.9599999999999997),
        (_FEE_RATE, _FEE_EXPONENT, 1.96, 2.032031, 1.96),
        (Decimal("0.0175"), Decimal(1), 10.0, 10.0, 9.8775),
        # a fee larger than the balance spends nothing, never a negative amount
        (Decimal("0.5"), Decimal(0), 10.0, 0.2, 0.0),
    ],
)
@pytest.mark.usefixtures("_fixed_orders")
def test_buy_sizing_matches_the_old_sdk(
    clob, monkeypatch, rate, exponent, usd, balance, spend
) -> None:
    """The client's buy sizing returns, to the bit, what the old SDK returned.

    `pm.quote_buy` and `trade.py buy` both size through it, so a quote, the
    preflight and the order agree only while this holds.
    """
    remote_signer = _remote_signer()
    _fee_market(monkeypatch, clob, rate, exponent)
    client = remote_signer.make_clob_client(clob.cs, _AGENT_DW)
    price = client.calculate_market_price(_V1_TOKEN, pm.BUY_SIDE, usd, "FOK")
    assert price == 0.3
    # pylint: disable-next=protected-access
    sized = client._adjust_buy_amount_for_balance(  # noqa: SLF001
        _V1_TOKEN, usd, price, balance, None
    )
    assert sized == spend


@pytest.mark.usefixtures("_fixed_orders")
def test_trade_quote_prices_the_taker_fee(clob, monkeypatch, capsys) -> None:
    """`trade.py quote` reports the fee and the top-up a short balance needs."""
    trade = _clob_script("trade")
    _fee_market(monkeypatch, clob)
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: 9_500_000)

    trade.cmd_quote(clob.cs, _V1_TOKEN, 10.0, "fok")

    quote = _printed_json(capsys.readouterr().out)
    assert quote["fill_price"] == 0.3
    assert quote["estimated_shares"] == 33.333333
    assert quote["estimated_fee_usd"] == 0.3675
    assert quote["required_dw_balance_usd"] == 10.3675
    assert quote["shortfall_usd"] == 0.8675
    assert quote["spendable_now_usd"] == 9.150875
    assert quote["blocked"] is False
    assert clob.orders == []


_NOT_REPLAY_SAFE = "not attempted automatically: operation is not replay-safe"


@pytest.mark.parametrize(
    ("status", "reason", "definitive"),
    [
        (401, "Unauthorized/Invalid api key", True),
        (403, "unauthorized: api key revoked", False),
    ],
)
@pytest.mark.usefixtures("_fixed_orders")
def test_trade_auth_rejected_buy_is_never_posted_twice(
    clob, capsys, status, reason, definitive
) -> None:
    """A buy the CLOB refuses for its credentials is not retried automatically.

    The creds are cleared so an operator's retry derives fresh ones, and the
    command exits 1 saying why it did not retry. Only a 401 proves nothing was
    submitted, so only a 401 resolves the pending marker; any other auth
    refusal keeps it and warns that the outcome may be ambiguous.
    """
    trade = _clob_script("trade")
    clob.refused_key = _CACHED_CREDS["api_key"]
    clob.refusal = (status, {"error": reason})

    with pytest.raises(SystemExit) as exited:
        trade.cmd_limit(clob.cs, _V1_TOKEN, "buy", 0.5, 10.0, "gtc", None)

    assert exited.value.code == 1
    assert len(clob.orders) == 1
    assert clob.server.digests == [_V1_GOLDEN_DIGEST]  # one order, nothing derived
    assert clob.derivations() == []
    state = pm.load_state(clob.cs)
    assert "clob_creds" not in state
    token = int(_V1_TOKEN)
    pending = {} if definitive else {token: 1}
    assert pm._dw_pending_buy_counts(state) == pending  # noqa: SLF001
    printed = _printed_json(capsys.readouterr().out)
    assert printed["retry"] == _NOT_REPLAY_SAFE
    assert reason in printed["error"]
    assert ("warning" in printed) is not definitive


def test_trade_prints_a_clob_refusal_as_its_error(clob, capsys) -> None:
    """A refusal that is not about credentials prints ``{"error": ...}``, exit 1.

    The cached creds stay: nothing about the refusal says they are stale.
    """
    trade = _clob_script("trade")
    clob.refused_key = _CACHED_CREDS["api_key"]
    clob.refusal = (400, {"error": "order lookup refused"})

    with pytest.raises(SystemExit) as exited:
        trade.cmd_order(clob.cs, _ORDER_ID)

    assert exited.value.code == 1
    printed = _printed_json(capsys.readouterr().out)
    assert list(printed) == ["error"]
    assert "order lookup refused" in printed["error"]
    assert clob.derivations() == []
    assert pm.load_state(clob.cs)["clob_creds"] == _CACHED_CREDS


def test_trade_prints_the_retry_s_refusal_as_its_error(clob, capsys) -> None:
    """A cancel refused again on re-derived creds prints that second refusal.

    The CLOB issues the same key it refused, so the one retry the replay-safe
    cancel gets is refused too: the command prints ``{"error": ...}`` for it
    and exits 1, without a third attempt.
    """
    trade = _clob_script("trade")
    clob.refused_key = _CACHED_CREDS["api_key"]
    clob.refusal = (401, {"error": "request rejected"})
    clob.issued = {
        "apiKey": _CACHED_CREDS["api_key"],
        "secret": _CACHED_CREDS["api_secret"],
        "passphrase": _CACHED_CREDS["api_passphrase"],
    }

    with pytest.raises(SystemExit) as exited:
        trade.cmd_cancel(clob.cs, _ORDER_ID)

    assert exited.value.code == 1
    cancels = [
        r for r in clob.requests if (r.method, r.url.path) == ("DELETE", "/order")
    ]
    assert len(cancels) == 2
    assert len(clob.derivations()) == 1
    printed = _printed_json(capsys.readouterr().out)
    assert list(printed) == ["error"]
    assert "request rejected" in printed["error"]


def test_trade_auth_failed_cancel_rederives_and_retries_once(clob, capsys) -> None:
    """A cancel refused with 401 retries once, on freshly derived creds.

    Cancelling is replay-safe, so the stale creds are dropped, new ones are
    derived through Connect and kept, and the cancel is sent once more. The
    401 alone marks the failure as an auth one, whatever its message says.
    """
    trade = _clob_script("trade")
    clob.refused_key = _CACHED_CREDS["api_key"]
    clob.refusal = (401, {"error": "request rejected"})
    clob.issued = {
        "apiKey": "derived-key",
        "secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
        "passphrase": "derived-passphrase",  # nosec B105
    }
    clob.active = ["derived-key"]

    trade.cmd_cancel(clob.cs, _ORDER_ID)

    cancels = [
        r.headers.get("POLY_API_KEY")
        for r in clob.requests
        if (r.method, r.url.path) == ("DELETE", "/order")
    ]
    assert cancels == [_CACHED_CREDS["api_key"], "derived-key"]
    assert len(clob.derivations()) == 1
    assert len(clob.server.requests) == 1  # the ClobAuth signature, nothing else
    assert pm.load_state(clob.cs)["clob_creds"] == {
        "api_key": "derived-key",
        "api_secret": "ZGVyaXZlZC1zZWNyZXQ=",  # nosec B105
        "api_passphrase": "derived-passphrase",  # nosec B105
    }
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)


# --- trade.py keeps the CLOB's own answer --------------------------------------------

# Polymarket documents "unmatched" as an order that "was marketable but failed
# to delay. Placement still succeeded." (docs.polymarket.com, create order).
_UNMATCHED = dict(_ACCEPTED, status="unmatched")
_MATCHED = dict(
    _ACCEPTED,
    status="matched",
    makingAmount="5",
    takingAmount="10",
    tradeIDs=["2c7f5e1a-4b9d-4e3a-8f61-0d2b7c9e5a14"],
    transactionsHashes=["0x" + "ab" * 32],
)


def _exit_code(command):
    """Run `command`; return the code it exited with, or None if it returned."""
    try:
        command()
    except SystemExit as exited:
        return exited.code
    return None


def _printed_reply(out: str) -> dict:
    """Parse the one JSON object a command printed as its result."""
    assert out.strip(), "the command printed nothing"
    printed = json.loads(out)
    assert isinstance(printed, dict)
    return printed


def _trade_command(trade, cs, command: str):
    """Return one of trade.py's order commands, bound to its fixed test order."""
    return {
        "buy": lambda: trade.cmd_buy(cs, _V1_TOKEN, 7.3, "fok"),
        "limit-buy": lambda: trade.cmd_limit(
            cs, _V1_TOKEN, "buy", 0.5, 10.0, "gtc", None
        ),
        "sell": lambda: trade.cmd_sell(cs, _V1_TOKEN, 12.5, "fak"),
        "limit-sell": lambda: trade.cmd_limit(
            cs, _V1_TOKEN, "sell", 0.42, 7.0, "gtc", None
        ),
    }[command]


@pytest.mark.parametrize("command", ["buy", "limit-buy"])
@pytest.mark.usefixtures("_fixed_orders")
def test_an_unmatched_buy_is_placed_and_keeps_its_hint(
    clob, monkeypatch, capsys, command
) -> None:
    """A buy answered ``success: true, status: unmatched`` was placed.

    It is reported like any placed order: the command prints it and exits 0,
    and the recovery hint is resolved the way a placed buy's is, with the
    holdings hint kept. Only ``success: false`` is a rejection.
    """
    trade = _clob_script("trade")
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: 500_000_000)
    clob.posted = dict(_UNMATCHED)

    code = _exit_code(_trade_command(trade, clob.cs, command))

    out = capsys.readouterr().out
    assert code in (None, 0), f"an unmatched (placed) buy exited {code!r}"
    assert len(clob.orders) == 1
    token = int(_V1_TOKEN)
    assert pm._dw_pending_buy_counts(clob.state_at_post[0]) == {
        token: 1
    }  # noqa: SLF001
    after = pm.load_state(clob.cs)
    assert pm._dw_pending_buy_counts(after) == {}  # noqa: SLF001
    assert token in after["dw_open_tokens"]
    assert _mentions(_printed_reply(out), _ORDER_ID)


@pytest.mark.parametrize("reply", [_MATCHED, _UNMATCHED], ids=["matched", "unmatched"])
@pytest.mark.parametrize("command", ["buy", "limit-buy", "sell", "limit-sell"])
@pytest.mark.usefixtures("_fixed_orders")
def test_trade_prints_the_clob_s_order_reply_under_its_own_names(
    clob, monkeypatch, capsys, command, reply
) -> None:
    """A placed order prints what the CLOB answered, under the CLOB's names.

    The agent reads this output: ``orderID``, ``success``, ``status``,
    ``errorMsg``, ``makingAmount``, ``takingAmount`` and the rest keep the
    names and the values of the CLOB's own reply, as they always have.
    """
    trade = _clob_script("trade")
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: 500_000_000)
    clob.posted = dict(reply)

    code = _exit_code(_trade_command(trade, clob.cs, command))

    printed = _printed_reply(capsys.readouterr().out)
    assert {key: printed.get(key) for key in reply} == reply
    assert code in (None, 0)


def test_trade_order_and_cancel_print_the_clob_s_reply(clob, capsys) -> None:
    """`trade.py order` and `cancel` print the CLOB's reply under its own names.

    The order's fields are the CLOB's (``expiration``, ``created_at`` as the
    CLOB sent it, ``market``...), not a reshaped copy.
    """
    trade = _clob_script("trade")

    trade.cmd_order(clob.cs, _ORDER_ID)
    status = _printed_reply(capsys.readouterr().out)
    assert {key: status.get(key) for key in _OPEN_ORDER} == _OPEN_ORDER

    trade.cmd_cancel(clob.cs, _ORDER_ID)
    cancelled = _printed_reply(capsys.readouterr().out)
    assert cancelled == {"canceled": [_ORDER_ID], "not_canceled": {}}


# The 0.30 level holds 9.75 pUSD of shares: a 10 pUSD buy reaches the 0.31
# level behind it, but the same buy less its taker fee would not. CLOB books
# list asks from the worst price to the best.
_TWO_LEVEL_FEE_BOOK = dict(
    _BOOK,
    asks=[{"price": "0.31", "size": "1000"}, {"price": "0.3", "size": "32.5"}],
)


@pytest.mark.parametrize(
    ("balance_units", "maker_amount", "taker_amount"),
    [
        # 10 pUSD less the fee at 0.31 (9.6310225), still priced at 0.31
        (10_000_000, "9630000", "31064500"),
        # what is left of a 9.50 balance once that fee is held back (9.149...)
        (9_500_000, "9140000", "29483800"),
    ],
)
@pytest.mark.usefixtures("_fixed_orders")
def test_fee_held_back_buy_keeps_the_price_of_the_requested_amount(
    clob, monkeypatch, capsys, balance_units, maker_amount, taker_amount
) -> None:
    """A fee-held-back buy is priced once, for the --usd asked for.

    py-clob-client-v2==1.0.2 priced a market buy at the level the requested
    amount reaches, then held the fee back from the amount and built the
    order at that same price. Pricing the smaller amount again would move the
    order to a better level the requested amount does not fit in. The amounts
    are the ones that SDK signed for this book, fee and balance.
    """
    trade = _clob_script("trade")
    _fee_market(monkeypatch, clob)
    clob.book = _TWO_LEVEL_FEE_BOOK
    clob.cs._w3 = object()  # noqa: SLF001 - balance reads are stubbed below
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: balance_units)

    trade.cmd_buy(clob.cs, _V1_TOKEN, 10.0, "fok")

    (posted,) = clob.orders
    order = posted["order"]
    assert str(order["tokenId"]) == _V1_TOKEN
    assert (str(order["makerAmount"]), str(order["takerAmount"])) == (
        maker_amount,
        taker_amount,
    )
    assert _mentions(_printed_json(capsys.readouterr().out), _ORDER_ID)
