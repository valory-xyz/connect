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
(``polymarket-client``, layered on by tox -e unit-tests; without it this file
skips) against a stand-in for the Connect signer, so the signatures they check
are the SDK's own.
"""

# The skill modules are imported at runtime via a sys.path insert (they ship
# as bundled assets, not an installed package) and pull in the CLOB SDK —
# mypy can follow none of this, so skip the file.
# mypy: ignore-errors

import base64
import importlib.util
import json
import os
import re
import subprocess  # nosec B404 - runs the skill's own bootstrap script
import sys
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import get_args

import httpx
import pytest
import requests
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_defunct, encode_typed_data
from eth_account.signers.local import LocalAccount
from eth_keys import keys as eth_keys
from eth_utils import is_address, keccak, to_checksum_address

# Without the SDK this file skips, unless CONNECT_REQUIRE_SDK is set: tox's
# SDK run sets it, so a broken overlay fails there. See testenv:unit-tests.
if os.environ.get("CONNECT_REQUIRE_SDK"):
    importlib.import_module("polymarket")
else:
    pytest.importorskip("polymarket")

from polymarket import RequestRejectedError, SecureClient, TransportError  # noqa: E402
from polymarket._internal.actions.orders import cache as sdk_order_cache  # noqa: E402
from polymarket._internal.actions.orders import orders as sdk_orders  # noqa: E402
from polymarket._internal.actions.orders import post as sdk_post  # noqa: E402
from polymarket._internal.actions.orders.market import (  # noqa: E402
    adjust_buy_amount_for_fees,
)
from polymarket._internal.actions.orders.market_data import (  # noqa: E402
    MarketInfo,
    PlatformFeeInfo,
)
from polymarket._internal.l1_auth import build_api_key_auth_typed_data  # noqa: E402
from polymarket.models.clob.order_response import (  # noqa: E402
    OrderResponseErrorCode,
    RejectedOrder,
)
from web3.exceptions import ContractLogicError, TimeExhausted  # noqa: E402

from connect import workspace  # noqa: E402

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
# wrong constant there fails these tests instead of cancelling out.
_PUSD = "0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB"
_CTF = "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
_CTF_EXCHANGE = "0xE111180000d2663C0091e4f400237545B87B996B"
_NEG_RISK_CTF_EXCHANGE = "0xe2222d279d744050d28e00520010520000310F59"
_NEG_RISK_ADAPTER = "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296"
_EXCHANGE_V3 = "0xe3333700cA9d93003F00f0F71f8515005F6c00Aa"
_POSITION_MANAGER = "0x006F54F7f9A22e0000CC2AB60031000000ae9fEF"
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
    """All-missing yields 4 pUSD approvals and 4 operator grants (3 CTF, 1 V2)."""
    monkeypatch.setattr(pm, "erc20_allowance", lambda *a: 0)
    monkeypatch.setattr(pm, "is_approved_for_all", lambda *a: False)
    calls = pm.missing_approval_calls(None, ADDR_A)
    assert len(calls) == 8
    pusd_calls = [c for c in calls if c["target"] == pm.PUSD]
    ctf_calls = [c for c in calls if c["target"] == pm.CTF]
    position_calls = [c for c in calls if c["target"] == _POSITION_MANAGER]
    assert len(pusd_calls) == 4
    assert len(ctf_calls) == 3
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
    assert len(calls) == 3  # the three pUSD spenders that are NOT yet approved
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
    # own tests against the CLOB stand-in below.
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
    assert json.loads(capsys.readouterr().out) == {
        "redeemed": [{"status": 1}],
        "failed": 0,
    }


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
    # the approval set, named: the DW's three venues and the NegRiskAdapter
    # neg-risk orders need, not the two collateral adapters
    venues = {"CTFExchange", "NegRiskCTFExchange", "NegRiskAdapter", "ExchangeV3"}
    approvals = report["dw_trading_approvals"]
    assert set(approvals["pusd_allowances"].values()) == venues
    named = {name for section in approvals.values() for name in section.values()}
    assert named == venues


def test_constants_report_describes_the_protocol_v2_contracts() -> None:
    """The rows Protocol V2 adds, and the NegRiskAdapter still listed as granted."""
    rows = {c["name"]: c for c in pm.constants_report()["contracts"]}
    assert rows["ExchangeV3"]["address"] == _EXCHANGE_V3
    assert rows["PositionManager"]["address"] == _POSITION_MANAGER
    assert rows["NegRiskAdapter"]["address"] == _NEG_RISK_ADAPTER
    assert "no longer granted" not in rows["NegRiskAdapter"]["role"]


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


def _dw_holds(clob, monkeypatch, balance: float) -> None:
    """Make the DepositWallet hold `balance` pUSD."""
    clob.cs._w3 = object()  # noqa: SLF001 - the balance read is stubbed
    units = round(balance * 1_000_000)
    monkeypatch.setattr(pm, "erc20_balance_of", lambda w3, token, owner: units)


def _quote(usd: float, balance: float, price: float = 0.5) -> dict:
    """`pm.quote_buy` at `price`, sized by the SDK at 0.50 with a 3% taker fee."""
    fee = PlatformFeeInfo(rate=Decimal("0.015"), exponent=Decimal(0))

    def spend(funds: Decimal) -> Decimal:
        return adjust_buy_amount_for_fees(
            amount=Decimal(str(usd)), price=Decimal("0.5"), max_spend=funds, fee=fee
        )

    return pm.quote_buy("7", usd, balance, "FOK", price, spend)


def test_quote_surfaces_price_fee_shares_and_topup() -> None:
    """The numbers existed only inside the buy preflight's error message."""
    quote = _quote(10.0, 100.0)

    assert quote["fill_price"] == 0.5
    assert quote["estimated_shares"] == 20.0
    assert quote["estimated_fee_usd"] == pytest.approx(0.30, abs=1e-6)
    assert quote["required_dw_balance_usd"] == pytest.approx(10.30, abs=1e-6)
    assert quote["shortfall_usd"] == 0.0
    assert quote["spendable_now_usd"] == 10.0
    assert quote["blocked"] is False


def test_quote_names_the_exact_topup_when_the_balance_is_short() -> None:
    """shortfall_usd goes straight to `funds.py top-up --amount`."""
    quote = _quote(10.0, 4.0)
    assert quote["dw_balance_usd"] == 4.0
    assert quote["shortfall_usd"] == pytest.approx(6.30, abs=1e-6)


def test_quote_flags_the_dollar_minimum_that_breaks_small_bets() -> None:
    """A $1 bet on a $1 balance is fee-shrunk under the CLOB's minimum."""
    quote = _quote(1.0, 1.0)
    assert quote["spendable_now_usd"] < 1.0
    assert quote["blocked"] is True
    assert quote["shortfall_usd"] > 0


def test_a_bet_under_the_minimum_is_blocked_even_with_a_fat_balance() -> None:
    """A $0.50 order is affordable in full and still bounced by the venue.

    Comparing only the fee-shrunk figure to the minimum called this "fine":
    affordable == usd, so the old `affordable < usd` guard was false and the
    quote published a verdict the CLOB would reject.
    """
    quote = _quote(0.50, 100.0)

    assert quote["shortfall_usd"] == 0.0  # money is not the problem
    assert quote["blocked"] is True
    assert "raise it" in quote["blocked_reason"]
    assert "more pUSD will not help" in quote["blocked_reason"]


def test_a_fee_shrunk_bet_is_told_to_add_funds_not_to_raise_the_bet() -> None:
    """The two block causes need opposite fixes, so they must read differently."""
    quote = _quote(1.0, 1.0)

    assert quote["blocked"] is True
    assert "can be funded once the taker fee is held back" in quote["blocked_reason"]
    assert f"{quote['shortfall_usd']:.4f}" in quote["blocked_reason"]


def test_a_healthy_quote_has_no_blocked_reason() -> None:
    """`blocked_reason` is None exactly when the order would go through."""
    quote = _quote(10.0, 100.0)
    assert quote["blocked"] is False
    assert quote["blocked_reason"] is None


def test_quote_works_against_an_empty_deposit_wallet() -> None:
    """How much do I need? is the question an empty DW most needs answered.

    A balance of less than a cent is as good as empty.
    """
    quote = _quote(10.0, 0.0)
    assert quote["spendable_now_usd"] == 0.0
    assert quote["shortfall_usd"] == quote["required_dw_balance_usd"]
    dust = _quote(10.0, 0.004)
    assert dust["blocked"] is True
    assert dust["shortfall_usd"] == pytest.approx(quote["shortfall_usd"] - 0.004)


def test_quote_does_not_divide_by_a_zero_price() -> None:
    """An empty book must not turn a quote into a ZeroDivisionError."""
    quote = _quote(10.0, 50.0, price=0)
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
# The ready sentinel names the SDK pin, so a venv built for an older pin is not
# mistaken for a ready one. OLD_SENTINEL is what py-clob-client-v2 venvs carry.
SENTINEL = ".bootstrap-complete-polymarket-client-0.13.0"
OLD_SENTINEL = ".bootstrap-complete"


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


def _fake_venv(root: Path, complete: bool = True, built_by: str = "python3") -> Path:
    """Build a venv stub whose python answers the certifi query.

    `complete=False` reproduces a venv whose pip install died partway: the
    interpreter exists, the sentinel does not. Anything else is run by
    `built_by`, by default the `python3` on PATH, so the venv's version is that
    interpreter's.
    """
    venv = root / ".venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    python = venv / "bin" / "python"
    python.write_text(
        f'#!/bin/sh\ncase "$*" in *certifi*) echo /fake/cacert.pem ;;\n'
        f'*) exec "{built_by}" "$@" ;; esac\n',
        encoding="utf-8",
    )
    python.chmod(0o755)
    _fake_pip(venv)  # creation is gated on pip, so the stub needs one
    if complete:
        (venv / SENTINEL).touch()
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
    assert (venv / SENTINEL).is_file()


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
    assert not (venv / SENTINEL).exists()

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
    _fake_pip(elsewhere)  # without pip the bootstrap rebuilds the venv
    (elsewhere / SENTINEL).touch()

    result = _run_bootstrap(tmp_path, {"CONNECT_POLYMARKET_VENV": str(elsewhere)})

    assert result.returncode == 0, result.stderr
    assert f"export PY={python}" in result.stdout
    assert "reusing venv" in result.stderr


@requires_posix_shell
def test_bootstrap_emits_only_shell_assignments_on_stdout(tmp_path) -> None:
    """The stdout is eval'd, so a stray log line there would be executed."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    _fake_venv(tmp_path)

    result = _run_bootstrap(tmp_path)

    assert all(
        line.startswith("export ") for line in result.stdout.splitlines() if line
    )


# A `python3` stand-in that reports `version`: it answers `--version` and runs
# `-c` code under that `sys.version_info`, logs `-m venv` runs to `log`, gives
# an existing venv without pip one that logs there too, and on `--clear` drops
# its sentinels and makes itself its python. It refuses anything else, so a
# run that gets past the version check shows.
_PYTHON3 = """#!{executable}
import collections, os, sys
VERSION = "{version}"
if sys.argv[1] == "--version":
    print("Python " + VERSION)
elif sys.argv[1] == "-c":
    version_info = collections.namedtuple("version_info", "major minor micro")
    sys.version_info = version_info(*(int(part) for part in VERSION.split(".")))
    exec(sys.argv[2])
elif sys.argv[1:3] == ["-m", "venv"]:
    with open("{log}", "a") as log:
        print(*sys.argv[1:], file=log)
    venv = sys.argv[-1]
    if "--clear" in sys.argv:
        for name in os.listdir(venv):
            if name.startswith(".bootstrap-complete"):
                os.remove(os.path.join(venv, name))
        os.remove(os.path.join(venv, "bin", "python"))
        os.symlink(__file__, os.path.join(venv, "bin", "python"))
    pip = os.path.join(venv, "bin", "pip")
    if os.path.isdir(os.path.dirname(pip)) and not os.path.exists(pip):
        with open(pip, "w") as script:
            script.write('#!/bin/sh\\necho pip "$@" >> "{log}"\\n')
        os.chmod(pip, 0o755)
else:
    sys.exit("stand-in python3 will not run " + " ".join(sys.argv[1:]))
"""


def _python3(directory: Path, version: str, log: Path) -> Path:
    """Write the `python3` stand-in reporting `version` into `directory`."""
    directory.mkdir(exist_ok=True)
    python3 = directory / "python3"
    python3.write_text(
        _PYTHON3.format(executable=sys.executable, version=version, log=log)
    )
    python3.chmod(0o755)
    return python3


@requires_posix_shell
@pytest.mark.parametrize(
    ("on_path", "chosen", "venv_state"),
    [
        ("3.10.12", None, "pip"),
        ("3.11.0", None, "pip"),
        ("3.10.12", "3.10.12", "pip"),
        ("3.10.12", "3.11.0", "pip"),
        ("3.9.6", "3.10.12", "pip"),
        ("3.11.0", "3.10.12", "no pip"),
        ("3.10.12", None, "broken"),
    ],
)
def test_bootstrap_needs_python_3_11_and_rebuilds_old_sdk_venvs(
    tmp_path, on_path, chosen, venv_state
) -> None:
    """polymarket-client needs Python 3.11, and a venv made for the old SDK is rebuilt.

    The interpreter is CONNECT_PYTHON when set, else python3. Below 3.11 the
    bootstrap refuses before pip runs, naming the floor; on 3.11 it installs
    the pinned SDK, never py-clob-client-v2, under the new sentinel.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _fake_venv(tmp_path, complete=False)
    (venv / OLD_SENTINEL).touch()
    pip_log = tmp_path / "pip.log"
    (venv / "bin" / "pip").write_text(f'#!/bin/sh\necho "$@" >> "{pip_log}"\n')
    if venv_state == "no pip":  # pip installed nothing: the interpreter's floor
        (venv / "bin" / "pip").unlink()
    if venv_state == "broken":  # its base Python is gone, so it runs nothing
        (venv / "bin" / "python").write_text("#!/bin/sh\nexit 1\n")
    bin_dir = _python3(tmp_path / "bin", on_path, pip_log).parent
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    chosen_log = tmp_path / "chosen.log"
    if chosen:  # a path the refusal names must not run in the caller's eval
        chosen_dir = tmp_path / "chosen$(touch pwned)"
        env["CONNECT_PYTHON"] = str(_python3(chosen_dir, chosen, chosen_log))

    result = _run_bootstrap(tmp_path, env)

    if (chosen or on_path) == "3.10.12":
        assert result.returncode != 0
        assert not pip_log.exists()
        assert not chosen_log.exists()  # a refusal leaves the venv alone
        assert "export PY=" not in result.stdout
        evaled = subprocess.run(  # nosec B603 B607 - fixed argv, test input
            ["bash", "-c", result.stdout],
            cwd=str(tmp_path),
            capture_output=True,
            text=True,
            check=False,
        )
        assert evaled.returncode != 0
        assert not (tmp_path / "pwned").exists()
        assert "needs Python 3.11+" in evaled.stderr
        assert "Python 3.10.12" in evaled.stderr
    else:
        assert result.returncode == 0, result.stderr
        installs = pip_log.read_text(encoding="utf-8").split()
        assert "polymarket-client==0.13.0" in installs
        assert not [name for name in installs if "py-clob-client" in name]
        assert "venv" not in installs  # python3 neither built nor rebuilt it
        assert (venv / SENTINEL).is_file()
    if chosen == "3.11.0":
        # the venv python3 3.10 made is rebuilt by CONNECT_PYTHON, and once it
        # is ready a plain run from the skill's directory reuses it as it is,
        # however old python3 is
        assert chosen_log.read_text(encoding="utf-8") == f"-m venv --clear {venv}\n"
        nested = tmp_path / ".claude" / "skills" / "connect-polymarket"
        nested.mkdir(parents=True)
        again = _run_bootstrap(nested, {"PATH": env["PATH"]})
        assert again.returncode == 0, again.stderr
        assert "reusing venv" in again.stderr
        assert "venv" not in pip_log.read_text(encoding="utf-8").split()


@requires_posix_shell
@pytest.mark.parametrize("runnable", [True, False])
def test_bootstrap_creates_a_missing_venv_with_connect_python(
    tmp_path, runnable
) -> None:
    """A fresh workspace gets its venv from CONNECT_PYTHON, not the older python3.

    A CONNECT_PYTHON that is there but runs no Python is refused as such.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    log = tmp_path / "chosen.log"
    chosen = _python3(tmp_path / "chosen", "3.11.0", log)
    if not runnable:
        chosen.write_text("#!/bin/sh\nexit 1\n")
    bin_dir = _python3(tmp_path / "bin", "3.10.12", tmp_path / "path.log").parent
    env = {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}

    result = _run_bootstrap(tmp_path, {**env, "CONNECT_PYTHON": str(chosen)})

    assert not (tmp_path / "path.log").exists()
    if runnable:
        assert "creating venv" in result.stderr
        assert log.read_text(encoding="utf-8") == f"-m venv {tmp_path / '.venv'}\n"
    else:
        evaled = subprocess.run(  # nosec B603 B607 - fixed argv, test input
            ["bash", "-c", result.stdout], capture_output=True, text=True, check=False
        )
        assert evaled.returncode != 0
        assert "not a runnable Python" in evaled.stderr
        assert not (tmp_path / ".venv").exists()


@requires_posix_shell
@pytest.mark.parametrize(
    ("built_with", "on_path", "has_pip", "ready", "rebuilt"),
    [
        ("3.10.12", "3.11.9", True, False, True),
        ("3.11.2", "3.11.9", True, False, False),
        ("3.12.0", "3.11.9", True, False, False),
        ("3.11.2", "3.10.12", True, False, False),
        ("3.12.0", "3.11.9", False, False, True),
        (None, "3.11.9", True, False, True),
        (None, "3.11.9", False, False, True),
        (None, "3.11.9", True, True, True),
    ],
)
def test_bootstrap_rebuilds_a_venv_another_python3_made(
    tmp_path, built_with, on_path, has_pip, ready, rebuilt
) -> None:
    """A venv an older python3 built is rebuilt before the install, not reused.

    A user who upgrades python3 to install the SDK must not stay stuck on the
    old venv, whose pip finds no polymarket-client for its Python. One built by
    the same or a newer minor version is installed into as it is, and the
    3.11 floor is then that venv's Python, not an older python3's. One without
    pip holds no install, so any other version rebuilds it. One whose Python
    runs nothing (built_with None) is rebuilt, ready or not; the ready one
    is a dangling link, as deleting its base Python leaves it.
    """
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    log = tmp_path / "commands.log"
    log.touch()
    old = str(_python3(tmp_path / "old", built_with, log)) if built_with else "false"
    venv = _fake_venv(tmp_path, complete=ready, built_by=old)
    if ready and not built_with:
        (venv / "bin" / "python").unlink()
        (venv / "bin" / "python").symlink_to(tmp_path / "gone" / "python3.12")
    (venv / OLD_SENTINEL).touch()
    (venv / "bin" / "pip").write_text(f'#!/bin/sh\necho pip "$@" >> "{log}"\n')
    if not has_pip:
        (venv / "bin" / "pip").unlink()
    bin_dir = _python3(tmp_path / "bin", on_path, log).parent

    result = _run_bootstrap(
        tmp_path, {"PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}
    )

    assert result.returncode == 0, result.stderr
    commands = log.read_text(encoding="utf-8").splitlines()
    venv_runs = [i for i, c in enumerate(commands) if c.startswith("-m venv")]
    rebuilds = [f"-m venv --clear {venv}"] if rebuilt else []
    assert [commands[i] for i in venv_runs] == rebuilds
    install = next(
        i for i, c in enumerate(commands) if "polymarket-client==0.13.0" in c
    )
    assert all(i < install for i in venv_runs)
    notice = f"rebuilding venv at {venv} with Python {on_path}"
    assert (notice in result.stderr) is rebuilt
    assert (venv / SENTINEL).is_file()


@requires_posix_shell
@pytest.mark.parametrize("built_with", ["3.10.12", None], ids=["older", "broken"])
def test_bootstrap_never_clears_a_directory_that_is_not_a_venv(
    tmp_path, built_with
) -> None:
    """A CONNECT_POLYMARKET_VENV with no pyvenv.cfg is refused, not rebuilt.

    `venv --clear` empties the directory, so a prefix that only looks like a
    venv the bootstrap would rebuild is named in the refusal and left as it is.
    """
    log = tmp_path / "commands.log"
    old = str(_python3(tmp_path / "old", built_with, log)) if built_with else "false"
    venv = _fake_venv(tmp_path / "prefix$(touch pwned)", complete=False, built_by=old)
    (venv / "pyvenv.cfg").unlink()
    (venv / "notes.txt").write_text("the operator's own file", encoding="utf-8")
    before = {p: p.read_bytes() for p in venv.rglob("*") if p.is_file()}
    bin_dir = _python3(tmp_path / "bin", "3.11.9", log).parent

    result = _run_bootstrap(
        tmp_path,
        {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "CONNECT_POLYMARKET_VENV": str(venv),
        },
    )

    assert result.returncode != 0
    evaled = subprocess.run(  # nosec B603 B607 - fixed argv, test input
        ["bash", "-c", result.stdout],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )
    assert evaled.returncode != 0
    assert str(venv) in evaled.stderr
    assert not (tmp_path / "pwned").exists()
    assert {p: p.read_bytes() for p in venv.rglob("*") if p.is_file()} == before


def test_workspace_gitignores_the_skill_venv() -> None:
    """A `git init` in the workspace must not be able to stage the venv."""
    assert ".venv/" in workspace.GITIGNORE_ENTRIES


def test_skill_no_longer_teaches_the_inverted_dns_rule() -> None:
    """Three identical IPs is the healthy result, and the doc must not say otherwise."""
    doc = (_SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert "one address for all three means" not in doc
    assert "Identical IP addresses across the three hosts are normal" in doc


def test_skill_names_the_interpreter_the_bootstrap_honours() -> None:
    """The documented fix for an old python3 must set the variable the script reads."""
    doc = (_SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")
    assert [
        line
        for line in doc.splitlines()
        if "CONNECT_PYTHON=" in line and "bootstrap_env.sh" in line
    ]


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

# (token, spender or operator) of each approval the DW needs: the pre-V2 set,
# which includes the NegRiskAdapter neg-risk orders need, and the V2 pair.
_V1_APPROVALS = (
    (_PUSD, _CTF_EXCHANGE),
    (_PUSD, _NEG_RISK_CTF_EXCHANGE),
    (_PUSD, _NEG_RISK_ADAPTER),
    (_CTF, _CTF_EXCHANGE),
    (_CTF, _NEG_RISK_CTF_EXCHANGE),
    (_CTF, _NEG_RISK_ADAPTER),
)
_V2_APPROVALS = ((_PUSD, _EXCHANGE_V3), (_POSITION_MANAGER, _EXCHANGE_V3))


def _approval_calls(approvals) -> list:
    """Return the exact calls granting `approvals`, spelled out byte by byte.

    pUSD gets approve(spender, MaxUint256), an ERC-1155 setApprovalForAll
    (operator, true), so a wrong selector, party, amount or flag fails here.
    """
    calls = []
    for token, party in approvals:
        word = "0" * 24 + party.removeprefix("0x").lower()
        if token == _PUSD:
            calls.append({"target": token, "data": "0x095ea7b3" + word + "f" * 64})
        else:
            calls.append(
                {"target": token, "data": "0xa22cb465" + word + "0" * 63 + "1"}
            )
    return sorted(calls, key=str)


def _approvals_on_chain(monkeypatch, granted: set) -> None:
    """Answer the DW's approval reads from `granted`, a set of (token, party)."""

    def allowance(w3, token, owner, spender):
        return _MAX_UINT256 if (token, spender) in granted else 0

    monkeypatch.setattr(pm, "erc20_allowance", allowance)
    monkeypatch.setattr(
        pm, "is_approved_for_all", lambda w3, t, o, op: (t, op) in granted
    )


def test_dw_setup_includes_v2_approvals(monkeypatch) -> None:
    """A fresh DW gets the V1 set, NegRiskAdapter included, and both V2 approvals.

    The pUSD approval to ExchangeV3 is MaxUint256: Polymarket's relayer
    refuses the whole batch for anything less.
    """
    _approvals_on_chain(monkeypatch, set())
    calls = pm.missing_approval_calls(None, DW_ADDR)
    assert sorted(calls, key=str) == _approval_calls(_V1_APPROVALS + _V2_APPROVALS)


def test_existing_wallet_gets_v2_approvals_once(monkeypatch) -> None:
    """A DW holding the pre-V2 set gets exactly the two V2 approvals, then none."""
    granted = set(_V1_APPROVALS)
    _approvals_on_chain(monkeypatch, granted)
    calls = pm.missing_approval_calls(None, DW_ADDR)
    assert sorted(calls, key=str) == _approval_calls(_V2_APPROVALS)
    granted.update(_V2_APPROVALS)  # the batch is mined
    assert pm.missing_approval_calls(None, DW_ADDR) == []


# --- relayer proxy errors keep the relayer's own words ----------------------------

# What Polymarket's relayer answered, through the proxy, to a bounded pUSD
# approval of ExchangeV3.
_RELAYER_REFUSAL = (
    '{"error":"call blocked: call[0] blocked: approve to exchange '
    '0xe3333700cA9d93003F00f0F71f8515005F6c00Aa must be MaxUint256"}'
)


class _RelayerCS:
    agent_eoa = _StubCS.agent_eoa

    @staticmethod
    def personal_sign(message: str) -> str:
        return "0x" + "11" * 65


def test_relayer_error_body_surfaced(monkeypatch) -> None:
    """A relayer proxy error names the call, the HTTP error, then the body.

    Only the body's first 500 characters, as a gateway can answer with a
    whole page; nothing after the error when no answer came at all.
    """
    answers = [(400, _RELAYER_REFUSAL), (502, "<html>" + "-" * 600), None]

    def answer(method, url, **kwargs):
        reply = answers.pop(0)
        if reply is None:
            raise requests.ConnectionError("proxy unreachable")
        response = requests.Response()
        response.status_code, response.url, response.reason = reply[0], url, "Nope"
        response._content = reply[1].encode()  # noqa: SLF001
        return response

    monkeypatch.setattr(requests, "request", answer)
    proxy = relayer_proxy.RelayerProxyClient(_RelayerCS(), "http://proxy.test")
    call = "Relayer proxy GET deployed failed:"
    url = "http://proxy.test/polymarket/relayer/deployed"
    for shown in (
        f"{call} 400 Client Error: Nope for url: {url}: {_RELAYER_REFUSAL}",
        f"{call} 502 Server Error: Nope for url: {url}: <html>" + "-" * 494,
        f"{call} proxy unreachable",
    ):
        with pytest.raises(relayer_proxy.RelayerProxyError) as failed:
            proxy.deployed(DW_ADDR)
        assert str(failed.value) == shown


# --- the CLOB client on the unified SDK --------------------------------------------

# A throwaway, publicly known test key, held only by the Connect stand-in, the
# way the Connect server is the only holder of the agent's key. Built before
# any test forbids creating keys.
_CONNECT_KEY = eth_keys.PrivateKey(
    bytes.fromhex("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318")
)
_AGENT_EOA = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
# The DepositWallet Polymarket's factory derives for _AGENT_EOA, its owner.
_AGENT_DW = "0xd2C50736787e5eeefA6c2E81496AE56d51D6b7B1"
_V1_TOKEN = (  # nosec B105 - an outcome token id, not a password
    "71321045679252212594626385532706912750332728571942532289631379312455583992563"
)
# A Protocol V2 position id: module 1, the reserved bits clear, outcome 0.
_V2_TOKEN = str(int("01" + "ab" * 18 + "00" * 13, 16))

# Captured from the code this replaces (py_clob_client_v2 1.0.2): the digest
# Connect signed, and its signature, for a GTC BUY of 10 _V1_TOKEN at 0.50,
# salt 123456789, timestamp 1_800_000_000_000 ms.
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
    b"Order(uint256 salt,address maker,address signer,uint256 tokenId,"
    b"uint256 makerAmount,uint256 takerAmount,uint8 side,uint8 signatureType,"
    b"uint256 timestamp,bytes32 metadata,bytes32 builder)"
)
_ORDER_ID = "0x" + "0e" * 32
_OPEN_ORDER = {  # one row of the CLOB's /data/orders, and its /data/order reply
    "id": _ORDER_ID,
    "market": "0x" + "cd" * 32,
    "asset_id": _V1_TOKEN,
    "owner": "cached-key",
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
}
_PLACED = {  # the CLOB's reply to a placed order
    "success": True,
    "errorMsg": "",
    "orderID": _ORDER_ID,
    "status": "live",
    "makingAmount": "",
    "takingAmount": "",
}
# Marketable but delayed: the order may still be placed, though the SDK reads
# the reply as a rejection with code "unmatched" and drops its order id.
_UNMATCHED = dict(_PLACED, status="unmatched")
_REFUSED = dict(
    _PLACED, success=False, errorMsg="not enough balance / allowance", orderID=""
)
# One level each side: asks at 0.50, bids at 0.40.
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


def _connect_sign(digest: bytes) -> str:
    """Sign a raw digest the way connect/signer.py does: unprefixed, v in {27, 28}."""
    sig = _CONNECT_KEY.sign_msg_hash(digest)
    return "0x" + sig.to_bytes()[:64].hex() + f"{sig.v + 27:02x}"


def _creds(key: str) -> dict:
    """Return API creds in the workspace's format, the secret base64 like a real one."""
    secret = base64.b64encode(key.encode()).decode()
    return {"api_key": key, "api_secret": secret, "api_passphrase": key + "-pass"}


def _issued(key: str) -> dict:
    """Return the same creds as the CLOB issues them."""
    return dict(zip(("apiKey", "secret", "passphrase"), _creds(key).values()))


class _Clob:
    """The SDK's HTTP endpoints and the Connect server, in process.

    Records every request and digest; each attribute set in __init__ is an answer.
    """

    def __init__(self, cs) -> None:
        """Bind the workspace; nothing issued, posted or refused yet."""
        self.cs, self.requests, self.digests = cs, [], []
        self.create, self.issued = 200, None
        self.orders, self.book, self.fee = [], _BOOK, (Decimal(0), Decimal(1))
        self.placed, self.order = _PLACED, _OPEN_ORDER
        self.pages, self.refused_key, self.refusal = {}, None, None

    def sign(self, path: str, payload: dict) -> dict:
        """Answer the Connect signer's ``POST /sign-message``: a digest, nothing else."""
        assert path == "/sign-message"
        assert set(payload) == {"digest"}
        digest = bytes.fromhex(str(payload["digest"]).removeprefix("0x"))
        self.digests.append("0x" + digest.hex())
        return {"signature": _connect_sign(digest)}

    def send(self, request: httpx.Request) -> httpx.Response:
        """Answer one SDK request."""
        self.requests.append(request)
        method, path = request.method, request.url.path

        def reply(body, status=200):
            return httpx.Response(status, json=body, request=request)

        if path == "/auth/api-key" and isinstance(self.create, Exception):
            raise self.create
        if path in ("/auth/api-key", "/auth/derive-api-key"):
            created = path.endswith("derive-api-key") or self.create == 200
            return reply(self.issued) if created else reply({}, self.create)
        if self.refused_key and request.headers.get("POLY_API_KEY") == self.refused_key:
            return reply(*self.refusal[::-1])
        if (method, path) == ("POST", "/order"):
            self.orders.append(json.loads(request.content)["order"])
            if isinstance(self.placed, Exception):
                raise self.placed
            if isinstance(self.placed, tuple):  # (status, body)
                return reply(*self.placed[::-1])
            return reply(self.placed)
        if (method, path) == ("DELETE", "/order"):
            assert json.loads(request.content) == {"orderID": _ORDER_ID}
            return reply({"canceled": [_ORDER_ID], "not_canceled": {}})
        if path == f"/data/order/{_ORDER_ID}":
            return reply(self.order)
        if path == "/book":
            return reply(self.book)
        return reply(self.pages[request.url.params.get("next_cursor", "MA==")])

    def calls(self, method: str, path: str) -> list:
        """Return the requests sent to one endpoint."""
        return [r for r in self.requests if (r.method, r.url.path) == (method, path)]


@pytest.fixture
def clob(tmp_path, monkeypatch) -> _Clob:
    """Return a workspace with cached creds and a DW, the SDK's network faked.

    Order salts and timestamps are fixed; any eth_account or eth_keys entry
    point that holds or uses a key fails the test.
    """

    def key_used(*args, **kwargs):
        raise AssertionError("key material was used in the skill's process")

    for name in (
        "create",
        "from_key",
        "_sign_hash",
        "sign_message",
        "unsafe_sign_hash",
    ):
        monkeypatch.setattr(Account, name, key_used)
    for cls in (LocalAccount, eth_keys.PrivateKey):
        monkeypatch.setattr(cls, "__init__", key_used)

    cs = pm.ConnectSigner("http://127.0.0.1:8716", "test-bearer", tmp_path)
    cs._info = {"agent_eoa": _AGENT_EOA}  # noqa: SLF001 - /wallet, pre-answered
    pm.save_state(cs, {"clob_creds": _creds("cached-key")})
    http = _Clob(cs)
    monkeypatch.setattr(cs, "_post", http.sign)
    monkeypatch.setattr(httpx.Client, "send", lambda self, r, **kw: http.send(r))
    monkeypatch.setattr(deposit_wallet, "_resolve_dw", lambda cs: _AGENT_DW)
    monkeypatch.setattr(
        pm, "http_get_json", lambda url, params=None: [{"version": "v1"}]
    )
    monkeypatch.setattr(sdk_orders, "_generate_salt", lambda: 123456789)
    monkeypatch.setattr(sdk_orders, "_current_timestamp_ms", lambda: 1_800_000_000_000)
    monkeypatch.setattr(
        sdk_order_cache, "resolve_condition_by_token_sync", lambda ctx, token_id: "0x"
    )
    monkeypatch.setattr(
        sdk_order_cache,
        "fetch_market_info_sync",
        lambda ctx, condition_id: MarketInfo(
            fee_info=PlatformFeeInfo(rate=http.fee[0], exponent=http.fee[1]),
            neg_risk=False,
            tick_size=Decimal("0.01"),
            token_ids=frozenset({_V1_TOKEN, _V2_TOKEN}),
        ),
    )
    return http


def _script(name: str):
    """Import a skill script under its own name (connect-pons has a trade.py too)."""
    path = _SCRIPTS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"connect_polymarket_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _domain_separator(version: str, exchange: str) -> bytes:
    """EIP-712 domain separator of a Polymarket exchange on Polygon."""
    domain_type = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [
                keccak(text=domain_type),
                keccak(text="Polymarket CTF Exchange"),
                keccak(text=version),
                137,
                exchange,
            ],
        )
    )


def test_remote_signer_signs_v1_and_v2_orders(clob) -> None:
    """Both order kinds sign through RemoteSigner, each on its own exchange.

    The V1 order is byte-identical to the old code's. Both carry the DW's
    POLY_1271 wrapping: the owner's signature over the order in the DW's
    TypedDataSign, the exchange's domain (V1: "2" on CTF Exchange; V2: "3" on
    ExchangeV3), the contents hash, and the Order type string and its length.
    """
    client = _script("remote_signer").make_clob_client(clob.cs, _AGENT_DW)
    v1 = client.create_limit_order(
        token_id=_V1_TOKEN, price="0.5", size="10", side="BUY"
    )
    v2 = client.create_limit_order(
        token_id=_V2_TOKEN, price="0.5", size="10", side="BUY"
    )

    assert (clob.digests[0], v1.signature) == (_V1_GOLDEN_DIGEST, _V1_GOLDEN_SIGNATURE)
    typed_data_sign = (
        b"TypedDataSign(Order contents,string name,string version,uint256 chainId,"
        b"address verifyingContract,bytes32 salt)" + _ORDER_TYPE
    )
    for order, digest, domain in (
        (v1, clob.digests[0], _domain_separator("2", _CTF_EXCHANGE)),
        (v2, clob.digests[1], _domain_separator("3", _EXCHANGE_V3)),
    ):
        signature = bytes.fromhex(order.signature.removeprefix("0x"))
        contents = signature[97:129]
        assert signature[65:97] == domain
        assert signature[129:] == _ORDER_TYPE + len(_ORDER_TYPE).to_bytes(2, "big")
        struct = abi_encode(
            ["bytes32"] * 4 + ["uint256", "address", "bytes32"],
            [
                keccak(typed_data_sign),
                contents,
                keccak(text="DepositWallet"),
                keccak(text="1"),
                137,
                _AGENT_DW,
                bytes(32),
            ],
        )
        assert digest == "0x" + keccak(b"\x19\x01" + domain + keccak(struct)).hex()
        assert signature[:65].hex() == _connect_sign(bytes.fromhex(digest[2:]))[2:]
        assert (order.maker, order.signer, order.signature_type) == (
            _AGENT_DW,
            _AGENT_DW,
            3,
        )


def test_no_private_key_in_process(clob) -> None:
    """The SDK holds a RemoteSigner, and every signature it gets is Connect's.

    With every key entry point failing the test (the `clob` fixture), its
    `address` is the agent EOA, and typed data and an EIP-191 message both
    reach Connect as a digest alone.
    """
    remote_signer = _script("remote_signer")
    held = remote_signer.make_clob_client(clob.cs, _AGENT_DW)._ctx.signer
    assert isinstance(held, remote_signer.RemoteSigner)
    assert held.address == _AGENT_EOA

    typed = build_api_key_auth_typed_data(
        address=_AGENT_EOA, chain_id=137, timestamp=1_800_000_000, nonce=0
    )
    typed_digest = _hash_eip191_message(encode_typed_data(full_message=typed))
    message_digest = keccak(b"\x19Ethereum Signed Message:\n5hello")
    for signed, digest in (
        (held.sign_typed_data(typed), typed_digest),
        (held.sign_message(encode_defunct(text="hello")), message_digest),
    ):
        assert "0x" + signed.signature.hex() == _connect_sign(digest)
    assert clob.digests == ["0x" + typed_digest.hex(), "0x" + message_digest.hex()]


def test_cached_api_credentials_reused(clob) -> None:
    """Workspace creds are reused as they are, with no request and no signature."""
    stored = pm.state_path(clob.cs).read_bytes()
    creds = _script("remote_signer").make_clob_client(clob.cs, _AGENT_DW).credentials
    assert (creds.key, creds.secret, creds.passphrase) == tuple(
        _creds("cached-key").values()
    )
    assert clob.requests == clob.digests == []
    assert pm.state_path(clob.cs).read_bytes() == stored


@pytest.mark.parametrize(
    "create",
    [200, 400, 500, httpx.ConnectError("connection reset by peer")],
    ids=["200", "400", "500", "no-answer"],
)
def test_first_credentials_derive_only_after_a_400_on_create(clob, create) -> None:
    """A workspace without creds creates them once, deriving only after a 400.

    The L1 auth is Connect's signature with nonce 0. Created or derived creds
    are kept beside the rest of the workspace state and reused next time; a
    500, or no answer at all, is an error that derives and keeps nothing.
    """
    clob.issued, clob.create = _issued("fresh-key"), create
    wallet = {"deposit_wallet": {"address": _AGENT_DW}}
    pm.save_state(clob.cs, wallet)
    make_clob_client = _script("remote_signer").make_clob_client
    issued = create in (200, 400)

    if issued:
        for _ in range(2):
            assert make_clob_client(clob.cs, _AGENT_DW).credentials.key == "fresh-key"
    else:
        with pytest.raises((RequestRejectedError, TransportError)):
            make_clob_client(clob.cs, _AGENT_DW)

    paths = ["/auth/api-key", "/auth/derive-api-key"][: 1 + (create == 400)]
    assert [r.url.path for r in clob.requests] == paths
    created = clob.requests[0]
    clob_auth = build_api_key_auth_typed_data(
        address=_AGENT_EOA,
        chain_id=137,
        timestamp=int(created.headers["POLY_TIMESTAMP"]),
        nonce=0,
    )
    digest = _hash_eip191_message(encode_typed_data(full_message=clob_auth))
    assert (created.headers["POLY_NONCE"], clob.digests[0]) == (
        "0",
        "0x" + digest.hex(),
    )
    assert created.headers["POLY_SIGNATURE"] == _connect_sign(digest)
    kept = {"clob_creds": _creds("fresh-key")} if issued else {}
    assert pm.load_state(clob.cs) == {**wallet, **kept}


# --- trade.py and funds.py on the unified SDK ---------------------------------------

_BUY, _LIMIT_BUY = ("buy", 10.0, "fok"), ("limit", "buy", 0.5, 10.0, "gtc", None)
_SELL, _LIMIT_SELL = ("sell", 12.5, "fak"), ("limit", "sell", 0.5, 10.0, "gtc", None)


def _run(clob, capsys, command) -> tuple:
    """Run one trade.py command; return its exit code and all it told the agent."""
    name, *args = command
    try:
        getattr(_script("trade"), f"cmd_{name}")(clob.cs, _V1_TOKEN, *args)
        code = None
    except SystemExit as e:
        code = e.code
    out = capsys.readouterr()
    return code, (out.out + out.err + str(code)).lower()


@pytest.mark.parametrize(
    ("command", "order_type", "amounts"),
    [
        (("limit", "sell", 0.42, 7.0, "gtd", 3600), "GTD", (7_000_000, 2_940_000)),
        (_SELL, "FAK", (12_500_000, 5_000_000)),
    ],
    ids=["limit-gtd", "market"],
)
def test_trade_sell_posts_one_order_and_prints_the_clob_s_reply(
    clob, capsys, command, order_type, amounts
) -> None:
    """A sell posts one signed order, prints its id and leaves no buy's marker."""
    start = int(time.time())
    code, told = _run(clob, capsys, command)

    (order,) = clob.orders
    assert (order["maker"], order["tokenId"], order["side"]) == (
        _AGENT_DW,
        _V1_TOKEN,
        "SELL",
    )
    assert (int(order["makerAmount"]), int(order["takerAmount"])) == amounts
    assert json.loads(clob.requests[-1].content)["orderType"] == order_type
    if order_type == "GTD":
        assert start + 3600 <= int(order["expiration"]) <= time.time() + 3600
    assert code is None
    assert _ORDER_ID.lower() in told
    assert "dw_open_tokens" not in pm.load_state(clob.cs)


def test_trade_buy_spends_what_the_sdk_sizes_for_the_balance(
    clob, monkeypatch, capsys
) -> None:
    """`trade.py buy` spends at most the DW's pUSD, sized by the SDK's own rules.

    A placed buy confirms its marker and keeps its holdings hint. `trade.py
    quote` reports the same spend without asking Connect to sign, even for an
    empty DW; dust is refused before anything is posted, naming the quote's
    top-up; and topping up by the quote's shortfall buys all of --usd, even at
    the buy's cent rounding.
    """
    trade = _script("trade")
    clob.fee = (Decimal("0.25"), Decimal(1))
    for balance, amounts in (
        (100.0, (10_000_000, 20_000_000)),
        (10.5, (9_330_000, 18_660_000)),  # covers --usd, not its fee
        (10.0, (8_880_000, 17_760_000)),
    ):
        _dw_holds(clob, monkeypatch, balance)
        assert _run(clob, capsys, _BUY)[0] is None
        order = clob.orders[-1]
        assert (int(order["makerAmount"]), int(order["takerAmount"])) == amounts
    assert pm.dw_open_tokens(clob.cs) == [int(_V1_TOKEN)]
    signed = len(clob.digests)
    trade.cmd_quote(clob.cs, _V1_TOKEN, 10.0, "fok")
    quote = json.loads(capsys.readouterr().out)
    assert len(clob.digests) == signed  # a quote asks Connect for no signature
    assert pm.dw_pending_buy_tokens(clob.cs) == []  # buys confirmed, quote left none
    assert 8.88 <= quote["spendable_now_usd"] < 8.89  # the buy's spend, to the cent
    assert 1.25 - 1e-6 <= quote["shortfall_usd"] <= 1.26
    for balance in (1.0, 0.004):  # under the minimum once the fee is held back
        _dw_holds(clob, monkeypatch, balance)
        trade.cmd_quote(clob.cs, _V1_TOKEN, 1.0, "fok")
        topup = json.loads(capsys.readouterr().out)["shortfall_usd"]
        with pytest.raises(SystemExit, match=f"{topup:.4f}.*`trade.py quote`"):
            trade.cmd_buy(clob.cs, _V1_TOKEN, 1.0, "fok")
    assert len(clob.orders) == 3
    _dw_holds(clob, monkeypatch, 0.0)
    trade.cmd_quote(clob.cs, _V1_TOKEN, 10.0, "fok")
    empty = json.loads(capsys.readouterr().out)
    assert empty["shortfall_usd"] == empty["required_dw_balance_usd"] > 10.0

    clob.fee = (Decimal("0.3489"), Decimal(2))
    clob.book = dict(_BOOK, asks=[{"price": "0.3", "size": "1000"}])
    _dw_holds(clob, monkeypatch, 6.727721)
    trade.cmd_quote(clob.cs, _V1_TOKEN, 36.46, "fok")
    shortfall = json.loads(capsys.readouterr().out)["shortfall_usd"]
    _dw_holds(clob, monkeypatch, 6.727721 + shortfall)
    trade.cmd_buy(clob.cs, _V1_TOKEN, 36.46, "fok")
    assert int(clob.orders[-1]["makerAmount"]) == 36_460_000


@pytest.mark.parametrize(
    ("command", "status", "error"),
    [
        (_BUY, 401, "expired"),
        (_LIMIT_BUY, 401, "expired"),
        (_SELL, 401, "expired"),
        (_BUY, 403, "Unauthorized"),
    ],
    ids=["buy", "limit-buy", "sell", "auth-message"],
)
def test_trade_auth_rejected_order_is_never_posted_twice(
    clob, monkeypatch, capsys, command, status, error
) -> None:
    """An order refused for its creds is not retried, and its creds go.

    A 401 is an auth failure whatever its message says, and proves no order,
    so a buy's marker goes too. An auth-looking refusal that is not a 401
    keeps the marker and the rest of the state, and says to reconcile.
    """
    _dw_holds(clob, monkeypatch, 100.0)
    clob.refused_key, clob.refusal = "cached-key", (status, {"error": error})
    clob.issued = _issued("fresh-key")  # a retry could post again
    name, *args = command

    with pytest.raises(SystemExit, match="^1$"):
        getattr(_script("trade"), f"cmd_{name}")(clob.cs, _V1_TOKEN, *args)

    ambiguous = status != 401
    warning = "submission outcome may be ambiguous; reconcile before retrying"
    assert json.loads(capsys.readouterr().out) == {
        "error": error,
        "retry": "not attempted automatically: operation is not replay-safe",
        **({"warning": warning} if ambiguous else {}),
    }
    assert len(clob.calls("POST", "/order")) == 1
    assert "clob_creds" not in pm.load_state(clob.cs)
    pending = [int(_V1_TOKEN)] if ambiguous else []
    assert pm.dw_pending_buy_tokens(clob.cs) == pending


def test_trade_buy_warns_when_its_placed_marker_cannot_be_confirmed(
    clob, monkeypatch, capsys
) -> None:
    """A placed buy is reported placed even if confirming its marker fails."""
    _dw_holds(clob, monkeypatch, 100.0)

    def disk_full(cs, token_id):
        raise OSError("disk full")

    monkeypatch.setattr(pm, "confirm_dw_buy_intent", disk_full)

    code, told = _run(clob, capsys, _BUY)

    assert code is None
    assert _ORDER_ID.lower() in told
    assert "the action itself succeeded" in told
    assert pm.dw_pending_buy_tokens(clob.cs) == [int(_V1_TOKEN)]


def test_trade_main_wires_the_quote_subcommand(clob, monkeypatch, capsys) -> None:
    """The CLI is the only way a quote runs in production, so parse it for real."""
    _dw_holds(clob, monkeypatch, 100.0)
    monkeypatch.setattr(pm.ConnectSigner, "from_workspace", lambda: clob.cs)
    argv = ["trade.py", "quote", "--token-id", _V1_TOKEN, "--usd", "10"]
    monkeypatch.setattr(sys, "argv", argv)

    _script("trade").main()

    quote = json.loads(capsys.readouterr().out)
    assert (quote["token_id"], quote["requested_usd"]) == (_V1_TOKEN, 10.0)
    assert quote["order_type"] == "FOK"


def test_trade_prints_the_clob_s_refusal_as_its_error(clob, capsys) -> None:
    """A refusal not about credentials prints ``{"error": ...}`` and exits 1."""
    clob.refused_key, clob.refusal = "cached-key", (400, {"error": "refused"})

    with pytest.raises(SystemExit, match="^1$"):
        _script("trade").cmd_order(clob.cs, _ORDER_ID)

    assert json.loads(capsys.readouterr().out) == {"error": "refused"}


def test_trade_order_and_cancel_print_the_clob_s_reply(clob, capsys) -> None:
    """`trade.py order` prints the order's id and status; `cancel` the CLOB's reply.

    A cancel or an order read, both replay-safe, refused with a bare 401 is
    retried once on re-derived creds, which are kept; a second refusal is
    printed. An order reply the SDK's model refuses (the null
    ``associate_trades`` the CLOB sends) prints an error and exits 1, quoting
    at most 500 characters.
    """
    trade = _script("trade")
    trade.cmd_order(clob.cs, _ORDER_ID)
    printed = capsys.readouterr().out
    assert _ORDER_ID in printed
    assert "LIVE" in printed
    clob.refused_key, clob.refusal = "cached-key", (401, {"error": "unauthorized"})
    clob.issued = _issued("fresh-key")
    trade.cmd_cancel(clob.cs, _ORDER_ID)
    assert json.loads(capsys.readouterr().out) == {
        "canceled": [_ORDER_ID],
        "not_canceled": {},
    }
    cancels = clob.calls("DELETE", "/order")
    assert [r.headers["POLY_API_KEY"] for r in cancels] == ["cached-key", "fresh-key"]
    assert pm.load_state(clob.cs)["clob_creds"] == _creds("fresh-key")
    clob.refused_key, clob.issued = "fresh-key", _issued("third-key")
    trade.cmd_order(clob.cs, _ORDER_ID)
    assert "LIVE" in capsys.readouterr().out
    assert pm.load_state(clob.cs)["clob_creds"] == _creds("third-key")

    clob.order = dict(_OPEN_ORDER, associate_trades=None, outcome="x" * 600)
    with pytest.raises(SystemExit, match="^1$"):
        trade.cmd_order(clob.cs, _ORDER_ID)
    printed = capsys.readouterr().out
    assert "error" in json.loads(printed)
    assert "x" * 501 not in printed

    clob.refused_key = "third-key"  # the re-derived key is refused too
    with pytest.raises(SystemExit, match="^1$"):
        trade.cmd_cancel(clob.cs, _ORDER_ID)
    assert json.loads(capsys.readouterr().out) == {"error": "unauthorized"}
    assert len(clob.calls("DELETE", "/order")) == 4


_UNREADABLE = {k: v for k, v in _PLACED.items() if k != "takingAmount"}


# the on-chain check for the order's own token, not the list that lags the chain
_UNCERTAIN = ("uncertain", f"--token-ids {_V1_TOKEN}")
_NO_FUNDS = ("not enough balance / allowance",)
# a refusal code a later SDK may add, which the script cannot know proves no order
_NEW_CODE = RejectedOrder.model_construct(code="new_code", message="new refusal")


def test_the_sdk_s_refusal_codes_are_all_classified() -> None:
    """Every code the SDK assigns but "unmatched" and "unknown" proves no order.

    An SDK bump that adds a code fails here until the code is classified.
    """
    refused = getattr(_script("trade"), "_REFUSED_CODES", ())
    assert set(get_args(OrderResponseErrorCode)) ^ set(refused) == {
        "unmatched",
        "unknown",
    }


@pytest.mark.parametrize(
    ("command", "reply", "told_of", "kept"),
    [
        (_BUY, _UNMATCHED, _UNCERTAIN, True),
        (_LIMIT_BUY, _UNMATCHED, _UNCERTAIN, True),
        (_SELL, _UNMATCHED, _UNCERTAIN, None),
        (_LIMIT_SELL, _UNMATCHED, _UNCERTAIN, None),
        # success: true with a status the SDK does not know: code "unknown"
        (_BUY, dict(_PLACED, status="pending"), _UNCERTAIN, True),
        (_BUY, _UNREADABLE, _UNCERTAIN, True),
        (_SELL, _UNREADABLE, _UNCERTAIN, None),
        (_BUY, _REFUSED, _NO_FUNDS, False),
        (_LIMIT_BUY, _REFUSED, _NO_FUNDS, False),
        (_BUY, httpx.ReadTimeout("read timed out"), _UNCERTAIN, True),
        (_BUY, (500, {"error": "internal"}), _UNCERTAIN, True),
        (_BUY, (408, {"error": "request timeout"}), ("request timeout",), True),
        (_BUY, _NEW_CODE, _UNCERTAIN, True),
    ],
    ids="unmatched unmatched-limit unmatched-sell unmatched-limit-sell odd-status "
    "unreadable unreadable-sell refused refused-limit timed-out 500 408 "
    "new-code".split(),
)
def test_only_a_refusal_code_proves_an_order_was_not_placed(
    clob, monkeypatch, capsys, command, reply, told_of, kept
) -> None:
    """Every outcome short of a placed order exits non-zero with its reason.

    "unmatched", a reply the SDK cannot classify ("unknown") or cannot read,
    no answer at all, or a 5xx may arrive after the CLOB has the order:
    placement is uncertain, and a buy keeps its pending marker. So does a
    408, or a refusal code the script does not know. Only a refusal code it
    knows, or a 401, proves no order, resolving the marker.
    """
    _dw_holds(clob, monkeypatch, 100.0)
    if reply is _NEW_CODE:
        monkeypatch.setattr(sdk_post, "normalize_order_response", lambda raw: _NEW_CODE)
        reply = _REFUSED
    clob.placed = reply

    code, told = _run(clob, capsys, command)

    assert code not in (None, 0)
    assert all(word in told for word in told_of)
    assert not re.search(r"positions --wallet dw(?! --token-ids)", told)
    if kept is not None:
        assert pm.dw_pending_buy_tokens(clob.cs) == ([int(_V1_TOKEN)] if kept else [])


_IDS = ["0x" + f"{n:02x}" * 32 for n in range(1, 7)]
_UNVERIFIED = "could not verify open CLOB orders before sweeping ("


def _page(data, next_cursor="LTE=") -> dict:
    """Return one page of the CLOB's open orders."""
    return {"data": data, "next_cursor": next_cursor}


@pytest.mark.parametrize(
    ("pages", "refusal"),
    [
        # six orders on later pages: counted, the first five named
        (
            {
                "MA==": _page([], "Mg=="),
                "Mg==": _page([dict(_OPEN_ORDER, id=i) for i in _IDS[:2]], "NA=="),
                "NA==": _page([dict(_OPEN_ORDER, id=i) for i in _IDS[2:]]),
            },
            f"6 open CLOB order(s) rest against the DW ({', '.join(_IDS[:5])}) ",
        ),
        # rows the SDK cannot read: one that is not an order, ids that are not
        # strings, the null trades the CLOB sends, a page that is not a list;
        # whatever the refusal quotes of them stops at 500 characters
        ({"MA==": _page([_OPEN_ORDER, "x" * 600])}, _UNVERIFIED),
        (
            {"MA==": _page([dict(_OPEN_ORDER, id=123), dict(_OPEN_ORDER, id=None)])},
            _UNVERIFIED,
        ),
        ({"MA==": _page([dict(_OPEN_ORDER, associate_trades=None)])}, _UNVERIFIED),
        ({"MA==": _page("x" * 600)}, _UNVERIFIED),
    ],
    ids=["six", "non-object-row", "non-string-ids", "null-trades", "oversized-page"],
)
def test_sweep_reads_every_page_of_open_orders_raw(clob, pages, refusal) -> None:
    """The open-orders check behind `funds.py sweep` reads every page.

    Orders on any page block the sweep. A reply the SDK cannot read refuses
    it too, rather than reading as no orders, and echoes no more than 500
    characters of what the CLOB sent.
    """
    clob.pages = pages

    with pytest.raises(SystemExit) as refused:
        funds._abort_if_open_orders(clob.cs, _AGENT_DW)

    assert str(refused.value).startswith(refusal)
    assert "x" * 501 not in str(refused.value)


@pytest.mark.parametrize("force", [False, True])
def test_sweep_reads_open_orders_unless_forced(clob, monkeypatch, force) -> None:
    """`funds.py sweep` goes ahead once the CLOB lists no open order.

    --force skips that read.
    """
    check = funds._abort_if_open_orders
    _sweep_mocks(monkeypatch, pusd=0, ctf_balance=0, recorded=[], indexed=[])
    monkeypatch.setattr(funds, "_abort_if_open_orders", check)
    monkeypatch.setattr(pm.ConnectSigner, "safe_address", SAFE_ADDR)
    clob.cs._w3 = object()  # noqa: SLF001 - the balance reads are stubbed
    clob.pages = {"MA==": _page([])}

    funds.cmd_sweep(clob.cs, None, force=force)

    assert len(clob.calls("GET", "/data/orders")) == (0 if force else 1)


_DIRECT_SENDS = (
    "approve_erc20",
    "approve_erc1155_for_all",
    "transfer_erc20",
    "setup_trading_approvals",
    "execute_transaction",
    "split_position",
    "merge_positions",
    "merge_multiple_positions",
    "redeem_positions",
    "execute_collateral_return_plan",
    "place_limit_order",
    "place_market_order",
    "post_orders",  # posts signed orders past the buy marker and market check
    "accept_combo_quote",
    "authorize_session_key",
    "revoke_session_key",
)


@pytest.mark.parametrize("method", _DIRECT_SENDS)
def test_client_refuses_the_sdk_s_direct_sends(clob, method) -> None:
    """The SDK client's own senders are closed: nothing is signed or sent.

    Each would sign through Connect and go straight to Polymarket, past the
    scripts' order flow or the relayer proxy.
    """
    assert callable(getattr(SecureClient, method))
    client = _script("remote_signer").make_clob_client(clob.cs, _AGENT_DW)

    with pytest.raises(Exception, match="outside Connect's relayer proxy"):
        getattr(client, method)()

    assert clob.requests == clob.digests == []


# --- Protocol V2 binary markets: find, trade, hold, move and claim ---------------

_ROUTER = "0x12121212006e4CD160D18e3f00711DA5c3372600"
_TRANSFER = "safeTransferFrom(address,address,uint256,uint256,bytes)"
_APPROVE_ALL = "setApprovalForAll(address,bool)"
_APPROVAL = "0xa22cb465"  # its selector
_ADAPTER_REDEEM = "redeemPositions(address,bytes32,bytes32,uint256[])"
# V1 ids whose top byte reads as a V2 module; reserved bit 40 marks them V1.
_V1_NO = str((2 << 248) | (1 << 40) | 9)


def _calldata(signature: str, *args) -> str:
    """Encode a call from its signature, independently of the skill's encoders."""
    types = signature[signature.index("(") + 1 : -1].split(",")
    return "0x" + (keccak(text=signature)[:4] + abi_encode(types, list(args))).hex()


def _market(slug: str, condition_id: str, **fields) -> dict:
    """Build an open Gamma V2 row: position id = condition id + outcome index."""
    base = int(condition_id, 16)
    return {
        "slug": slug,
        "conditionId": condition_id,
        "version": "v2",
        "positionIds": [str(base), str(base + 1)],
        "clobTokenIds": None,
        "outcomes": '["Yes", "No"]',
        "active": True,
        "closed": False,
        **fields,
    }


# Recorded V2 markets plus a synthetic combinatorial; an id's first byte is its module.
_V2_BINARY = _market(
    "polyv2bkbsl-cay-bur-2026-10-23",
    "0x01e64a3b41c057c976f9b5de07e357c99e000000000000000000000000000000",
    negRisk=None,
    volumeNum=500,
)
_UNTRADEABLE = (
    _market(
        "polyv2-central-park-high-59f-or-below-2026-10-22",
        "0x02ee1f9ac20b0329a15c5b142e036fb317000500000000000000000000000000",
        negRisk=True,
    ),
    _market("v2-combinatorial", "0x03" + "5e" * 16 + "00" * 15),
)
# a V1 market can list position ids too; it still trades by its CLOB token ids
_V1_MARKET = _market(
    "v1-binary",
    "0x" + "c1" * 32,
    version="v1",
    clobTokenIds=json.dumps([_V1_TOKEN, _V1_NO]),
    volumeNum=1000,
)
_TRADING_IDS = {
    "v1-binary": [_V1_TOKEN, _V1_NO],
    _V2_BINARY["slug"]: _V2_BINARY["positionIds"],
}


def _gamma(monkeypatch, *rows, slug_index: str = "") -> list:
    """Serve Gamma over `rows` as it filters them: v1 only unless asked for v2.

    public-search returns every version; with `slug_index`, a slug resolves
    only through that index. Returns the versions each other read asked for.
    """
    versions: list = []

    def asked(value) -> set:
        return {str(value)} if isinstance(value, (str, int)) else set(map(str, value))

    def fake_get(url, params=None):
        params, index = dict(params or {}), url.removeprefix(f"{pm.GAMMA_API}/")
        if index == "public-search":
            return {"events": [{"markets": list(rows)}]}
        assert index in ("markets", "events"), url
        versions.append(asked(params.get("version", "v1")))
        served = [r for r in rows if r["version"] in versions[-1]]
        for key, ids in (
            ("slug", lambda r: {r["slug"]}),
            ("condition_ids", lambda r: {r["conditionId"]}),
            ("clob_token_ids", lambda r: set(json.loads(r["clobTokenIds"] or "[]"))),
            ("position_ids", lambda r: set(r["positionIds"])),
        ):
            if key in params:
                served = [r for r in served if ids(r) & asked(params[key])]
        if "slug" in params and slug_index not in ("", index):
            return []
        if index == "events":
            return [{"slug": params.get("slug"), "markets": served}] if served else []
        return served

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    return versions


_BOTH = (_V1_MARKET, _V2_BINARY)
_BY_SLUG = [(markets.cmd_market, (m["slug"], None)) for m in _BOTH]
_MARKET_READS = {
    "list": [(markets.cmd_list, (10, None, None))],
    "search": [(markets.cmd_list, (10, "cay bur", None))],
    "slug": _BY_SLUG,  # each slug resolves only through /markets
    "events-fallback": _BY_SLUG,  # each slug resolves only through /events
    "condition-id": [(markets.cmd_market, (None, m["conditionId"])) for m in _BOTH],
    "group": [(markets.cmd_group, (None, None, m["slug"])) for m in _BOTH],
}


@pytest.mark.parametrize("read", sorted(_MARKET_READS))
def test_v2_position_markets_search(monkeypatch, capsys, read) -> None:
    """Listings and lookups find binary V2 markets beside V1 ones.

    Each market offers the ids it trades by, chosen by its version: a V2
    market's position ids, a V1 market's CLOB token ids, in one Gamma read
    asking for both versions. Listings leave out neg-risk, combinatorial and
    closed V2 markets.
    """
    closed = _market("v2-closed", "0x01" + "c0" * 16 + "00" * 15, closed=True)
    versions = _gamma(
        monkeypatch,
        *_BOTH,
        *_UNTRADEABLE,
        closed,
        slug_index={"slug": "markets", "events-fallback": "events"}.get(read, ""),
    )
    priced: list = []
    monkeypatch.setattr(
        pm, "clob_live_prices", lambda tokens: priced.extend(tokens) or {}
    )

    shown = []
    for command, args in _MARKET_READS[read]:
        command(*args)
        out = json.loads(capsys.readouterr().out)
        shown.extend(out["siblings"] if isinstance(out, dict) else out)

    assert sorted(m["slug"] for m in shown) == sorted(_TRADING_IDS)
    assert {m["slug"]: m["clob_token_ids"] for m in shown} == _TRADING_IDS
    assert sorted(priced) == sorted(sum(_TRADING_IDS.values(), []))
    assert all(asked == {"v1", "v2"} for asked in versions)


_ORDERS = {
    "quote": ("quote", 10.0, "fok"),
    "buy": _BUY,
    "sell": _SELL,
    "limit-buy": _LIMIT_BUY,
    "limit-sell": _LIMIT_SELL,
}


@pytest.mark.parametrize("command", sorted(_ORDERS))
def test_v2_position_trade_by_position_id(clob, monkeypatch, capsys, command) -> None:
    """A binary V2 market trades by its position id, a V1 one by its token id.

    Neg-risk and combinatorial V2 markets, and a binary V2 position no open
    market lists, are refused before anything is signed or sent.
    """
    # the CLOB stand-in's own V2 market, its book served for the asset asked
    v2_binary = _market("v2-binary", f"0x{int(_V2_TOKEN):064x}")
    _gamma(monkeypatch, _V1_MARKET, v2_binary, *_UNTRADEABLE)
    send = clob.send

    def book_of_the_asset_asked(request):
        clob.book = dict(_BOOK, asset_id=request.url.params.get("token_id"))
        return send(request)

    monkeypatch.setattr(clob, "send", book_of_the_asset_asked)
    _dw_holds(clob, monkeypatch, 100.0)
    name, *args = _ORDERS[command]
    run = getattr(_script("trade"), f"cmd_{name}")

    for market in (*_UNTRADEABLE, _V2_BINARY):
        with pytest.raises(SystemExit):
            run(clob.cs, market["positionIds"][0], *args)
    assert clob.requests == clob.digests == []
    pm.require_supported_market(_V1_NO)  # V1 by its layout, though its top byte is 2

    traded = []
    for token in (_V1_TOKEN, _V2_TOKEN):
        run(clob.cs, token, *args)
        if name == "quote":
            traded.append(json.loads(capsys.readouterr().out)["token_id"])
    if name != "quote":
        traded = [order["tokenId"] for order in clob.orders]
    assert traded == [_V1_TOKEN, _V2_TOKEN]


def _key(*parts) -> tuple:
    """Addresses checksummed and ids as ints, however a caller spells them."""
    return tuple(
        to_checksum_address(p) if str(p).startswith("0x") else int(p) for p in parts
    )


def _call(target, data) -> tuple:
    """Return a call as (checksummed target, lowercase 0x calldata)."""
    data = data.lower() if isinstance(data, str) else "0x" + bytes(data).hex()
    return to_checksum_address(target), data


class _SafeChain:
    """The service safe and the ERC-1155 balances and approvals it reads.

    Both are keyed by contract, so a read at the wrong one finds nothing. An
    approval the safe sends is granted, and a Router claim burns its position.
    """

    safe_address = SAFE_ADDR
    w3 = object()

    def __init__(self, monkeypatch, balances: dict, approved=()) -> None:
        """Hold `balances`, (contract, owner, id) -> units, and `approved` pairs."""
        self.balances = {_key(*k): units for k, units in balances.items()}
        self.approved = {_key(*pair) for pair in approved}
        self.sent: list = []
        for name, read in (
            ("erc1155_balance_of", lambda w3, *k: self.balances.get(_key(*k), 0)),
            ("is_approved_for_all", lambda w3, t, _, op: _key(t, op) in self.approved),
        ):
            monkeypatch.setattr(pm, name, read)

    def safe_transaction(self, to, data, value=0, request_id=None) -> str:
        """Record one safe call and apply it as the chain would."""
        target, data = _call(to, data)
        self.sent.append((target, data))
        args = bytes.fromhex(data[10:])
        if data.startswith(_APPROVAL):
            operator, granted = abi_decode(["address", "bool"], args)
            if granted:
                self.approved.add(_key(target, operator))
        elif target == _ROUTER:
            condition, index, _ = abi_decode(["bytes31", "uint256", "uint256"], args)
            claimed = (int.from_bytes(condition, "big") << 8) + index
            self.balances.pop(_key(_POSITION_MANAGER, SAFE_ADDR, claimed), None)
        return "0x" + "ab" * 32

    def wait_receipt(self, tx_hash, timeout=300) -> dict:
        """Every call confirms."""
        return {"status": 1, "tx_hash": tx_hash}


_V2_HELD, _V1_HELD = int(_V2_BINARY["positionIds"][1]), (1 << 248) | (1 << 40) | 7


def _holding(monkeypatch, at: str) -> _SafeChain:
    """Hold 5 V2 shares on PositionManager and 7 V1 on the CTF, both at `at`."""
    held = {
        (_POSITION_MANAGER, at, _V2_HELD): 5 * 10**6,
        (_CTF, at, _V1_HELD): 7 * 10**6,
    }
    return _SafeChain(monkeypatch, held)


def test_v2_position_holdings_from_position_manager(monkeypatch, capsys) -> None:
    """`positions` confirms every V2 holding on PositionManager, V1 on the CTF."""
    other = [int(m["positionIds"][0]) for m in _UNTRADEABLE]
    cs = _holding(monkeypatch, SAFE_ADDR)
    cs.balances.update({_key(_POSITION_MANAGER, SAFE_ADDR, i): 10**6 for i in other})
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page([]))
    monkeypatch.setattr(positions, "_resolve_dw", lambda cs: DW_HELD)

    positions.cmd_positions(cs, "safe", False, [_V2_HELD, _V1_HELD, *other])

    held = json.loads(capsys.readouterr().out)["onchain_check"]["held"]
    assert [(int(h["token_id"]), h["size"]) for h in held] == [
        (_V2_HELD, 5.0),
        (_V1_HELD, 7.0),
        *((i, 1.0) for i in other),
    ]
    # only an ASCII decimal id can name a V2 position, and no id raises
    fullwidth = "".join(chr(0xFF10 + int(d)) for d in _V2_TOKEN)
    for odd in (fullwidth, "²", "", hex(int(_V2_TOKEN)), None):
        assert pm.v2_module(odd) == 0, odd


@pytest.mark.parametrize("command", ["sweep", "return-position"])
def test_v2_position_funds_through_position_manager(monkeypatch, command) -> None:
    """V2 shares move between the DW and the safe on PositionManager, V1 on the CTF."""
    holder, receiver = (DW_ADDR, SAFE_ADDR)[:: 1 if command == "sweep" else -1]
    _sweep_mocks(monkeypatch, pusd=0, ctf_balance=0, recorded=[], indexed=[])
    cs = _holding(monkeypatch, holder)
    monkeypatch.setattr(pm, "forget_dw_tokens", lambda cs, token_ids: None)
    monkeypatch.setattr(pm, "record_dw_token_best_effort", lambda cs, token_id: True)
    monkeypatch.setattr(_FakeRelayer, "result", (True, "STATE_MINED", "0xhash"))
    batches = []
    monkeypatch.setattr(
        _FakeRelayer,
        "exec_wallet_batch",
        lambda self, dw, nonce, calls: batches.append(calls) or "relayer-tx",
    )

    if command == "sweep":
        funds.cmd_sweep(cs, [_V2_HELD, _V1_HELD])
        (batch,) = batches
        moved = [_call(c["target"], c["data"]) for c in batch]
    else:
        for token_id in (_V2_HELD, _V1_HELD):
            funds.cmd_return_position(cs, token_id, None)
        moved = cs.sent

    assert moved == [
        (
            _POSITION_MANAGER,
            _calldata(_TRANSFER, holder, receiver, _V2_HELD, 5_000_000, b""),
        ),
        (_CTF, _calldata(_TRANSFER, holder, receiver, _V1_HELD, 7_000_000, b"")),
    ]


# A resolved binary V2 market, as the data API lists the safe's sides of it.
_V2_RESOLVED = "0x01d4bb20435cb2b6c6431871f0ec197e92000000000000000000000000000000"
_ADAPTERS = (pm.CTF_COLLATERAL_ADAPTER, pm.NEG_RISK_CTF_COLLATERAL_ADAPTER)
_ROUTER_APPROVAL = (_POSITION_MANAGER, _calldata(_APPROVE_ALL, _ROUTER, True))


def _settled(token_id, value, condition_id, index, neg_risk=False) -> dict:
    """Return a redeemable data-API position row, in the names `_v2_page` maps."""
    keys = ("asset", "currentValue", "conditionId", "outcomeIndex", "negativeRisk")
    row = zip(keys, (str(token_id), value, condition_id, index, neg_risk))
    return dict(row, redeemable=True)


def _adapter_claim(outcome_index: int) -> tuple:
    """Return the V1 claim of `_V1_MARKET`: redeemPositions on its adapter."""
    condition = bytes.fromhex(_V1_MARKET["conditionId"][2:])
    data = _calldata(_ADAPTER_REDEEM, _PUSD, bytes(32), condition, [1 << outcome_index])
    return pm.CTF_COLLATERAL_ADAPTER, data


@pytest.mark.parametrize(("command", "won"), [("all", 0), ("all", 1), ("redeem", 1)])
def test_v2_position_claim_through_router(monkeypatch, command, won) -> None:
    """A winning V2 position is claimed from the safe through the Router.

    The condition id (high 31 bytes) and outcome index come from the position
    id, the amount from the safe's exact PositionManager balance; the data API
    row may disagree and rounds sizes. The Router is approved once, a claimed
    position is not claimed again, and V1 claims through an adapter approved for it.
    """
    position = int(_V2_RESOLVED, 16) + won
    cs = _SafeChain(monkeypatch, {(_POSITION_MANAGER, SAFE_ADDR, position): 1_818_182})
    rows = [
        _settled(position, 1.8181, _V2_BINARY["conditionId"], 1 - won),
        _settled(_V1_TOKEN, 7.0, _V1_MARKET["conditionId"], 0),
    ][: 1 + won]
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page(rows))

    if command == "redeem":
        redeem.cmd_redeem(cs, _V2_RESOLVED, won, False)
    else:
        redeem.cmd_all(cs)
        redeem.cmd_all(cs)

    approvals = [call for call in cs.sent if call[1].startswith(_APPROVAL)]
    claims = [call for call in cs.sent if call not in approvals]
    condition = bytes.fromhex(_V2_RESOLVED[2:])[:31]
    claim = _calldata("redeem(bytes31,uint256,uint256)", condition, won, 1_818_182)
    if command == "redeem":
        assert _ROUTER_APPROVAL in approvals
        assert claims == [(_ROUTER, claim)]
    else:
        granted = [(_CTF, _calldata(_APPROVE_ALL, a, True)) for a in _ADAPTERS]
        assert sorted(approvals) == sorted([*granted[: 2 * won], _ROUTER_APPROVAL])
        assert claims == [(_ROUTER, claim), *[_adapter_claim(0)] * 2 * won]


def test_v2_position_losing_row_not_claimed(monkeypatch, capsys) -> None:
    """`redeem.py` claims no losing, unheld, neg-risk or combinatorial V2 position.

    Refusing one sends nothing, not even the Router approval. A losing V1 row
    still goes to its adapter. On a safe that approved both adapters before
    V2, V1 claims ask for no new approval; `approve` grants the Router, once.
    """
    neg_risk, combinatorial = _UNTRADEABLE
    rows = [
        _settled(int(_V2_RESOLVED, 16) + 1, 0.0, _V2_RESOLVED, 1),
        _settled(neg_risk["positionIds"][0], 4.0, neg_risk["conditionId"], 0, True),
        _settled(combinatorial["positionIds"][0], 4.0, combinatorial["conditionId"], 0),
        _settled(_V1_NO, 0.0, _V1_MARKET["conditionId"], 1),
    ]
    held = {(_POSITION_MANAGER, SAFE_ADDR, r["asset"]): 5 * 10**6 for r in rows[:3]}
    cs = _SafeChain(monkeypatch, held, approved=[(_CTF, a) for a in _ADAPTERS])
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page(rows))
    monkeypatch.setattr(pm.ConnectSigner, "from_workspace", lambda: cs)
    monkeypatch.setattr(sys, "argv", ["redeem.py", "approve"])

    for market in (*_UNTRADEABLE, {"conditionId": _V2_RESOLVED}):
        with pytest.raises(SystemExit):
            redeem.cmd_redeem(cs, market["conditionId"], 0, True)
    capsys.readouterr()
    redeem.cmd_all(cs)
    skipped = json.loads(capsys.readouterr().out)["skipped"]
    redeem.cmd_redeem(cs, _V1_MARKET["conditionId"], 1, False)
    redeem.main()
    redeem.main()

    assert cs.sent == [_adapter_claim(1), _adapter_claim(1), _ROUTER_APPROVAL]
    reasons = ["no_value", "unsupported_v2", "unsupported_v2"]
    assert skipped == [
        {
            "condition_id": r["conditionId"],
            "outcome_index": r["outcomeIndex"],
            "reason": reason,
        }
        for r, reason in zip(rows, reasons)
    ]


def test_v2_position_claim_by_position_id(monkeypatch, capsys) -> None:
    """A V2 row whose condition id is its legacy V1 one is claimed by position id."""
    position = int(_V2_RESOLVED, 16) + 1
    rows = [
        _settled(position, 2.0, _V1_MARKET["conditionId"], 1),
        _settled(_V1_TOKEN, 7.0, _V1_MARKET["conditionId"], 0),
    ]
    held = {(_POSITION_MANAGER, SAFE_ADDR, position): 2_000_000}
    cs = _SafeChain(monkeypatch, held)
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page(rows))
    monkeypatch.setattr(pm.ConnectSigner, "from_workspace", lambda: cs)

    def claim_by_id(position_id: str) -> None:
        monkeypatch.setattr(
            sys, "argv", ["redeem.py", "redeem", "--position-id", position_id]
        )
        redeem.main()

    redeem.cmd_list(cs)
    v2_row, v1_row = json.loads(capsys.readouterr().out)
    assert "position_id" not in v1_row
    with pytest.raises(SystemExit, match="not a binary V2"):
        claim_by_id(str(_V1_HELD))
    claim_by_id(v2_row["position_id"])
    with pytest.raises(SystemExit, match="holds no position"):
        claim_by_id(str(position))

    condition = bytes.fromhex(_V2_RESOLVED[2:])[:31]
    claim = _calldata("redeem(bytes31,uint256,uint256)", condition, 1, 2_000_000)
    assert cs.sent == [_ROUTER_APPROVAL, (_ROUTER, claim)]


@pytest.mark.parametrize(
    ("condition_id", "outcome_index"),
    [(_V2_RESOLVED[:-2] + "01", 0), (_V2_RESOLVED, 2)],
)
def test_v2_position_claim_refuses_a_condition_id_off_the_layout(
    monkeypatch, condition_id, outcome_index
) -> None:
    """A V2 condition id not ending in 00, or an index past 1, claims nothing."""
    held = {(_POSITION_MANAGER, SAFE_ADDR, int(condition_id, 16)): 10**6}
    cs = _SafeChain(monkeypatch, held)
    with pytest.raises(SystemExit, match="--position-id"):
        redeem.cmd_redeem(cs, condition_id, outcome_index, False)
    assert cs.sent == []


def test_redeem_requires_its_v1_arguments_before_the_workspace(monkeypatch, capsys):
    """Without --position-id, `redeem` still requires both V1 arguments."""
    monkeypatch.setattr(pm.ConnectSigner, "from_workspace", lambda: pytest.fail())
    monkeypatch.setattr(sys, "argv", ["redeem.py", "redeem", "--outcome-index", "0"])
    with pytest.raises(SystemExit) as exited:
        redeem.main()
    assert exited.value.code == 2
    assert capsys.readouterr().err.endswith(
        "error: the following arguments are required: --condition-id\n"
    )


def test_v2_position_unheld_row_reported_skipped(monkeypatch, capsys) -> None:
    """`all` reports a valued V2 row the safe no longer holds as `not_held`."""
    rows = [_settled(int(_V2_RESOLVED, 16), 3.0, _V2_RESOLVED, 0)]
    cs = _SafeChain(monkeypatch, {})
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: _v2_page(rows))
    redeem.cmd_all(cs)
    assert json.loads(capsys.readouterr().out)["skipped"] == [
        {"condition_id": _V2_RESOLVED, "outcome_index": 0, "reason": "not_held"}
    ]
    assert cs.sent == []
