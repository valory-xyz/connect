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
network, no funds, no ``py_clob_client_v2`` dependency (order/SDK paths are
covered by the live e2e, not here).
"""

# The skill modules are imported at runtime via a sys.path insert (they ship
# as bundled assets, not an installed package) and pull in py_clob_client_v2,
# which has no type stubs — mypy can follow none of this, so skip the file.
# mypy: ignore-errors

import json
import os
import subprocess  # nosec B404 - runs the skill's own bootstrap script
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
from web3.exceptions import ContractLogicError, TimeExhausted

from connect import workspace
from connect.config import AGENT_HTTP_PORT, BIND_HOST

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
import signer_client  # noqa: E402  (on sys.path via pm_common's sibling import)


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
    """All-missing yields 3 pUSD approvals + 3 CTF operator grants, no more."""
    monkeypatch.setattr(pm, "erc20_allowance", lambda *a: 0)
    monkeypatch.setattr(pm, "is_approved_for_all", lambda *a: False)
    calls = pm.missing_approval_calls(None, ADDR_A)
    assert len(calls) == 6
    pusd_calls = [c for c in calls if c["target"] == pm.PUSD]
    ctf_calls = [c for c in calls if c["target"] == pm.CTF]
    assert len(pusd_calls) == len(pm.APPROVAL_SPENDERS_PUSD) == 3
    assert len(ctf_calls) == len(pm.APPROVAL_OPERATORS_CTF) == 3
    assert all(c["data"].startswith("0x095ea7b3") for c in pusd_calls)
    assert all(c["data"].startswith("0xa22cb465") for c in ctf_calls)


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
    seen = []

    def fake_get(url, params=None):
        seen.append(dict(params))
        return {
            0: [{"asset": "11"}, {"asset": "12"}],
            2: [{"asset": "13"}],
        }[params.get("offset", 0)]

    monkeypatch.setattr(pm, "http_get_json", fake_get)

    assert funds._dw_position_token_ids(DW_ADDR) == [11, 12, 13]
    assert [params["offset"] for params in seen] == [0, 2]
    assert all(params["limit"] == 2 for params in seen)


@pytest.mark.parametrize("payload", [None, {"positions": []}])
def test_dw_position_token_ids_rejects_non_list_page(monkeypatch, payload) -> None:
    """Malformed indexed-position pages cannot masquerade as completion."""
    monkeypatch.setattr(funds, "POSITIONS_PAGE_LIMIT", 1, raising=False)
    pages = iter(([{"asset": "11"}], payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="expected a list"):
        funds._dw_position_token_ids(DW_ADDR)


def test_dw_position_token_ids_fails_at_api_offset_ceiling(monkeypatch) -> None:
    """A full final addressable page cannot be mistaken for completion."""
    monkeypatch.setattr(funds, "POSITIONS_PAGE_LIMIT", 2, raising=False)
    monkeypatch.setattr(funds, "POSITIONS_MAX_OFFSET", 2, raising=False)
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [{"asset": "11"}, {"asset": "12"}],
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
    """Redeemable discovery continues until the API returns a short page."""
    monkeypatch.setattr(redeem, "POSITIONS_PAGE_LIMIT", 2)
    seen = []

    def fake_get(url, params=None):
        seen.append(dict(params))
        return {
            0: [{"conditionId": "0x1"}, {"conditionId": "0x2"}],
            2: [{"conditionId": "0x3"}],
        }[params["offset"]]

    monkeypatch.setattr(pm, "http_get_json", fake_get)

    assert [p["conditionId"] for p in redeem._redeemable(_SweepCS({}))] == [
        "0x1",
        "0x2",
        "0x3",
    ]
    assert [params["offset"] for params in seen] == [0, 2]
    assert all(params["limit"] == 2 for params in seen)


def test_redeemable_fails_at_api_offset_ceiling(monkeypatch) -> None:
    """A full final addressable page must not be mistaken for completion."""
    monkeypatch.setattr(redeem, "POSITIONS_PAGE_LIMIT", 2)
    monkeypatch.setattr(redeem, "POSITIONS_MAX_OFFSET", 2)
    monkeypatch.setattr(
        pm,
        "http_get_json",
        lambda url, params=None: [{"conditionId": "0x1"}, {"conditionId": "0x2"}],
    )

    with pytest.raises(SystemExit, match="pagination limit"):
        redeem._redeemable(_SweepCS({}))


def test_positions_command_fetches_every_page(monkeypatch, capsys) -> None:
    """Portfolio reporting pages through instead of showing only page one."""
    monkeypatch.setattr(positions, "POSITIONS_PAGE_LIMIT", 2)
    seen = []

    def fake_get(url, params=None):
        seen.append(dict(params))
        return {
            0: [{"asset": "11"}, {"asset": "12"}],
            2: [{"asset": "13"}],
        }[params["offset"]]

    monkeypatch.setattr(pm, "http_get_json", fake_get)

    positions.cmd_positions(_SweepCS({}), "safe", False, None, False)

    reported = json.loads(capsys.readouterr().out)
    assert [p["token_id"] for p in reported["positions"]] == ["11", "12", "13"]
    assert [params["offset"] for params in seen] == [0, 2]


@pytest.mark.parametrize("payload", [None, {"positions": []}])
def test_positions_command_rejects_non_list_page(monkeypatch, payload) -> None:
    """A malformed portfolio page must not read as an empty portfolio."""
    monkeypatch.setattr(positions, "POSITIONS_PAGE_LIMIT", 1)
    pages = iter(([{"asset": "11"}], payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="expected a list"):
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
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: list(indexed))
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
    assert "disagree with the indexer" in out["warning"]
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
    assert "different size" in out["warning"]


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
        pm, "http_get_json", lambda url, params=None: [{"asset": "55", "size": 2}]
    )

    def boom(_cs):
        raise SystemExit("persisted DepositWallet has no readable owner()")

    monkeypatch.setattr(positions, "_resolve_dw", boom)

    positions.cmd_positions(cs, "safe", False)

    out = json.loads(capsys.readouterr().out)
    assert [p["token_id"] for p in out["positions"]] == ["55"]  # not discarded
    assert "could not confirm on-chain" in out["onchain_check"]["error"]
    assert "held" not in out["onchain_check"]  # never reads as "checked, none"


def test_positions_no_onchain_flag_trusts_the_indexer(
    monkeypatch, capsys, tmp_path
) -> None:
    """--no-onchain must not silently still hit the chain."""
    cs = _ChainCS(tmp_path)
    pm.record_dw_token(cs, 77)
    called = []
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: [])
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
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: [])

    positions.cmd_trades(_ChainCS(tmp_path), "safe", 10)

    out = json.loads(capsys.readouterr().out)
    assert out["trades"] == []
    assert "lags the chain" in out["note"]


@pytest.mark.parametrize("payload", [None, {"positions": []}])
def test_redeemable_rejects_non_list_page(monkeypatch, payload) -> None:
    """A malformed later page cannot masquerade as pagination completion."""
    monkeypatch.setattr(redeem, "POSITIONS_PAGE_LIMIT", 1)
    pages = iter(([{"conditionId": "0x1"}], payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="expected a list"):
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


# --- .mcp.json base URL: the trailing slash that 404'd a whole live run ----------


def _write_mcp_config(directory: Path, url: str) -> None:
    (directory / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    signer_client.MCP_SERVER_NAME: {
                        "url": url,
                        "headers": {"Authorization": "Bearer t0ken"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8716/mcp",
        "http://127.0.0.1:8716/mcp/",
        "http://127.0.0.1:8716/mcp///",
    ],
)
def test_mcp_base_url_drops_the_suffix_however_it_is_slashed(tmp_path, url) -> None:
    """A trailing slash must not defeat the /mcp strip — it 404s every request."""
    _write_mcp_config(tmp_path, url)
    base_url, token, root = signer_client.load_mcp_config_dir(tmp_path)
    assert base_url == "http://127.0.0.1:8716"
    assert token == "t0ken"  # nosec B105
    assert root == tmp_path.resolve()


def test_base_url_handles_the_url_the_server_actually_writes(tmp_path) -> None:
    """Producer and consumer in one test — the gap that broke every live run.

    ``workspace.mcp_url`` ends in a slash on purpose (a POST to /mcp without
    it hits the agent-UI route and 405s), so the reader must cope with it
    rather than the writer dropping it.
    """
    _write_mcp_config(tmp_path, workspace.mcp_url())
    base_url, _, _ = signer_client.load_mcp_config_dir(tmp_path)
    assert base_url == f"http://{BIND_HOST}:{AGENT_HTTP_PORT}"
    assert not base_url.rstrip("/").endswith("/mcp")


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
            {"question": "resolves soon", "endDate": soon},
            {"question": "resolves next year", "endDate": far_future},
            {"question": "no end date at all"},
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
    if complete:
        (venv / ".bootstrap-complete").touch()
    return venv


def _fake_pip(venv: Path, exit_code: int = 0) -> Path:
    """Put a stub pip in the venv so no real install is attempted."""
    pip = venv / "bin" / "pip"
    pip.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
    pip.chmod(0o755)
    return pip


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
