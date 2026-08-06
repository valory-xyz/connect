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
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_utils import is_address, to_checksum_address
from web3.exceptions import ContractLogicError, TimeExhausted

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
import pm_common as pm  # noqa: E402
import positions  # noqa: E402
import redeem  # noqa: E402
import relayer_proxy  # noqa: E402

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

    positions.cmd_positions(_SweepCS({}), "safe", False)

    reported = json.loads(capsys.readouterr().out)
    assert [p["token_id"] for p in reported] == ["11", "12", "13"]
    assert [params["offset"] for params in seen] == [0, 2]


@pytest.mark.parametrize("payload", [None, {"positions": []}])
def test_positions_command_rejects_non_list_page(monkeypatch, payload) -> None:
    """A malformed portfolio page must not read as an empty portfolio."""
    monkeypatch.setattr(positions, "POSITIONS_PAGE_LIMIT", 1)
    pages = iter(([{"asset": "11"}], payload))
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: next(pages))

    with pytest.raises(SystemExit, match="expected a list"):
        positions.cmd_positions(_SweepCS({}), "safe", False)


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
    # the approval set, named — the DW's three venues, not the two adapters
    assert set(report["dw_trading_approvals"]["pusd_allowances"].values()) == {
        "CTFExchange",
        "NegRiskCTFExchange",
        "NegRiskAdapter",
    }


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
