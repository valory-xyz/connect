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
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
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


def test_legacy_pending_token_migrates_to_reference_count(tmp_path) -> None:
    """The token-set state written by older versions remains recoverable."""
    cs = _cs_with_workspace(tmp_path)
    pm.save_state(cs, {"dw_open_tokens": [5], "dw_pending_buy_tokens": [5]})

    pm.record_dw_buy_intent(cs, 5)

    state = pm.load_state(cs)
    assert state["dw_pending_buy_counts"] == {"5": 2}
    assert "dw_pending_buy_tokens" not in state


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
