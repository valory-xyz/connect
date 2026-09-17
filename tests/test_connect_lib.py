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

"""Unit tests for the shared skill modules."""

import http.client
import io
import json
import math
import sys
import typing as t
import urllib.error
from email.message import Message
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address
from web3.exceptions import ContractCustomError, Web3RPCError

LIB = Path(__file__).resolve().parent.parent / "connect" / "assets" / "lib"
sys.path.insert(0, str(LIB))

import cli  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import ipfs  # noqa: E402  pylint: disable=wrong-import-position
import permit  # noqa: E402  pylint: disable=wrong-import-position
import router  # noqa: E402  pylint: disable=wrong-import-position
import state  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position
import web  # noqa: E402  pylint: disable=wrong-import-position

CHAIN_ID = 4663
WHERE = uniswap.DEPLOYMENTS[CHAIN_ID]
NATIVE = evm.NATIVE
TOKEN = to_checksum_address("0x" + "ab" * 20)
USDG = to_checksum_address("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")
WETH = to_checksum_address("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73")
SAFE = to_checksum_address("0x" + "5a" * 20)
HOOK = to_checksum_address("0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044")
V4_POOL: uniswap.PoolV4 = {
    "version": "v4",
    "fee": 0,
    "tick_spacing": 200,
    "hooks": HOOK,
    "pool_id": "0x" + "00" * 32,
    "liquidity": 1,
    "quote_address": NATIVE,
}
V3_POOL: uniswap.PoolV3 = {
    "version": "v3",
    "fee": 10000,
    "address": to_checksum_address("0x" + "33" * 20),
    "quote_address": WETH,
}
V2_POOL: uniswap.PoolV2 = {
    "version": "v2",
    "fee": 3000,
    "address": to_checksum_address("0x" + "22" * 20),
    "quote_address": WETH,
}


class _CallW3:
    """A web3 whose eth_call and eth_getBalance answer fixed values."""

    def __init__(self, answer: bytes = b"", balance: int = 0) -> None:
        """Answer every call with these bytes and every balance with this."""
        self.eth = self
        self.calls: list[dict] = []
        self._answer = answer
        self._balance = balance

    def call(self, tx: dict) -> bytes:
        """Record the call and answer."""
        self.calls.append(tx)
        return self._answer

    def get_balance(self, holder: str) -> int:
        """Record the balance read as a call and answer."""
        self.calls.append({"balance_of": holder})
        return self._balance


class _ReceiptW3:
    """A web3 whose receipts carry a status, or whose wait raises."""

    def __init__(self, status: int = 1, error: t.Optional[Exception] = None) -> None:
        """Answer every receipt with this status, or raise this error."""
        self.eth = self
        self._status = status
        self._error = error

    def wait_for_transaction_receipt(
        self, tx_hash: str, timeout: float, poll_latency: float
    ) -> dict:
        """Answer the wait."""
        assert (timeout, poll_latency) == (
            evm.RECEIPT_TIMEOUT_S,
            evm.RECEIPT_POLL_S,
        ), tx_hash
        if self._error is not None:
            raise self._error
        return {"status": self._status}


class _Signer:
    """Records what it is asked to send."""

    def __init__(self, error: t.Optional[Exception] = None) -> None:
        """Fail every send with this error, when given."""
        self.sent: list[dict] = []
        self._error = error

    def send_transaction(self, tx: dict) -> str:
        """Record and return a hash."""
        if self._error is not None:
            raise self._error
        self.sent.append(tx)
        return f"0x{len(self.sent):064x}"


def test_native_is_the_zero_address() -> None:
    """The native coin is address(0), as v4 and the Pons factory spell it."""
    assert int(NATIVE, 16) == 0
    assert evm.is_native(NATIVE)
    assert evm.is_native("0x" + "00" * 20)
    assert not evm.is_native(WETH)


def test_native_decimals_need_no_call() -> None:
    """There is no contract to ask at address(0)."""
    w3 = _CallW3()
    assert evm.token_decimals(w3, NATIVE) == 18  # type: ignore[arg-type]
    assert not w3.calls


def test_native_balance_is_the_account_balance() -> None:
    """At address(0) balanceOf would answer nothing; eth_getBalance is the read."""
    w3 = _CallW3(balance=3 * 10**17)
    got = evm.balance_of(w3, NATIVE, SAFE, 18)  # type: ignore[arg-type]
    assert got == pytest.approx(0.3)
    assert w3.calls == [{"balance_of": SAFE}]


def test_token_balance_still_reads_balance_of() -> None:
    """An ERC-20 balance is still a balanceOf call on the token."""
    w3 = _CallW3(answer=(5 * 10**6).to_bytes(32, "big"))
    assert evm.balance_of(w3, USDG, SAFE, 6) == 5.0  # type: ignore[arg-type]
    assert bytes(w3.calls[0]["data"])[:4] == evm.SEL_BALANCE_OF


def test_raw_balance_is_in_base_units() -> None:
    """The raw read skips the whole-unit scaling for both native and tokens."""
    native = _CallW3(balance=3 * 10**17)
    assert evm.raw_balance_of(native, NATIVE, SAFE) == 3 * 10**17  # type: ignore[arg-type]
    token = _CallW3(answer=(5 * 10**6).to_bytes(32, "big"))
    assert evm.raw_balance_of(token, USDG, SAFE) == 5 * 10**6  # type: ignore[arg-type]


def test_call_types_decodes_the_return() -> None:
    """Each requested type comes back decoded, in order."""
    w3 = _CallW3(answer=(7).to_bytes(32, "big") + bytes(12) + bytes.fromhex("11" * 20))
    got = evm.call_types(w3, USDG, b"\x01", ["uint256", "address"])  # type: ignore[arg-type]
    assert got == (7, to_checksum_address("0x" + "11" * 20).lower())
    assert w3.calls[0]["to"] == USDG


def test_call_types_refuses_a_short_return() -> None:
    """A return shorter than the types need names the contract."""
    w3 = _CallW3(answer=bytes(32))
    with pytest.raises(evm.SwapError, match=f"{USDG} returned 32 bytes"):
        evm.call_types(w3, USDG, b"", ["uint256", "uint256"])  # type: ignore[arg-type]


def test_call_types_refuses_an_undecodable_return() -> None:
    """A dynamic type whose offset points nowhere is a SwapError, not a crash."""
    w3 = _CallW3(answer=(10**6).to_bytes(32, "big"))
    with pytest.raises(evm.SwapError, match="not \\['string'\\]"):
        evm.call_types(w3, USDG, b"", ["string"])  # type: ignore[arg-type]


def test_to_base_units_reads_native_decimals_without_a_call() -> None:
    """Whole ETH converts exactly, from the fixed native decimals."""
    w3 = _CallW3()
    got = evm.to_base_units(w3, NATIVE, 0.1)  # type: ignore[arg-type]
    assert got == 10**17
    assert not w3.calls


def test_weth_deposit_carries_the_value_it_wraps() -> None:
    """deposit() takes no argument; the amount is the call's value."""
    call = evm.weth_deposit_call(WETH, 7)
    assert call == {"to": WETH, "data": "0xd0e30db0", "what": "wrap ETH", "value": 7}


def test_weth_withdraw_encodes_the_amount_and_sends_no_value() -> None:
    """withdraw(uint256) names the amount and carries no value."""
    call = evm.weth_withdraw_call(WETH, 9)
    assert call["data"][:10] == "0x2e1a7d4d"
    assert abi_decode(["uint256"], bytes.fromhex(call["data"][10:])) == (9,)
    assert "value" not in call
    assert call["to"] == WETH


@pytest.mark.parametrize("whole", [math.inf, -math.inf, math.nan])
def test_to_base_units_refuses_a_non_finite_amount(whole: float) -> None:
    """Infinity and NaN are refused before any read or conversion."""
    with pytest.raises(evm.SwapError, match="not a finite amount"):
        evm.to_base_units(object(), NATIVE, whole)  # type: ignore[arg-type]


def test_send_calls_passes_value_and_confirms_each(
    capsys: pytest.CaptureFixture,
) -> None:
    """Value reaches the signer, and each call is confirmed in order."""
    signer = _Signer()
    calls = [
        evm.weth_deposit_call(WETH, 5),
        evm.erc20_approval_call(WETH, SAFE, 5, "approve"),
    ]
    landed = evm.send_calls(_ReceiptW3(), signer, calls)
    assert signer.sent[0]["value"] == 5
    assert "value" not in signer.sent[1]
    assert evm.summary(landed) == [f"wrap ETH: 0x{1:064x}", f"approve: 0x{2:064x}"]
    assert all(sent.receipt["status"] == 1 for sent in landed)
    assert "wrap ETH: 0x" in capsys.readouterr().out


def test_send_calls_names_a_send_that_failed() -> None:
    """A failed send stops the sequence and says whether it may have broadcast."""
    signer = _Signer(error=RuntimeError("boom"))
    with pytest.raises(evm.SwapError, match="could not be sent.*may still"):
        evm.send_calls(_ReceiptW3(), signer, [evm.weth_deposit_call(WETH, 1)])


@pytest.mark.parametrize(
    ("error", "outcome"),
    [
        ("signer returned HTTP 400: safe may not call itself", "refused it before"),
        ("signer returned HTTP 401: invalid token", "refused it before"),
        (
            "signer returned HTTP 400: send failed: ('execution reverted: GS013', '0x')",
            "reverted in simulation",
        ),
        ("signer returned HTTP 400: send failed: read timed out", "may still"),
        ("signer returned HTTP 400: request 'x' is already in flight", "may still"),
        ("signer returned HTTP 500: Internal Server Error", "may still"),
        ("send not confirmed after 3 attempts (timed out)", "may still"),
    ],
)
def test_send_outcome_says_nothing_broadcast_only_when_that_is_certain(
    error: str, outcome: str
) -> None:
    """Refusals and simulation reverts are final; anything else may have landed."""
    assert outcome in evm.send_outcome(RuntimeError(error))


def test_send_calls_names_a_call_that_never_confirmed() -> None:
    """A receipt timeout is an unknown fate, not a failure."""
    w3 = _ReceiptW3(error=TimeoutError("slow"))
    with pytest.raises(evm.SwapError, match="has not confirmed"):
        evm.send_calls(w3, _Signer(), [evm.weth_deposit_call(WETH, 1)])


def test_send_calls_stops_at_a_revert() -> None:
    """A reverted call must not read as success, and nothing follows it."""
    signer = _Signer()
    calls = [evm.weth_deposit_call(WETH, 1), evm.weth_withdraw_call(WETH, 1)]
    with pytest.raises(evm.SwapError, match=r"reverted; confirmed so far: \[\]"):
        evm.send_calls(_ReceiptW3(status=0), signer, calls)
    assert len(signer.sent) == 1


@pytest.mark.parametrize("pool", [V3_POOL, V2_POOL])
@pytest.mark.parametrize(("token_in", "token_out"), [(NATIVE, TOKEN), (TOKEN, NATIVE)])
def test_v2_and_v3_refuse_the_native_coin(
    pool: uniswap.Pool, token_in: str, token_out: str
) -> None:
    """Only v4 pools hold ETH itself; v2/v3 would need WETH."""
    with pytest.raises(evm.SwapError, match="cannot trade the native coin"):
        uniswap.quote_pool(_CallW3(), CHAIN_ID, pool, token_in, token_out, 1)  # type: ignore[arg-type]
    with pytest.raises(evm.SwapError, match="cannot trade the native coin"):
        uniswap.build_execute(pool, token_in, token_out, 1, 1, SAFE, 1)
    with pytest.raises(evm.SwapError, match="cannot trade the native coin"):
        uniswap.verify_execute("0x", pool, token_in, token_out, 1, 1, SAFE, 1)


def test_v4_quote_keys_native_as_currency0() -> None:
    """address(0) sorts first, so buying with ETH is zeroForOne."""
    w3 = _CallW3(answer=(42).to_bytes(32, "big"))
    out = uniswap.quote_pool(
        w3, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 10**15  # type: ignore[arg-type]
    )
    assert out == 42
    assert w3.calls[0]["to"] == WHERE["v4_quoter"]
    data = bytes(w3.calls[0]["data"])
    assert data[:4] == uniswap.SEL_QUOTE_V4
    key, zero_for_one, amount, _ = abi_decode(
        ["((address,address,uint24,int24,address),bool,uint128,bytes)"], data[4:]
    )[0]
    assert key == (NATIVE, TOKEN.lower(), 0, 200, HOOK.lower())
    assert zero_for_one is True
    assert amount == 10**15


@pytest.mark.parametrize(("token_in", "token_out"), [(NATIVE, TOKEN), (TOKEN, NATIVE)])
def test_v4_native_swap_round_trips_through_the_verifier(
    token_in: str, token_out: str
) -> None:
    """A native leg settles and takes address(0), and the verifier agrees."""
    calldata = uniswap.build_execute(V4_POOL, token_in, token_out, 10, 9, SAFE, 77)
    uniswap.verify_execute(calldata, V4_POOL, token_in, token_out, 10, 9, SAFE, 77)
    _, inputs, _ = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    _, params = abi_decode(["bytes", "bytes[]"], inputs[0])
    settle = abi_decode(["address", "uint256", "bool"], params[1])
    take = abi_decode(["address", "address", "uint256"], params[2])
    assert settle[0] == token_in.lower()
    assert take[0] == token_out.lower()
    with pytest.raises(evm.SwapError, match="amount_in"):
        uniswap.verify_execute(calldata, V4_POOL, token_in, token_out, 11, 9, SAFE, 77)


@pytest.fixture(name="probe")
def probe_fixture(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Answer quote_pool from a table and record the sizes asked."""
    state: dict[str, t.Any] = {"asked": [], "out": 0}

    def _quote(*args: t.Any) -> int:
        """Record the probe size and answer."""
        state["asked"].append(args[-1])
        return int(state["out"])

    monkeypatch.setattr(uniswap, "quote_pool", _quote)
    return state


def test_price_impact_compares_the_fill_with_a_small_probe(probe: dict) -> None:
    """A fill at 1.9 against a probe at 2.0 is 500 bps worse."""
    probe["out"] = 20
    got = uniswap.price_impact_bps(
        None, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 10_000, 19_000  # type: ignore[arg-type]
    )
    assert got == pytest.approx(500.0)
    assert probe["asked"] == [10]


def test_price_impact_never_goes_negative(probe: dict) -> None:
    """A probe that rounds down must not make a fill look better than free."""
    probe["out"] = 1
    got = uniswap.price_impact_bps(
        None, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 5, 10  # type: ignore[arg-type]
    )
    assert got == 0.0
    assert probe["asked"] == [1]


def test_price_impact_refuses_a_zero_probe(probe: dict) -> None:
    """No probe rate, no impact figure: refuse rather than report zero."""
    probe["out"] = 0
    with pytest.raises(evm.SwapError, match="probe .* quoted zero"):
        uniswap.price_impact_bps(
            None, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 10_000, 1  # type: ignore[arg-type]
        )


def test_price_impact_refuses_a_non_positive_fill(probe: dict) -> None:
    """A zero-size fill has no average rate, so it is refused before any probe."""
    with pytest.raises(evm.SwapError, match="0-unit fill"):
        uniswap.price_impact_bps(
            None, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 0, 0  # type: ignore[arg-type]
        )
    assert not probe["asked"]


@pytest.mark.parametrize("slippage", [0.0, 0.5, evm.MAX_SLIPPAGE])
def test_check_slippage_accepts_the_range(slippage: float) -> None:
    """Both ends of 0..MAX_SLIPPAGE are allowed."""
    evm.check_slippage(slippage)


@pytest.mark.parametrize("slippage", [-0.1, 5.1, 100.0, float("nan")])
def test_check_slippage_refuses_outside_the_range(slippage: float) -> None:
    """A negative or loose floor is refused."""
    with pytest.raises(evm.SwapError, match="not slippage protection"):
        evm.check_slippage(slippage)


@pytest.mark.parametrize(
    ("amount", "slippage", "floor"),
    [(10**18, 0.0, 10**18), (10**18, 0.5, 995 * 10**15), (12345, 0.1, 12332)],
)
def test_apply_slippage_floors_the_amount(
    amount: int, slippage: float, floor: int
) -> None:
    """The floor is exact in Decimal and rounds down."""
    assert evm.apply_slippage(amount, slippage) == floor


def test_print_dry_run_prints_one_line_per_call(
    capsys: pytest.CaptureFixture,
) -> None:
    """Each call prints its target, value (zero when absent) and calldata head."""
    data = "0x" + "ab" * 40
    evm.print_dry_run(
        [
            {"to": TOKEN, "data": data, "what": "approve"},
            {"to": WETH, "data": "0x", "what": "wrap ETH", "value": 7},
        ]
    )
    assert capsys.readouterr().out.splitlines() == [
        f"dry-run approve: to={TOKEN} value=0 data={data[:74]}...",
        f"dry-run wrap ETH: to={WETH} value=7 data=0x...",
    ]


def _fake_permit(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    """Sign permits without a network, recording what was asked."""
    asked: list[tuple] = []

    def _signed(*args: t.Any, **kwargs: t.Any) -> bytes:
        """Build a well-formed permit for exactly what was asked."""
        asked.append((*args, kwargs))
        token, amount, spender, expiry = args[3], args[4], args[6], args[7]
        return permit.permit_input(
            permit.PermitDetails(token, amount, expiry, 0), spender, expiry, b"s"
        )

    monkeypatch.setattr(permit, "signed_action", _signed)
    return asked


def test_router_swap_with_the_native_coin_needs_no_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ETH in: one call, carrying the amount as value, and nothing to sign."""
    asked = _fake_permit(monkeypatch)
    monkeypatch.setattr(router.time, "time", lambda: 1_000)
    routed = router.router_swap(
        None, object(), SAFE, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 10, 9, False
    )
    assert not asked
    assert routed.permit == router.PERMIT_NONE
    assert routed.deadline == 1_000 + router.DEADLINE_S
    [call] = routed.calls
    assert call["to"] == WHERE["universal_router"]
    assert call["value"] == 10
    assert uniswap.permit_action_in(call["data"]) is None


def test_router_swap_folds_the_permit_for_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token in with a signer: one approval, the permit inside the swap."""
    asked = _fake_permit(monkeypatch)
    monkeypatch.setattr(router.time, "time", lambda: 1_000)
    routed = router.router_swap(
        None, object(), SAFE, CHAIN_ID, V4_POOL, TOKEN, NATIVE, 10, 9, False, 1
    )
    assert routed.permit == router.PERMIT_SIGNED
    assert routed.deadline == 1_000 + router.DEADLINE_S + 2 * evm.RECEIPT_TIMEOUT_S
    assert [c["what"] for c in routed.calls] == ["approve Permit2", "swap"]
    assert all("value" not in c for c in routed.calls)
    assert asked[0][2:] == (
        SAFE,
        TOKEN,
        10,
        WHERE["permit2"],
        WHERE["universal_router"],
        routed.deadline,
        {"placeholder": False},
    )


def test_router_swap_dry_run_asks_for_a_placeholder_permit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dry run builds the same two calls, labelled as signed at send time."""
    asked = _fake_permit(monkeypatch)
    routed = router.router_swap(
        None,
        object(),
        SAFE,
        CHAIN_ID,
        V4_POOL,
        TOKEN,
        NATIVE,
        10,
        9,
        False,
        dry_run=True,
    )
    assert asked[0][-1] == {"placeholder": True}
    assert routed.permit == router.PERMIT_AT_SEND
    assert [c["what"] for c in routed.calls] == ["approve Permit2", "swap"]


class _PermitW3:
    """A web3 on a renumbered fork, answering the reads signed_action makes."""

    chain_id = 9_994_663

    def __init__(self) -> None:
        """Answer as a safe with no Permit2 allowance yet."""
        self.eth = self

    def call(self, tx: dict) -> bytes:
        """Permit2 gets a zero allowance; the safe gets its domain separator."""
        return bytes(96) if tx["to"] == WHERE["permit2"] else b"\x11" * 32


class _DigestSigner:
    """Records the digests it signs."""

    def __init__(self) -> None:
        """Start with nothing signed."""
        self.digests: list[bytes] = []

    def sign_digest(self, digest: bytes) -> str:
        """Record and answer a recognisable signature."""
        self.digests.append(digest)
        return "0x" + "ab" * 65


def _permit_for(signer: _DigestSigner, placeholder: bool) -> bytes:
    """Run the real signed_action against the fork stub."""
    return permit.signed_action(
        _PermitW3(),
        signer,
        SAFE,
        TOKEN,
        10,
        WHERE["permit2"],
        WHERE["universal_router"],
        99,
        placeholder=placeholder,
    )


def test_signed_action_signs_for_the_chain_the_node_reports() -> None:
    """Permit2 checks the digest against the chain it runs on, not the skill's."""
    signer = _DigestSigner()
    details, spender, deadline = permit.decode_action(_permit_for(signer, False))
    digest = permit.permit_single_digest(
        _PermitW3.chain_id, WHERE["permit2"], details, spender, deadline
    )
    assert signer.digests == [permit.safe_message_digest(b"\x11" * 32, digest)]


def test_signed_action_placeholder_never_asks_the_signer() -> None:
    """A dry run's permit carries 65 zero bytes and signs nothing."""
    signer = _DigestSigner()
    action = _permit_for(signer, True)
    _, signature = abi_decode([permit.PERMIT_SINGLE_ABI, "bytes"], action)
    assert signature == permit.PLACEHOLDER_SIGNATURE == bytes(65)
    assert signer.digests == []


@pytest.mark.parametrize("signer", [None, object()])
def test_router_swap_approves_on_chain_when_not_folding(
    monkeypatch: pytest.MonkeyPatch, signer: t.Any
) -> None:
    """No signer, or separate approvals asked for: two approvals, no permit."""
    asked = _fake_permit(monkeypatch)
    monkeypatch.setattr(router.time, "time", lambda: 1_000)
    routed = router.router_swap(
        None, signer, SAFE, CHAIN_ID, V3_POOL, WETH, TOKEN, 10, 9, signer is not None
    )
    assert not asked
    assert routed.permit == router.PERMIT_SEPARATE
    assert routed.deadline == 1_000 + router.DEADLINE_S + 2 * evm.RECEIPT_TIMEOUT_S
    assert [c["what"] for c in routed.calls] == [
        "approve Permit2",
        "approve router",
        "swap",
    ]
    assert routed.calls[1]["to"] == WHERE["permit2"]


def test_router_swap_refuses_a_permit_missing_from_the_calldata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A signed permit the calldata dropped must not reach the signer."""
    _fake_permit(monkeypatch)
    monkeypatch.setattr(uniswap, "permit_action_in", lambda _calldata: None)
    with pytest.raises(evm.SwapError, match="not in the calldata"):
        router.router_swap(
            None, object(), SAFE, CHAIN_ID, V4_POOL, TOKEN, NATIVE, 10, 9, False
        )


def test_router_swap_refuses_a_permit_nobody_asked_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Calldata carrying an unrequested permit is not what was planned."""
    monkeypatch.setattr(uniswap, "permit_action_in", lambda _calldata: b"p")
    with pytest.raises(evm.SwapError, match="nobody asked for"):
        router.router_swap(
            None, None, SAFE, CHAIN_ID, V4_POOL, NATIVE, TOKEN, 10, 9, False
        )


def test_router_approvals_are_exact() -> None:
    """Both approvals name the amount, never an unlimited allowance."""
    erc20, permit2 = router.approval_calls(CHAIN_ID, TOKEN, 1_234, 99)
    assert abi_decode(["address", "uint256"], bytes.fromhex(erc20["data"][10:])) == (
        WHERE["permit2"].lower(),
        1_234,
    )
    decoded = abi_decode(
        ["address", "address", "uint160", "uint48"], bytes.fromhex(permit2["data"][10:])
    )
    assert decoded == (TOKEN.lower(), WHERE["universal_router"].lower(), 1_234, 99)


class _Record(t.NamedTuple):
    """A record whose fields carry their ABI types."""

    who: t.Annotated[str, "address"]
    amount: t.Annotated[int, "uint256"]


def test_abi_tuple_reads_the_field_annotations() -> None:
    """The tuple type follows the fields in order."""
    assert evm.abi_tuple(_Record) == "(address,uint256)"


def test_encode_call_prefixes_the_selector() -> None:
    """The selector leads the ABI-encoded arguments."""
    data = evm.encode_call(evm.SEL_BALANCE_OF, ["address"], [SAFE])
    assert data[:4] == evm.SEL_BALANCE_OF
    assert abi_decode(["address"], data[4:]) == (SAFE.lower(),)
    assert evm.encode_call(evm.SEL_DECIMALS, [], []) == evm.SEL_DECIMALS


def test_token_identity_reads_name_symbol_and_decimals() -> None:
    """Each read is its own call on the token."""
    answers = {
        evm.SEL_NAME: abi_encode(["string"], ["Pons"]),
        evm.SEL_SYMBOL: abi_encode(["string"], ["PONS"]),
        evm.SEL_DECIMALS: (6).to_bytes(32, "big"),
    }
    w3 = _CallW3()
    w3.call = lambda tx: answers[bytes(tx["data"])]  # type: ignore[method-assign]
    assert evm.token_identity(w3, USDG) == ("Pons", "PONS", 6)  # type: ignore[arg-type]
    assert evm.asset_info(w3, USDG) == ("PONS", 6)  # type: ignore[arg-type]


def test_asset_info_names_the_native_coin_without_a_call() -> None:
    """address(0) is ETH with native decimals."""
    w3 = _CallW3()
    assert evm.asset_info(w3, NATIVE) == ("ETH", 18)  # type: ignore[arg-type]
    assert not w3.calls


def test_call_string_refuses_a_non_string() -> None:
    """An answer that is not an ABI string is refused."""
    w3 = _CallW3(answer=(10**6).to_bytes(32, "big"))
    with pytest.raises(evm.SwapError, match="not \\['string'\\]"):
        evm.call_string(w3, USDG, evm.SEL_NAME)  # type: ignore[arg-type]


def test_decode_string_result_tells_revert_from_garbage(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A reverted read is empty; an undecodable one is None and noted."""
    assert evm.decode_string_result(True, abi_encode(["string"], ["x"]), "a") == "x"
    assert evm.decode_string_result(False, b"", "a") == ""
    assert not capsys.readouterr().err
    assert evm.decode_string_result(True, b"\x01", "USDG's name") is None
    assert "NOTE: USDG's name did not decode" in capsys.readouterr().err


def test_multicall3_is_the_canonical_deployment() -> None:
    """The aggregate3 selector and address are the well-known ones."""
    assert evm.MULTICALL3 == "0xcA11bde05977b3631167028862bE2a173976CA11"
    assert evm.SEL_AGGREGATE3.hex() == "82ad56cb"


def test_parse_bytes32_draws_fresh_bytes_when_none_is_given() -> None:
    """Without the flag each call gets its own random 32 bytes."""
    first, second = evm.parse_bytes32(None, "--salt"), evm.parse_bytes32(None, "--salt")
    assert len(first) == len(second) == 32
    assert first != second
    assert evm.parse_bytes32("0x" + "ab" * 32, "--salt") == b"\xab" * 32


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("0x" + "ab" * 31, "--salt must be 0x and 64 hex digits"),
        ("ab" * 32, "64 hex digits"),
        ("0x" + "ab" * 33, "64 hex digits"),
        ("0x" + "zz" * 32, "--salt is not hex"),
    ],
)
def test_parse_bytes32_refuses_malformed_text(text: str, match: str) -> None:
    """Anything but exactly 32 bytes of 0x-hex is refused, naming the flag."""
    with pytest.raises(evm.SwapError, match=match):
        evm.parse_bytes32(text, "--salt")


@pytest.mark.parametrize("limit", [0.0, -1.0, evm.MAX_IMPACT_CEILING_BPS + 1, math.nan])
def test_check_impact_limit_refuses_outside_the_range(limit: float) -> None:
    """A limit of zero or past the ceiling would switch the guard off."""
    with pytest.raises(evm.SwapError, match="price-impact limit"):
        evm.check_impact_limit(limit)


def test_check_impact_limit_accepts_the_range() -> None:
    """The default and the ceiling are both usable."""
    evm.check_impact_limit(evm.DEFAULT_MAX_IMPACT_BPS)
    evm.check_impact_limit(evm.MAX_IMPACT_CEILING_BPS)


class _Unavailable(RuntimeError):
    """The caller's own error type."""


@pytest.mark.parametrize(
    ("doc", "kinds", "match"),
    [
        ({}, (int,), "item has no usable 'n'"),
        ({"n": True}, (int,), "item has no usable 'n'"),
        ({"n": "1"}, (int,), "item 'n' is str"),
    ],
)
def test_check_json_type_raises_the_callers_error(
    doc: dict, kinds: tuple, match: str
) -> None:
    """A missing, boolean or mistyped field raises the error the caller chose."""
    with pytest.raises(_Unavailable, match=match):
        web.check_json_type(doc, "n", kinds, _Unavailable, "item")


def test_check_json_type_accepts_matching_fields() -> None:
    """A bool passes where bool is allowed, and None where None is."""
    web.check_json_type({"n": 1}, "n", (int,), _Unavailable, "item")
    web.check_json_type({"n": True}, "n", (bool,), _Unavailable, "item")
    web.check_json_type({"n": None}, "n", (str, type(None)), _Unavailable, "item")


def test_html_text_keeps_only_visible_words() -> None:
    """Tags go, entities decode, whitespace collapses, case folds."""
    raw = b"<p>No  Audit</p>\n<b>has&nbsp;closed &amp; more</b>"
    assert web.html_text(raw) == "no audit has closed & more"


@pytest.mark.parametrize(
    ("compact", "text"),
    [(True, '{"a":[1,2]}'), (False, '{\n  "a": [\n    1,\n    2\n  ]\n}')],
)
def test_write_json_atomic_replaces_the_file(
    tmp_path: Path, compact: bool, text: str
) -> None:
    """The file ends up whole, in the chosen format, with no scratch left."""
    path = tmp_path / "doc.json"
    path.write_text("old", encoding="utf-8")
    state.write_json_atomic(path, {"a": [1, 2]}, compact=compact)
    assert path.read_text(encoding="utf-8") == text
    assert not (tmp_path / "doc.tmp").exists()


def test_print_json_and_print_plan(capsys: pytest.CaptureFixture[str]) -> None:
    """Documents print as indented JSON; a plan drops its raw calls."""
    cli.print_json({"path": Path("x")})
    assert json.loads(capsys.readouterr().out) == {"path": "x"}
    cli.print_plan({"side": "buy", "calls": [{"to": SAFE}]})
    assert json.loads(capsys.readouterr().out) == {"side": "buy"}


AGENT = "test-agent/1"
IMAGE = "ipfs://bafkreiar3qgowwjij2a2cccofut7lxba6r55tzrz7oaawcizngeuct55je"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + (512).to_bytes(4, "big") * 2 + b"\0" * 20
JPEG = (
    b"\xff\xd8"
    + b"\xff\xe0\x00\x04ab"
    + b"\xff\xc0\x00\x11\x08"
    + (300).to_bytes(2, "big")
    + (400).to_bytes(2, "big")
    + b"\0" * 10
)
WEBP_X = b"RIFF\0\0\0\0WEBPVP8X" + b"\0" * 8 + (99).to_bytes(3, "little") * 2
WEBP_LOSSY = (
    b"RIFF\0\0\0\0WEBPVP8 "
    + b"\0" * 7
    + b"\x9d\x01\x2a"
    + (64).to_bytes(2, "little")
    + (32).to_bytes(2, "little")
)
WEBP_LOSSLESS = (
    b"RIFF\0\0\0\0WEBPVP8L"
    + b"\0" * 4
    + b"\x2f"
    + ((20 - 1) | ((10 - 1) << 14)).to_bytes(4, "little")
)


@pytest.mark.parametrize(
    ("body", "kind", "size"),
    [
        (PNG, "image/png", (512, 512)),
        (JPEG, "image/jpeg", (400, 300)),
        (WEBP_X, "image/webp", (100, 100)),
        (WEBP_LOSSY, "image/webp", (64, 32)),
        (WEBP_LOSSLESS, "image/webp", (20, 10)),
        (b"\x89PNG\r\n\x1a\n" + b"\0" * 30, "image/png", None),
        (b"\xff\xd8\xff\xd9", "image/jpeg", None),
        (b"RIFF\0\0\0\0WEBPABCD" + b"\0" * 20, "image/webp", None),
    ],
)
def test_image_type_and_size(body: bytes, kind: str, size: t.Any) -> None:
    """Magic bytes pick the type; headers give the size when simple."""
    assert ipfs.image_type(body) == kind
    assert ipfs.image_size(kind, body) == size


def test_image_type_rejects_others() -> None:
    """A GIF is not an accepted image."""
    assert ipfs.image_type(b"GIF89a....") is None


class FakeResponse(io.BytesIO):
    """A urlopen response with headers."""

    def __init__(self, body: bytes, content_type: str, length: t.Optional[str]) -> None:
        """Hold the body and headers."""
        super().__init__(body)
        self.headers = Message()
        self.headers["content-type"] = content_type
        if length is not None:
            self.headers["content-length"] = length


def serve(
    monkeypatch: pytest.MonkeyPatch,
    responses: dict[str, t.Any],
) -> list[str]:
    """Answer urlopen per gateway prefix; return the URLs asked."""
    asked: list[str] = []

    def urlopen(request: t.Any, timeout: int) -> FakeResponse:
        """One canned response."""
        assert timeout == ipfs.TIMEOUT_S
        assert request.get_header("User-agent") == AGENT
        asked.append(request.full_url)
        for prefix, answer in responses.items():
            if request.full_url.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return FakeResponse(*answer)
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(ipfs.urllib.request, "urlopen", urlopen)
    return asked


def test_check_image_falls_back_across_gateways(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failing gateway is skipped; the next one's answer is checked."""
    first, second = ipfs.GATEWAYS[:2]
    asked = serve(
        monkeypatch,
        {
            first: urllib.error.HTTPError(first, 429, "busy", Message(), None),
            second: (PNG, "image/png; charset=binary", str(len(PNG))),
        },
    )
    report = ipfs.check_image(IMAGE + "/logo.png", AGENT)
    assert asked == [first + IMAGE[7:] + "/logo.png", second + IMAGE[7:] + "/logo.png"]
    assert report["square"] is True
    assert report["bytes"] == len(PNG)
    assert report["width"] == 512


def test_check_image_skips_a_dropped_response(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gateway that drops the response mid-way falls through to the next."""
    first, second = ipfs.GATEWAYS[:2]
    serve(
        monkeypatch,
        {
            first: http.client.IncompleteRead(b"\x89PNG"),
            second: (PNG, "image/png", str(len(PNG))),
        },
    )
    assert ipfs.check_image(IMAGE, AGENT)["width"] == 512


def test_check_image_reports_a_non_square_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A usable non-square image passes, marked as such."""
    serve(monkeypatch, {ipfs.GATEWAYS[0]: (JPEG, "image/jpeg", None)})
    assert ipfs.check_image(IMAGE, AGENT)["square"] is False


def test_check_image_without_dimensions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unreadable dimensions are reported as unknown, not as a failure."""
    body = b"\xff\xd8\xff\xd9"
    serve(monkeypatch, {ipfs.GATEWAYS[0]: (body, "image/jpeg", "abc")})
    report = ipfs.check_image(IMAGE, AGENT)
    assert report["width"] is None
    assert report["square"] is None


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        ((b"", "image/png", str(ipfs.IMAGE_MAX_BYTES)), "under 5 MB"),
        ((b"\0" * ipfs.IMAGE_MAX_BYTES, "image/png", None), "under 5 MB"),
        ((PNG, "text/html", None), "gateway says text/html"),
        ((b"GIF89a", "image/gif", None), "looks like something else"),
        ((PNG, "image/jpeg", None), "looks like image/png"),
    ],
)
def test_check_image_refuses_bad_files(
    monkeypatch: pytest.MonkeyPatch, answer: t.Any, match: str
) -> None:
    """Oversized or wrongly typed files are refused outright."""
    asked = serve(monkeypatch, {ipfs.GATEWAYS[0]: answer})
    with pytest.raises(evm.SwapError, match=match):
        ipfs.check_image(IMAGE, AGENT)
    assert len(asked) == 1


def test_check_image_refuses_unresolvable_and_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No gateway serving it, or a non-IPFS URI, is refused."""
    asked = serve(monkeypatch, {})
    with pytest.raises(evm.SwapError, match="no gateway served"):
        ipfs.check_image(IMAGE, AGENT)
    assert len(asked) == len(ipfs.GATEWAYS)
    for bad in ("https://example.org/logo.png", "ipfs://short", IMAGE + "?x=1"):
        with pytest.raises(evm.SwapError, match="not an ipfs:// URI"):
            ipfs.check_image(bad, AGENT)


def test_read_web3_prefers_the_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    """With a signer, reads use its RPC."""
    marker = object()
    monkeypatch.setattr(evm, "connect", lambda chain: (marker, None))
    assert evm.read_web3("robinhood", "https://rpc.example") is marker


def test_read_web3_falls_back_to_the_public_rpc(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without a signer, reads go to the public RPC and say so."""

    def _missing(chain: str) -> None:
        """No workspace here."""
        raise FileNotFoundError(".mcp.json not found")

    monkeypatch.setattr(evm, "connect", _missing)
    w3 = evm.read_web3("robinhood", "https://rpc.example")
    assert w3.provider.endpoint_uri == "https://rpc.example"
    assert "reading from https://rpc.example" in capsys.readouterr().err


def test_multicall_allows_each_call_to_fail() -> None:
    """Every call is sent with allowFailure, and the results come back in order."""
    results = ((True, b"a"), (False, b""))
    w3 = _CallW3(answer=abi_encode(["(bool,bytes)[]"], [results]))
    assert evm.multicall(w3, [(USDG, b"\x01"), (WETH, b"\x02")]) == results  # type: ignore[arg-type]
    data = bytes(w3.calls[0]["data"])
    assert w3.calls[0]["to"] == evm.MULTICALL3
    assert data[:4] == evm.SEL_AGGREGATE3
    (sent,) = abi_decode(["(address,bool,bytes)[]"], data[4:])
    assert sent == ((USDG.lower(), True, b"\x01"), (WETH.lower(), True, b"\x02"))


def test_multicall_refuses_a_short_answer() -> None:
    """Fewer results than calls cannot be lined up with the calls."""
    w3 = _CallW3(answer=abi_encode(["(bool,bytes)[]"], [[(True, b"")]]))
    with pytest.raises(evm.SwapError, match="answered 1 results for 2 calls"):
        evm.multicall(w3, [(USDG, b""), (WETH, b"")])  # type: ignore[arg-type]


ERRORS = {
    evm.selector(signature): signature
    for signature in (
        "Error(string)",
        "Paused()",
        "Mismatch(bytes32,bytes32)",
        "Slippage(uint256,uint256)",
    )
}


def test_describe_revert_names_known_errors() -> None:
    """Known errors are named with their arguments; others pass through."""
    paused = "0x" + evm.selector("Paused()").hex()
    assert evm.describe_revert(paused, ERRORS) == "Paused()"
    mismatch = evm.selector("Mismatch(bytes32,bytes32)") + b"\x01" * 32 + b"\x02" * 32
    assert evm.describe_revert("0x" + mismatch.hex(), ERRORS) == (
        f"Mismatch(0x{'01' * 32}, 0x{'02' * 32})"
    )
    slip = evm.selector("Slippage(uint256,uint256)") + abi_encode(
        ["uint256", "uint256"], [5, 6]
    )
    assert evm.describe_revert("0x" + slip.hex(), ERRORS) == "Slippage(5, 6)"
    reason = evm.selector("Error(string)") + abi_encode(["string"], ["some reason"])
    assert evm.describe_revert("0x" + reason.hex(), ERRORS) == "Error(some reason)"
    assert evm.describe_revert("0xdeadbeef", ERRORS) == "0xdeadbeef"
    assert evm.describe_revert(None, ERRORS) == "None"


SIMULATED: evm.Call = {"to": USDG, "data": "0x01", "what": "launch", "value": 5}


def test_simulate_call_returns_the_raw_answer() -> None:
    """A dry run is made as the sender, with the call's value."""
    w3 = _CallW3(answer=b"\x07" * 64)
    assert evm.simulate_call(w3, SIMULATED, SAFE, ERRORS) == b"\x07" * 64  # type: ignore[arg-type]
    assert w3.calls == [{"from": SAFE, "to": USDG, "data": "0x01", "value": 5}]


class _FailingW3:
    """A web3 whose eth_call raises."""

    def __init__(self, error: Exception) -> None:
        """Raise this on every call."""
        self.eth = self
        self._error = error

    def call(self, tx: dict) -> bytes:
        """Raise."""
        raise self._error


PAUSED = "0x" + evm.selector("Paused()").hex()


@pytest.mark.parametrize(
    ("error", "match"),
    [
        (ContractCustomError(PAUSED, data=PAUSED), r"launch would revert: Paused\(\)"),
        (Web3RPCError("down"), "launch could not be simulated: down"),
    ],
)
def test_simulate_call_names_why_it_failed(error: Exception, match: str) -> None:
    """A revert is named from the error table; other failures are refusals too."""
    with pytest.raises(evm.SwapError, match=match):
        evm.simulate_call(_FailingW3(error), SIMULATED, SAFE, ERRORS)  # type: ignore[arg-type]


class _HTTPError(OSError):
    """An HTTP failure carrying its response, as web3's provider raises it."""

    def __init__(self, status: int) -> None:
        """Carry a response with this status."""
        super().__init__(f"HTTP {status}")
        self.response = type("Response", (), {"status_code": status})()


class _LogsW3:
    """A web3 whose eth_getLogs raises queued errors, then answers."""

    def __init__(self, errors: list[Exception]) -> None:
        """Raise these, one per query, before answering."""
        self.eth = self
        self.errors = errors
        self.queries: list[t.Any] = []

    def get_logs(self, query: t.Any) -> list[t.Any]:
        """Record the query; raise the next error or answer its span."""
        self.queries.append(query)
        if self.errors:
            raise self.errors.pop(0)
        return [(query["fromBlock"], query["toBlock"])]


def test_get_logs_backs_off_while_throttled(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 429 is retried after a growing pause."""
    pauses: list[float] = []
    monkeypatch.setattr(evm.time, "sleep", pauses.append)
    w3 = _LogsW3([_HTTPError(429), _HTTPError(429)])
    query = {"fromBlock": 1, "toBlock": 2}
    assert evm.get_logs(w3, query, "hint", 2, 0.5) == [(1, 2)]  # type: ignore[arg-type]
    assert pauses == [0.5, 5.0, 50.0]


@pytest.mark.parametrize(
    ("errors", "match"),
    [
        ([_HTTPError(429)] * 3, "keeps throttling log queries; retry later"),
        ([_HTTPError(500)], "failed a log query"),
        ([ConnectionResetError("reset")], "failed a log query"),
    ],
)
def test_get_logs_gives_up_with_a_reason(
    monkeypatch: pytest.MonkeyPatch, errors: list[Exception], match: str
) -> None:
    """Persistent throttling and other failures are refusals."""
    monkeypatch.setattr(evm.time, "sleep", lambda _s: None)
    with pytest.raises(evm.SwapError, match=match):
        evm.get_logs(_LogsW3(errors), {}, "retry later", 2, 0)  # type: ignore[arg-type]


def test_get_logs_passes_node_errors_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """A node refusal stays a Web3RPCError so a scan can shrink its span."""
    monkeypatch.setattr(evm.time, "sleep", lambda _s: None)
    with pytest.raises(Web3RPCError):
        evm.get_logs(_LogsW3([Web3RPCError("too many")]), {}, "", 2, 0)  # type: ignore[arg-type]


def _scan(
    errors: list[Exception], forward: bool, budget: int = 10, min_chunk: int = 2
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], list[int]]:
    """Scan blocks 1..10 in chunks of 4; return spans asked, spans seen, budget."""
    asked: list[tuple[int, int]] = []
    seen: list[tuple[int, int]] = []

    def fetch(lo: int, hi: int) -> list[t.Any]:
        """Record the span; raise the next error."""
        asked.append((lo, hi))
        if errors:
            raise errors.pop(0)
        return [lo]

    def on_chunk(logs: list[t.Any], lo: int, hi: int) -> None:
        """Record what answered."""
        assert logs == [lo]
        seen.append((lo, hi))

    left = [budget]
    evm.scan_logs(fetch, 1, 10, forward, left, on_chunk, 4, min_chunk)
    return asked, seen, left


def test_scan_logs_walks_forward_and_halves_a_refused_chunk() -> None:
    """A refused span is retried at half size, and the scan carries on from it."""
    asked, seen, left = _scan([Web3RPCError("too many")], True)
    assert asked == [(1, 4), (1, 2), (3, 4), (5, 6), (7, 8), (9, 10)]
    assert seen == asked[1:]
    assert left == [4]


def test_scan_logs_walks_backward() -> None:
    """A backward scan starts at the top."""
    _, seen, _ = _scan([], False)
    assert seen == [(7, 10), (3, 6), (1, 2)]


def test_scan_logs_stops_when_the_budget_is_spent() -> None:
    """No request is made past the budget."""
    _, seen, left = _scan([], True, budget=2)
    assert seen == [(1, 4), (5, 8)]
    assert left == [0]


def test_scan_logs_refuses_when_even_the_smallest_chunk_fails() -> None:
    """A refused minimum-size span ends the scan with a reason."""
    with pytest.raises(evm.SwapError, match="refuses even 2-block"):
        _scan([Web3RPCError("too many")] * 2, True)


class _Page(io.BytesIO):
    """A urlopen response."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        """Hold a body and status."""
        super().__init__(body)
        self.status = status


def _serve_page(monkeypatch: pytest.MonkeyPatch, answer: t.Any) -> list[t.Any]:
    """Answer every urlopen with this page or error; return the requests."""
    asked: list[t.Any] = []

    def urlopen(request: t.Any, timeout: float) -> _Page:
        """One canned answer."""
        assert timeout == 7
        asked.append(request)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(web.urllib.request, "urlopen", urlopen)
    return asked


def test_get_sends_the_agent_and_returns_the_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The body comes back; the request names the agent and wanted type."""
    asked = _serve_page(monkeypatch, _Page(b"{}"))
    assert web.get("https://x.example/a", AGENT, 7) == b"{}"
    assert asked[0].get_header("User-agent") == AGENT
    assert asked[0].get_header("Accept") == "application/json"


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        (_Page(b"", 204), "answered HTTP 204"),
        (OSError("down"), "unreachable \\(OSError: down\\)"),
        (http.client.IncompleteRead(b""), "unreachable"),
    ],
)
def test_get_reports_an_unusable_answer(
    monkeypatch: pytest.MonkeyPatch, answer: t.Any, match: str
) -> None:
    """A non-200 status or a network failure is Unavailable."""
    _serve_page(monkeypatch, answer)
    with pytest.raises(web.Unavailable, match=match):
        web.get("https://x.example/a", AGENT, 7)


def test_page_text_reads_the_visible_words(monkeypatch: pytest.MonkeyPatch) -> None:
    """A page is fetched as HTML and reduced to its text."""
    asked = _serve_page(monkeypatch, _Page(b"<p>No&nbsp;Audit</p>"))
    assert web.page_text("https://x.example/docs", AGENT, 7) == "no audit"
    assert asked[0].get_header("Accept") == "text/html"


def test_read_json_builds_the_document(tmp_path: Path) -> None:
    """A readable file is parsed and built; a missing one is None, silently."""
    path = tmp_path / "doc.json"
    assert state.read_json(path, "starting over", lambda doc: doc) is None
    path.write_text('{"a": 1}', encoding="utf-8")
    assert state.read_json(path, "starting over", lambda doc: doc["a"]) == 1


@pytest.mark.parametrize(
    ("content", "problem"),
    [("{", "JSONDecodeError"), ('{"a": 1}', "KeyError: 'b'")],
)
def test_read_json_notes_an_unreadable_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str, problem: str
) -> None:
    """A file that does not parse or build is None, and says what happens next."""
    path = tmp_path / "doc.json"
    path.write_text(content, encoding="utf-8")
    assert state.read_json(path, "starting over", lambda doc: doc["b"]) is None
    err = capsys.readouterr().err
    assert f"NOTE: {path} is unreadable ({problem}" in err
    assert err.rstrip().endswith("; starting over")


def test_an_answer_round_trips(tmp_path: Path) -> None:
    """A recorded answer is stripped, timestamped and read back with its extras."""
    path = tmp_path / "answer.json"
    assert state.read_answer(path, "asking again") is None
    state.record_answer(path, "  Yes  ", audit=lambda: {"status": "unaudited"})
    doc = state.read_answer(path, "asking again")
    assert doc is not None
    assert doc["answer"] == "Yes"
    assert doc["audit"] == {"status": "unaudited"}
    assert doc["recorded_at"]


@pytest.mark.parametrize("answer", ["", "   "])
def test_an_empty_answer_is_refused_before_extras_run(
    tmp_path: Path, answer: str
) -> None:
    """Nothing is recorded, or computed, for an empty answer."""
    path = tmp_path / "answer.json"

    def _never() -> None:
        """Fail if called."""
        raise AssertionError("extra computed for an empty answer")

    with pytest.raises(evm.SwapError, match="the answer is empty"):
        state.record_answer(path, answer, audit=_never)
    assert not path.exists()


@pytest.mark.parametrize("content", ["[]", "null", '{"answer": ""}', '{"answer": 1}'])
def test_a_malformed_answer_does_not_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    """Only a non-empty string answer counts; anything else is named."""
    path = tmp_path / "answer.json"
    path.write_text(content, encoding="utf-8")
    assert state.read_answer(path, "asking again") is None
    assert "holds no non-empty answer); asking again" in capsys.readouterr().err


LIMITS = {"name": 4, "note": 2}


def test_check_byte_limits_counts_utf8_bytes() -> None:
    """Limits are in bytes, and required fields must be set."""
    fields = {"name": "", "note": ""}
    with pytest.raises(evm.SwapError, match="name must be non-empty"):
        cli.check_byte_limits(fields, LIMITS, ("name",))
    cli.check_byte_limits({**fields, "name": "éé"}, LIMITS, ("name",))
    with pytest.raises(evm.SwapError, match="name is 6 bytes; the limit is 4"):
        cli.check_byte_limits({**fields, "name": "ééé"}, LIMITS, ("name",))
    with pytest.raises(evm.SwapError, match="note is 3 bytes"):
        cli.check_byte_limits({"name": "n", "note": "abc"}, LIMITS, ())


def test_constant_product_matches_the_formula() -> None:
    """Output rounds down; the input for an exact output rounds up."""
    assert uniswap.constant_product_out(10, 100, 1000) == 90
    assert uniswap.constant_product_in(90, 100, 1000) == 10


@pytest.mark.parametrize(
    ("amount", "reserve_in", "reserve_out", "match"),
    [
        (0, 1, 1, "nothing is left to swap"),
        (1, 0, 1, "empty reserve"),
        (1, 1, 0, "empty reserve"),
        (1, 10**30, 10, "too small"),
    ],
)
def test_constant_product_out_refuses_what_cannot_fill(
    amount: int, reserve_in: int, reserve_out: int, match: str
) -> None:
    """No input, an empty side or a zero output is refused."""
    with pytest.raises(evm.SwapError, match=match):
        uniswap.constant_product_out(amount, reserve_in, reserve_out)


@pytest.mark.parametrize("reserve_out", [10, 9])
def test_constant_product_in_refuses_to_exhaust_the_reserve(reserve_out: int) -> None:
    """An output at or past the reserve is refused, not divided by."""
    with pytest.raises(evm.SwapError, match="cannot cover a 10-unit output"):
        uniswap.constant_product_in(10, 10**18, reserve_out)
