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

"""Unit tests for the connect-pons skill's curve math and trade planning.

The curve fixtures are live Robinhood Chain states, each paired with what an
eth_simulateV1 of the deployed curve returned for the same block.
"""

import json
import sys
import typing as t
from decimal import Decimal

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address

from tests.conftest import (
    curve,
    evm,
    pons,
    router,
    trade,
    uniswap,
)

SAFE = "0x00000000000000000000000000000000000b0b01"
CURVE = to_checksum_address("0x44a8a7293c41f172ab456893ec79ef41c15ee53d")
TOKEN = to_checksum_address("0xe95362360430Ed612879C642Ee44DeCDcA6B076A")

OPEN_STATE = curve.CurveState(
    1699285193809984184,
    988650996383517819135975132,
    702936710669232104850260847,
    100,
    200,
)
AFTER_BUY_STATE = curve.CurveState(
    1747785193809984184,
    961216519026448733660227705,
    675502233312163019374513420,
    100,
    200,
)
NEAR_END_STATE = curve.CurveState(
    2477042193421576231,
    678228253221391606441974716,
    392513967507105892156260431,
    100,
    200,
)


def test_quote_buy_matches_the_deployed_curve() -> None:
    """A plain buy fills exactly what the live curve filled."""
    assert curve.buy_fill(OPEN_STATE, 50000000000000000) == (
        27434477357069085475747427,
        50000000000000000,
    )


def test_quote_sell_matches_the_deployed_curve() -> None:
    """A sell returns exactly what the live curve paid out."""
    assert curve.quote_sell(AFTER_BUY_STATE, 6858619339267271368936856) == (
        12011228333830996
    )


def test_a_buy_past_the_allocation_is_clamped_and_refunded() -> None:
    """The fill stops at sellable and spends what the live curve spent."""
    tokens, spent = curve.buy_fill(NEAR_END_STATE, 9 * 10**18)
    assert tokens == NEAR_END_STATE.sellable
    assert spent == 3508203924307653696
    assert curve.quote_buy(NEAR_END_STATE, 9 * 10**18) == tokens


def test_a_fresh_curve_reserves_the_pools_allocation() -> None:
    """Launch config 0 opens with the sellable amount a fresh live curve shows."""
    state = curve.CurveState.fresh(10**27, 168 * 10**16, 42 * 10**17, 100, 0)
    assert state == (
        168 * 10**16,
        10**27,
        714285714285714285714285715,
        100,
        0,
        0,
        False,
    )


def test_snipe_tax_comes_off_the_input_and_is_capped() -> None:
    """A taxed buy nets less, and never less than 1% of the spend."""
    taxed = OPEN_STATE._replace(snipe_tax_bps=9900)
    assert curve.effective_snipe_bps(taxed) == 10_000 - 100 - 200 - 100
    assert curve.effective_snipe_bps(OPEN_STATE) == 0
    amount = 10**17
    net = amount - amount // 100 - amount * 2 // 100 - amount * 96 // 100
    expected = net * OPEN_STATE.token_reserve // (OPEN_STATE.quote_reserve + net)
    assert curve.quote_buy(taxed, amount) == expected


def test_a_clamped_taxed_buy_grosses_up_by_every_fee() -> None:
    """The refund repricing divides by what is left after the snipe tax too."""
    taxed = NEAR_END_STATE._replace(snipe_tax_bps=1000)
    _, spent = curve.buy_fill(taxed, 10**20)
    net = (
        taxed.sellable * taxed.quote_reserve // (taxed.token_reserve - taxed.sellable)
        + 1
    )
    assert spent == -(-net * 10_000 // (10_000 - 100 - 200 - 1000))


@pytest.mark.parametrize(
    ("state", "amount", "message"),
    [
        (OPEN_STATE._replace(sellable=0), 10**18, "sold its allocation"),
        (OPEN_STATE, 0, "nothing is left to swap"),
        (OPEN_STATE._replace(quote_reserve=0), 10**18, "empty reserve"),
        (curve.CurveState(10**30, 10, 10, 0, 0), 1, "too small"),
    ],
)
def test_buys_the_curve_would_revert_are_refused(
    state: curve.CurveState, amount: int, message: str
) -> None:
    """Every revert the contract's math has is a refusal here."""
    with pytest.raises(evm.SwapError, match=message):
        curve.buy_fill(state, amount)


@pytest.mark.parametrize(
    "state",
    [OPEN_STATE._replace(ready_to_graduate=True), OPEN_STATE._replace(sellable=0)],
)
def test_sells_are_refused_once_the_curve_is_ready(state: curve.CurveState) -> None:
    """The sell side closes as soon as the allocation is gone."""
    with pytest.raises(evm.SwapError, match="refuses sells"):
        curve.quote_sell(state, 10**18)


def test_a_fresh_curve_refuses_empty_economics() -> None:
    """A config with no phantom reserve or threshold has no curve to open."""
    with pytest.raises(evm.SwapError, match="no curve economics"):
        curve.CurveState.fresh(10**27, 0, 0, 100, 0)


@pytest.mark.parametrize("amount", [0, -1])
@pytest.mark.parametrize("buying", [True, False])
def test_price_impact_refuses_a_non_positive_amount(amount: int, buying: bool) -> None:
    """There is no impact to measure for a fill of nothing."""
    with pytest.raises(evm.SwapError, match="cannot measure price impact"):
        curve.price_impact_bps(OPEN_STATE, amount, buying)


def test_price_impact_measures_reserve_movement() -> None:
    """Impact is the share of the reserve the net trade adds."""
    buy = curve.price_impact_bps(OPEN_STATE, 10**18, True)
    net = 10**18 - 10**16 - 2 * 10**16
    assert buy == pytest.approx(net * 10_000 / (OPEN_STATE.quote_reserve + net))
    sell = curve.price_impact_bps(OPEN_STATE, 10**24, False)
    assert sell == pytest.approx(10**28 / (OPEN_STATE.token_reserve + 10**24))


class _CurveW3:
    """Answers the curve's views by selector."""

    def __init__(self, reserves: bytes) -> None:
        """Store the raw getReserves answer."""
        self.reserves = reserves
        self.eth = self
        self.snipe_for: list[str] = []

    def call(self, tx: dict) -> bytes:
        """Answer one view."""
        data = tx["data"]
        if data == curve.SEL_GET_RESERVES:
            return self.reserves
        if data[:4] == curve.SEL_SNIPE_TAX_BPS:
            self.snipe_for.append(abi_decode(["address"], data[4:])[0])
            return abi_encode(["uint256"], [42])
        answers = {
            curve.SEL_SELLABLE: 7,
            pons.SEL_FEE_BPS: 100,
            curve.SEL_CREATOR_TAX_BPS: 50,
            curve.SEL_READY: 1,
        }
        return abi_encode(["uint256"], [answers[data]])


def test_curve_state_reads_every_view() -> None:
    """The live read fills each field, keying the snipe tax to the recipient."""
    w3 = _CurveW3(abi_encode(["uint256", "uint256"], [11, 22]))
    state = curve.CurveState.read(t.cast(t.Any, w3), CURVE, SAFE)
    assert state == (11, 22, 7, 100, 50, 42, True)
    assert w3.snipe_for == [SAFE.lower()]


def test_curve_state_refuses_a_short_reserves_read() -> None:
    """An address that is not a curve does not read as empty reserves."""
    with pytest.raises(evm.SwapError, match=f"{CURVE} returned 32 bytes"):
        curve.CurveState.read(t.cast(t.Any, _CurveW3(b"\x00" * 32)), CURVE, SAFE)


def test_a_native_buy_is_one_call_carrying_the_value() -> None:
    """Native pairs pay by value and need no approval."""
    (call,) = curve.buy_calls(CURVE, evm.NATIVE, 5, 4, SAFE)
    assert call["value"] == 5
    assert call["to"] == CURVE
    assert bytes.fromhex(call["data"][2:10]) == curve.SEL_BUY


def test_an_erc20_buy_approves_exactly_then_buys_without_value() -> None:
    """ERC-20 pairs approve the curve for the spend and send no value."""
    approve, buy = curve.buy_calls(CURVE, pons.USDG, 5, 4, SAFE)
    assert approve["to"] == pons.USDG
    assert abi_decode(["address", "uint256"], bytes.fromhex(approve["data"][10:])) == (
        CURVE.lower(),
        5,
    )
    assert buy["value"] == 0


def test_a_sell_approves_the_tokens_then_sells() -> None:
    """The sell approval is for the token and the exact amount."""
    approve, sell = curve.sell_calls(CURVE, TOKEN, 9, 3, SAFE)
    assert approve["to"] == TOKEN
    assert bytes.fromhex(sell["data"][2:10]) == curve.SEL_SELL
    assert abi_decode(curve.TRADE_ARGS, bytes.fromhex(sell["data"][10:])) == (
        9,
        3,
        SAFE.lower(),
    )


@pytest.mark.parametrize(
    ("field", "kwargs"),
    [
        ("recipient", {"recipient": CURVE}),
        ("minimum", {"minimum": 3}),
        ("value", {"value": 0}),
        ("target", {"curve": TOKEN}),
        ("selector", {"buying": False}),
    ],
)
def test_verify_trade_refuses_any_drift(field: str, kwargs: dict) -> None:
    """Each decoded field must be the planned one."""
    (call,) = curve.buy_calls(CURVE, evm.NATIVE, 5, 4, SAFE)
    planned: dict = {
        "buying": True,
        "curve": CURVE,
        "amount": 5,
        "minimum": 4,
        "recipient": SAFE,
        "value": 5,
    }
    planned.update(kwargs)
    with pytest.raises(evm.SwapError, match=field):
        curve.verify_trade(call, **planned)


def test_a_trade_without_a_minimum_is_refused() -> None:
    """A zero floor is no protection, even when it matches the plan."""
    with pytest.raises(evm.SwapError, match="no minimum"):
        curve.sell_calls(CURVE, TOKEN, 9, 0, SAFE)


def _launch(**overrides: t.Any) -> pons.Launch:
    """Build a curve launch paired with native ETH."""
    launch: dict = {
        "token": TOKEN,
        "name": "Robo",
        "symbol": "XROBO",
        "decimals": 18,
        "generation": "v2",
        "factory": pons.V2_FACTORY,
        "phase": 0,
        "venue": "curve",
        "pair_token": evm.NATIVE,
        "pair_symbol": "ETH",
        "pair_decimals": 18,
        "curve": CURVE,
        "pool": None,
        "fee_bps": 100,
        "creator_tax_bps": 200,
        "deployer": SAFE,
        "buyback_enabled": False,
    }
    launch.update(overrides)
    return t.cast(pons.Launch, launch)


V4_POOL: uniswap.PoolV4 = {
    "version": "v4",
    "fee": 0,
    "tick_spacing": 200,
    "hooks": pons.MEME_HOOK,
    "pool_id": "0x" + "11" * 32,
    "liquidity": 1,
    "quote_address": evm.NATIVE,
}
V3_POOL: uniswap.PoolV3 = {
    "version": "v3",
    "fee": 10000,
    "address": CURVE,
    "quote_address": pons.WETH,
}


class _ChainW3:
    """Balances by token, native coin included."""

    def __init__(self, balances: dict[str, list[int]]) -> None:
        """Queue each token's successive balance reads."""
        self.balances = balances
        self.eth = self

    def _next(self, token: str) -> int:
        """Pop the next balance for a token, keeping the last one."""
        queue = self.balances[token.lower()]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def get_balance(self, _holder: str) -> int:
        """Return the native balance."""
        return self._next(evm.NATIVE)

    def call(self, tx: dict) -> bytes:
        """Answer balanceOf."""
        assert tx["data"][:4] == evm.SEL_BALANCE_OF
        return abi_encode(["uint256"], [self._next(tx["to"])])


REAL_TO_BASE_UNITS = evm.to_base_units
RICH = {evm.NATIVE: [10**30], TOKEN.lower(): [10**30], pons.WETH.lower(): [10**30]}


@pytest.fixture(name="on_curve")
def on_curve_fixture(monkeypatch: pytest.MonkeyPatch) -> curve.CurveState:
    """Serve OPEN_STATE for any curve read and record the V2 acknowledgement."""
    monkeypatch.setattr(
        curve.CurveState, "read", classmethod(lambda cls, *_a: OPEN_STATE)
    )
    monkeypatch.setattr(pons, "require_v2_ack", lambda: {"status": "unaudited"})
    return OPEN_STATE


def _plan(
    launch: pons.Launch, buying: bool, amount: int, **kwargs: t.Any
) -> trade.Plan:
    """Plan a trade with a signer and ample balances unless overridden."""
    args: dict = {
        "slippage": 0.5,
        "max_impact_bps": 500.0,
        "recipient": SAFE,
        "signer": object(),
        "separate_approvals": False,
    }
    w3 = kwargs.pop("w3", _ChainW3({k: list(v) for k, v in RICH.items()}))
    args.update(kwargs)
    return trade.plan_trade(t.cast(t.Any, w3), launch, buying, amount, **args)


def test_a_quote_builds_nothing_and_asks_nothing(on_curve: curve.CurveState) -> None:
    """Without a signer: no calls, no audit, no balance or impact refusal."""
    plan = _plan(_launch(), True, 10**20, signer=None, w3=_ChainW3({}))
    assert plan["calls"] == []
    assert plan["audit"] is None
    assert plan["price_impact_bps"] > 500
    assert plan["spent"] < plan["amount_in"] == 100.0


def test_a_curve_buy_is_priced_floored_and_built(on_curve: curve.CurveState) -> None:
    """The floor is the slippage off the exact quote, and the call carries it."""
    plan = _plan(_launch(), True, 5 * 10**16)
    out = curve.quote_buy(on_curve, 5 * 10**16)
    floor = out * 995 // 1000
    assert plan["expected_out"] == out / 10**18
    assert plan["audit"] == {"status": "unaudited"}
    (call,) = plan["calls"]
    assert abi_decode(curve.TRADE_ARGS, bytes.fromhex(call["data"][10:])) == (
        5 * 10**16,
        floor,
        SAFE.lower(),
    )


def test_a_curve_sell_approves_the_token(on_curve: curve.CurveState) -> None:
    """A sell spends the launch token, approving the curve for exactly that."""
    plan = _plan(_launch(), False, 10**24)
    assert [c["what"] for c in plan["calls"]] == ["approve curve", "curve sell"]
    assert plan["pay"] == "XROBO"
    assert plan["receive"] == "ETH"


def test_a_snipe_taxed_buy_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A curve still inside its launch window is not bought into."""
    taxed = OPEN_STATE._replace(snipe_tax_bps=2500)
    monkeypatch.setattr(curve.CurveState, "read", classmethod(lambda cls, *_a: taxed))
    monkeypatch.setattr(pons, "require_v2_ack", dict)
    with pytest.raises(evm.SwapError, match="snipe tax"):
        _plan(_launch(), True, 10**16)


def test_a_v2_trade_without_acknowledgement_is_refused(
    monkeypatch: pytest.MonkeyPatch, on_curve: curve.CurveState
) -> None:
    """The acknowledgement guard runs before anything is built."""

    def _refuse() -> dict:
        raise evm.SwapError("ask the operator")

    monkeypatch.setattr(pons, "require_v2_ack", _refuse)
    with pytest.raises(evm.SwapError, match="ask the operator"):
        _plan(_launch(), True, 10**16)


@pytest.mark.parametrize(
    ("kwargs", "amount", "message"),
    [
        ({"slippage": 5.1}, 10**16, "slippage"),
        ({"slippage": -1}, 10**16, "slippage"),
        ({"max_impact_bps": 0}, 10**16, "price-impact limit"),
        ({"max_impact_bps": 2001}, 10**16, "price-impact limit"),
        ({}, 10**20, "moves the price"),
        ({"slippage": 5.0}, 10**16, None),
        ({"w3": _ChainW3({evm.NATIVE: [1]})}, 10**16, "the safe holds"),
    ],
)
def test_plan_refuses_what_the_guards_refuse(
    on_curve: curve.CurveState, kwargs: dict, amount: int, message: t.Optional[str]
) -> None:
    """Limits, impact and balance each refuse on their own."""
    if message is None:
        assert _plan(_launch(), True, amount, **kwargs)["calls"]
        return
    with pytest.raises(evm.SwapError, match=message):
        _plan(_launch(), True, amount, **kwargs)


def test_a_dust_trade_has_no_floor_and_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A minimum that rounds to zero is refused rather than sent."""
    dust = curve.CurveState(10**6, 10, 10, 0, 0)
    monkeypatch.setattr(curve.CurveState, "read", classmethod(lambda cls, *_a: dust))
    monkeypatch.setattr(pons, "require_v2_ack", dict)
    with pytest.raises(evm.SwapError, match="too small to set"):
        _plan(_launch(), True, 200_000, slippage=5.0, max_impact_bps=2000.0)


@pytest.mark.parametrize(
    ("phase", "reason"), [(1, "graduating"), (3, "rescued"), (9, "phase 9")]
)
def test_a_launch_without_a_venue_is_refused(phase: int, reason: str) -> None:
    """Swept and rescued launches say why they cannot trade."""
    with pytest.raises(evm.SwapError, match=reason):
        _plan(_launch(venue="none", phase=phase, curve=None), True, 10**16)


def _stub_pool_quotes(monkeypatch: pytest.MonkeyPatch, impact: float = 12.5) -> list:
    """Quote any pool at 1000 out and record the router_swap calls."""
    seen: list = []

    def _best(
        _w3: t.Any, _chain: int, token_in: str, token_out: str, amount: int, pools: list
    ) -> tuple:
        seen.append(("route", token_in, token_out, amount, pools))
        return pools[0], 1000

    def _swap(*args: t.Any, **kwargs: t.Any) -> router.RouterSwap:
        seen.append(("swap", args, kwargs))
        return router.RouterSwap(
            [{"to": "0xrouter", "data": "0x", "what": "swap"}], 1, "signed"
        )

    monkeypatch.setattr(uniswap, "best_route", _best)
    monkeypatch.setattr(uniswap, "price_impact_bps", lambda *_a: impact)
    monkeypatch.setattr(router, "router_swap", _swap)
    monkeypatch.setattr(pons, "require_v2_ack", dict)
    return seen


def test_a_graduated_v2_token_trades_its_v4_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The v4 route spends native ETH straight into the pool."""
    seen = _stub_pool_quotes(monkeypatch)
    launch = _launch(venue="v4", phase=2, curve=None, pool=V4_POOL)
    plan = _plan(launch, True, 10**16)
    assert seen[0] == ("route", evm.NATIVE, TOKEN, 10**16, [V4_POOL])
    _, args, kwargs = seen[1]
    assert args[5:10] == (evm.NATIVE, TOKEN, 10**16, 995, False)
    assert kwargs == {"calls_ahead": 0, "dry_run": False}
    assert plan["permit"] == "signed"
    assert plan["price_impact_bps"] == 12.5


def test_a_pool_trade_past_the_impact_limit_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pool's measured impact is held to the same limit."""
    seen = _stub_pool_quotes(monkeypatch, impact=900.0)
    launch = _launch(venue="v4", phase=2, curve=None, pool=V4_POOL)
    with pytest.raises(evm.SwapError, match="moves the price"):
        _plan(launch, False, 10**16)
    assert seen == [("route", TOKEN, evm.NATIVE, 10**16, [V4_POOL])]


def test_a_pool_venue_without_a_pool_is_refused() -> None:
    """A record that says v4 but carries no pool cannot be routed."""
    with pytest.raises(evm.SwapError, match="has no Uniswap pool"):
        _plan(_launch(venue="v4", phase=2, pool=None), True, 10**16)


def test_a_v1_buy_wraps_eth_before_the_swap(monkeypatch: pytest.MonkeyPatch) -> None:
    """V1 pools trade WETH: wrap first, then swap WETH, deadline covering both."""
    seen = _stub_pool_quotes(monkeypatch)
    launch = _launch(
        generation="v1",
        venue="v3",
        phase=2,
        curve=None,
        pool=V3_POOL,
        pair_token=pons.WETH,
        pair_symbol="WETH",
        fee_bps=0,
    )
    plan = _plan(launch, True, 10**16, w3=_ChainW3({evm.NATIVE: [10**16]}))
    assert seen[0][1:3] == (pons.WETH, TOKEN)
    assert seen[1][2] == {"calls_ahead": 1, "dry_run": False}
    assert [c["what"] for c in plan["calls"]] == ["wrap ETH", "swap"]
    assert plan["calls"][0]["value"] == 10**16
    assert plan["audit"] is None
    assert plan["pay"] == "ETH"


def test_a_v1_sell_unwraps_exactly_what_the_swap_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The unwrap is sized from the WETH balance delta, after the swap confirms."""
    seen = _stub_pool_quotes(monkeypatch)
    launch = _launch(
        generation="v1",
        venue="v3",
        phase=2,
        curve=None,
        pool=V3_POOL,
        pair_token=pons.WETH,
        pair_symbol="WETH",
    )
    plan = _plan(launch, False, 10**18)
    assert plan["receive"] == "ETH"
    assert seen[0] == ("route", TOKEN, pons.WETH, 10**18, [V3_POOL])
    _, args, kwargs = seen[1]
    assert args[5:8] == (TOKEN, pons.WETH, 10**18)
    assert kwargs == {"calls_ahead": 0, "dry_run": False}
    assert [c["what"] for c in plan["calls"]] == ["swap"]
    sent: list = []

    def _send(_w3: t.Any, _signer: t.Any, calls: list) -> list[evm.Sent]:
        sent.append(calls)
        return [evm.Sent("ok", "0x1", {})]

    monkeypatch.setattr(evm, "send_calls", _send)
    w3 = _ChainW3({pons.WETH.lower(): [100, 175]})
    assert [s.what for s in trade.execute(t.cast(t.Any, w3), object(), SAFE, plan)] == [
        "ok",
        "ok",
    ]
    assert sent[1] == [evm.weth_withdraw_call(pons.WETH, 75)]
    w3 = _ChainW3({pons.WETH.lower(): [100, 100]})
    with pytest.raises(evm.SwapError, match="nothing to\\s+unwrap"):
        trade.execute(t.cast(t.Any, w3), object(), SAFE, plan)
    reads = iter([100])

    def _read_once(*_args: t.Any) -> int:
        """Answer the pre-swap read, then fail."""
        for balance in reads:
            return balance
        raise TimeoutError("rpc down")

    monkeypatch.setattr(evm, "raw_balance_of", _read_once)
    sent.clear()
    with pytest.raises(evm.SwapError, match="landed.*ok: 0x1.*still needs unwrapping"):
        trade.execute(t.cast(t.Any, w3), object(), SAFE, plan)
    assert len(sent) == 1


def test_execute_sends_a_curve_plan_as_is(
    monkeypatch: pytest.MonkeyPatch, on_curve: curve.CurveState
) -> None:
    """Anything but a V1 sell is just its calls, confirmed in order."""
    plan = _plan(_launch(), True, 10**16)
    monkeypatch.setattr(
        evm, "send_calls", lambda _w3, _s, calls: [c["what"] for c in calls]
    )
    assert trade.execute(t.cast(t.Any, _ChainW3({})), object(), SAFE, plan) == [
        "curve buy"
    ]


class _Signer:
    """A signer that knows the safe and refuses to send or sign."""

    def chain_info(self, _chain: str) -> dict:
        """Return the safe on the trading chain."""
        return {"safe": SAFE}

    def sign_digest(self, digest: bytes) -> str:
        """Fail: nothing in these tests may ask for a signature."""
        raise AssertionError(f"asked to sign {digest!r}")


@pytest.fixture(name="cli")
def cli_fixture(
    monkeypatch: pytest.MonkeyPatch, on_curve: curve.CurveState
) -> t.Callable[..., int]:
    """Run trade.main against a stubbed chain and signer."""
    w3 = _ChainW3({k: list(v) for k, v in RICH.items()})
    monkeypatch.setattr(pons, "launch_record", lambda _w3, _token: _launch())
    monkeypatch.setattr(evm, "read_web3", lambda chain, rpc: w3)
    monkeypatch.setattr(evm, "connect", lambda _chain: (w3, _Signer()))
    monkeypatch.setattr(
        evm, "to_base_units", lambda _w3, _t, whole: int(Decimal(str(whole)) * 10**18)
    )

    def _run(*argv: str) -> int:
        monkeypatch.setattr(sys, "argv", ["trade.py", *argv])
        return trade.main()

    return _run


def test_cli_quote_prints_the_plan(
    cli: t.Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    """Quote reads the chain only and prints the priced plan."""
    assert cli("quote", "--token", TOKEN, "--tokens", "1000") == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["side"] == "sell"
    assert printed["permit"] == "not built for a quote"


def test_cli_dry_run_prints_the_calls(
    cli: t.Callable[..., int], capsys: pytest.CaptureFixture[str]
) -> None:
    """A dry run prints what would be sent and sends nothing."""
    assert cli("buy", "--token", TOKEN, "--spend", "0.01", "--dry-run") == 0
    out = capsys.readouterr().out
    assert f"dry-run curve buy: to={CURVE} value={10**16}" in out


def test_cli_dry_run_mentions_the_v1_unwrap(
    cli: t.Callable[..., int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The unwrap cannot be built ahead, so the dry run says it follows."""
    _stub_pool_quotes(monkeypatch)
    launch = _launch(venue="v3", generation="v1", pool=V3_POOL, pair_token=pons.WETH)
    monkeypatch.setattr(pons, "launch_record", lambda _w3, _token: launch)
    assert cli("sell", "--token", TOKEN, "--tokens", "1", "--dry-run") == 0
    assert "dry-run unwrap WETH" in capsys.readouterr().out


@pytest.mark.parametrize(("flag", "dry_run"), [(("--dry-run",), True), ((), False)])
def test_cli_tells_the_router_whether_this_is_a_dry_run(
    cli: t.Callable[..., int],
    monkeypatch: pytest.MonkeyPatch,
    flag: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Only a dry run asks the router for a placeholder permit."""
    seen = _stub_pool_quotes(monkeypatch)
    launch = _launch(venue="v4", phase=2, curve=None, pool=V4_POOL)
    monkeypatch.setattr(pons, "launch_record", lambda _w3, _token: launch)
    monkeypatch.setattr(trade, "execute", lambda *_a: [])
    assert cli("sell", "--token", TOKEN, "--tokens", "1", *flag) == 0
    assert seen[1][2]["dry_run"] is dry_run


@pytest.mark.parametrize(
    ("argv", "match"),
    [
        (("quote", "--spend", "0"), "--spend must be positive"),
        (("buy", "--spend", "-1"), "--spend must be positive"),
        (("sell", "--tokens", "0"), "--tokens must be positive"),
        (("quote", "--tokens", "1e-19"), "less than one base unit"),
    ],
)
def test_cli_refuses_a_size_that_is_not_positive(
    cli: t.Callable[..., int],
    capsys: pytest.CaptureFixture[str],
    argv: tuple[str, ...],
    match: str,
) -> None:
    """A size of zero or below, or below one base unit, is refused up front."""
    assert cli(argv[0], "--token", TOKEN, *argv[1:]) == 1
    assert match in capsys.readouterr().err


def test_cli_refuses_an_infinite_size(
    cli: t.Callable[..., int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An infinite size, which argparse accepts, is refused instead of overflowing."""
    monkeypatch.setattr(evm, "to_base_units", REAL_TO_BASE_UNITS)
    assert cli("quote", "--token", TOKEN, "--spend", "inf") == 1
    assert "refused: inf is not a finite amount" in capsys.readouterr().err


def test_cli_sell_sends_and_a_refusal_exits_nonzero(
    cli: t.Callable[..., int],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A real run sends; a refused one reports why on stderr."""
    sent: list = []

    def _send(_w3: t.Any, _signer: t.Any, calls: list) -> list[str]:
        sent.extend(calls)
        return []

    monkeypatch.setattr(evm, "send_calls", _send)
    assert cli("sell", "--token", TOKEN, "--tokens", "1000") == 0
    assert [c["what"] for c in sent] == ["approve curve", "curve sell"]
    assert cli("buy", "--token", TOKEN, "--spend", "1", "--slippage", "9") == 1
    assert "refused: slippage" in capsys.readouterr().err
