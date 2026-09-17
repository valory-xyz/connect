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

"""Pons V2 bonding curve: live state, exact quotes, and checked calldata."""

import typing as t

import evm
import pons
import uniswap
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
from web3 import Web3

BPS = 10_000
MIN_NET_BPS = 100

SEL_GET_RESERVES = evm.selector("getReserves()")
SEL_SELLABLE = evm.selector("sellableTokens()")
SEL_CREATOR_TAX_BPS = evm.selector("creatorTaxBps()")
SEL_SNIPE_TAX_BPS = evm.selector("currentSnipeTaxBps(address)")
SEL_READY = evm.selector("readyToGraduate()")
SEL_BUY = evm.selector("buy(uint256,uint256,address)")
SEL_SELL = evm.selector("sell(uint256,uint256,address)")
TRADE_ARGS = ["uint256", "uint256", "address"]


class CurveState(t.NamedTuple):
    """What a curve prices a trade against, as the contract reads it."""

    quote_reserve: int
    token_reserve: int
    sellable: int
    fee_bps: int
    creator_tax_bps: int
    snipe_tax_bps: int = 0
    ready_to_graduate: bool = False

    @classmethod
    def read(cls, w3: Web3, curve: str, recipient: str) -> "CurveState":
        """Read a live curve, with the snipe tax the recipient would pay."""
        address = to_checksum_address(curve)
        quote_reserve, token_reserve = evm.call_types(
            w3, address, SEL_GET_RESERVES, ["uint256", "uint256"]
        )
        snipe_data = evm.encode_call(
            SEL_SNIPE_TAX_BPS, ["address"], [to_checksum_address(recipient)]
        )
        return cls(
            quote_reserve=quote_reserve,
            token_reserve=token_reserve,
            sellable=evm.call_int(w3, address, SEL_SELLABLE),
            fee_bps=evm.call_int(w3, address, pons.SEL_FEE_BPS),
            creator_tax_bps=evm.call_int(w3, address, SEL_CREATOR_TAX_BPS),
            snipe_tax_bps=evm.call_int(w3, address, snipe_data),
            ready_to_graduate=bool(evm.call_int(w3, address, SEL_READY)),
        )

    @classmethod
    def fresh(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        supply: int,
        phantom_quote: int,
        graduation_threshold: int,
        fee_bps: int,
        creator_tax_bps: int,
    ) -> "CurveState":
        """Build the state a curve opens with under a launch config, untaxed.

        Raises:
            SwapError: when the config has no phantom reserve or threshold.
        """
        if phantom_quote + graduation_threshold <= 0:
            raise evm.SwapError("the launch config has no curve economics")
        reserved = supply * phantom_quote // (phantom_quote + graduation_threshold)
        return cls(phantom_quote, supply, supply - reserved, fee_bps, creator_tax_bps)


def effective_snipe_bps(state: CurveState) -> int:
    """Return the snipe tax a buy pays, capped so the buyer nets at least 1%."""
    if state.snipe_tax_bps == 0:
        return 0
    return min(
        state.snipe_tax_bps,
        BPS - state.fee_bps - state.creator_tax_bps - MIN_NET_BPS,
    )


def _net_of_fees(amount: int, state: CurveState, snipe_bps: int) -> int:
    """Take each fee leg off an amount, each floored on its own as the curve does."""
    return (
        amount
        - amount * state.fee_bps // BPS
        - amount * state.creator_tax_bps // BPS
        - amount * snipe_bps // BPS
    )


def buy_fill(state: CurveState, quote_in: int) -> tuple[int, int]:
    """Tokens a buy receives and the quote it spends, refund being the rest.

    Raises:
        SwapError: when the curve has nothing left to sell or the buy is too
            small to fill.
    """
    if state.sellable == 0:
        raise evm.SwapError("the curve has sold its allocation; it is graduating")
    snipe = effective_snipe_bps(state)
    tokens = uniswap.constant_product_out(
        _net_of_fees(quote_in, state, snipe),
        state.quote_reserve,
        state.token_reserve,
    )
    if tokens <= state.sellable:
        return tokens, quote_in
    net = uniswap.constant_product_in(
        state.sellable, state.quote_reserve, state.token_reserve
    )
    keep = BPS - state.fee_bps - state.creator_tax_bps - snipe
    grossed = -(-net * BPS // keep)
    return state.sellable, min(grossed, quote_in)


def quote_buy(state: CurveState, quote_in: int) -> int:
    """Tokens a buy of ``quote_in`` receives, clamped at the sellable allocation."""
    return buy_fill(state, quote_in)[0]


def quote_sell(state: CurveState, tokens_in: int) -> int:
    """Quote a sell of ``tokens_in`` returns after fees.

    Raises:
        SwapError: when the curve is closed to sells or the sell is too small.
    """
    if state.ready_to_graduate or state.sellable == 0:
        raise evm.SwapError(
            "the curve is ready to graduate and refuses sells; trade the pool "
            "once it exists"
        )
    gross = uniswap.constant_product_out(
        tokens_in, state.token_reserve, state.quote_reserve
    )
    return _net_of_fees(gross, state, 0)


def price_impact_bps(state: CurveState, amount: int, buying: bool) -> float:
    """Bps by which the fill is worse than the spot price, fees aside.

    Raises:
        SwapError: for a non-positive amount.
    """
    if amount <= 0:
        raise evm.SwapError(f"cannot measure price impact of a {amount}-unit fill")
    if buying:
        _, spent = buy_fill(state, amount)
        moved = _net_of_fees(spent, state, effective_snipe_bps(state))
        return moved * BPS / (state.quote_reserve + moved)
    return amount * BPS / (state.token_reserve + amount)


def _trade_call(selector: bytes, amount: int, minimum: int, recipient: str) -> str:
    """ABI-encode a curve buy or sell."""
    args = [amount, minimum, to_checksum_address(recipient)]
    return "0x" + evm.encode_call(selector, TRADE_ARGS, args).hex()


def verify_trade(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    call: evm.Call,
    buying: bool,
    curve: str,
    amount: int,
    minimum: int,
    recipient: str,
    value: int,
) -> None:
    """Decode a built curve call and check it is exactly the planned trade.

    Raises:
        SwapError: on any field that differs from the plan.
    """
    kind = "curve buy" if buying else "curve sell"
    raw = bytes.fromhex(call["data"].removeprefix("0x"))
    got_amount, got_minimum, got_recipient = abi_decode(TRADE_ARGS, raw[4:])
    evm.check_fields(
        kind,
        {
            "selector": (raw[:4], SEL_BUY if buying else SEL_SELL),
            "target": (to_checksum_address(call["to"]), to_checksum_address(curve)),
            "amount": (got_amount, amount),
            "minimum": (got_minimum, minimum),
            "recipient": (
                to_checksum_address(got_recipient),
                to_checksum_address(recipient),
            ),
            "value": (call.get("value", 0), value),
        },
    )
    if minimum <= 0:
        raise evm.SwapError(f"{kind} has no minimum output; that is no protection")


def buy_calls(
    curve: str, pair_token: str, quote_in: int, min_tokens_out: int, recipient: str
) -> list[evm.Call]:
    """Approve the curve (ERC-20 pair only) and buy, each call re-checked."""
    native = evm.is_native(pair_token)
    value = quote_in if native else 0
    buy: evm.Call = {
        "to": to_checksum_address(curve),
        "data": _trade_call(SEL_BUY, quote_in, min_tokens_out, recipient),
        "value": value,
        "what": "curve buy",
    }
    verify_trade(buy, True, curve, quote_in, min_tokens_out, recipient, value)
    if native:
        return [buy]
    approve = evm.erc20_approval_call(pair_token, curve, quote_in, "approve curve")
    return [approve, buy]


def sell_calls(
    curve: str, token: str, tokens_in: int, min_quote_out: int, recipient: str
) -> list[evm.Call]:
    """Approve the curve for the tokens and sell them, the sell re-checked."""
    sell: evm.Call = {
        "to": to_checksum_address(curve),
        "data": _trade_call(SEL_SELL, tokens_in, min_quote_out, recipient),
        "value": 0,
        "what": "curve sell",
    }
    verify_trade(sell, False, curve, tokens_in, min_quote_out, recipient, 0)
    approve = evm.erc20_approval_call(token, curve, tokens_in, "approve curve")
    return [approve, sell]


__all__ = [
    "CurveState",
    "buy_calls",
    "buy_fill",
    "effective_snipe_bps",
    "price_impact_bps",
    "quote_buy",
    "quote_sell",
    "sell_calls",
    "verify_trade",
]
