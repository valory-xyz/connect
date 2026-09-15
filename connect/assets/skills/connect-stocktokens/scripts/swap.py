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

"""Quote and swap Robinhood Chain stock tokens through the Universal Router.

Usage:
    python swap.py quote --symbol NVDA --usdg 1000
    python swap.py buy   --symbol NVDA --usdg 1000 [--slippage 0.5] [--dry-run]
    python swap.py sell  --symbol NVDA --shares 4.7 [--slippage 0.5] [--dry-run]
    ... [--separate-approvals] when the signer will not sign a permit digest
"""

import argparse
import json
import sys
import time
import typing as t
from decimal import Decimal

from web3 import Web3

import _bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import evm  # noqa: E402  pylint: disable=wrong-import-position
import permit  # noqa: E402  pylint: disable=wrong-import-position
import pools  # noqa: E402  pylint: disable=wrong-import-position
import stocktokens  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position

CHAIN = stocktokens.CHAIN
USDG = stocktokens.USDG
DEADLINE_S = 600
MAX_SLIPPAGE = 5.0
MAX_GAP_CEILING_BPS = 1000.0
RECEIPT_TIMEOUT_S = 300
RECEIPT_POLL_S = 2.0


class Plan(t.TypedDict):
    """A priced, encoded trade and the calls that would execute it."""

    symbol: str
    pool: uniswap.Pool
    amount_in: int
    quoted_out: int
    reference_out: int
    minimum_out: int
    implied_price: t.Optional[float]
    robinhood_bid: float
    robinhood_ask: float
    price_gap_bps: float
    price_warning: str
    slippage: float
    max_gap_bps: float
    token: str
    pending_multiplier: str
    permit: str
    deadline: int
    calls: list[evm.Call]


def _addresses() -> uniswap.Deployment:
    """Uniswap addresses for the chain this skill trades on."""
    return uniswap.deployment(stocktokens.CHAIN_ID)


def approval_calls(token_in: str, amount: int, expiry: int) -> list[evm.Call]:
    """Exact-amount approvals: ERC-20 to Permit2, then Permit2 to the router."""
    where = _addresses()
    return [
        evm.erc20_approval_call(token_in, where["permit2"], amount, "approve Permit2"),
        permit.approval_call(
            where["permit2"], token_in, where["universal_router"], amount, expiry
        ),
    ]


def reference_units(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    symbol: str,
    multiplier: str,
    amount: int,
    decimals_in: int,
    decimals_out: int,
    buying: bool,
) -> tuple[int, float, float]:
    """Compute what Robinhood's own price says this trade should return.

    Raises:
        SwapError: when the ticker is halted at Robinhood.
    """
    bid, ask, halted = stocktokens.reference_price(symbol, multiplier)
    if halted:
        raise evm.SwapError(f"{symbol} is halted at Robinhood; refusing to trade")
    whole_in = amount / 10**decimals_in
    reference_out = (whole_in / ask) if buying else (whole_in * bid)
    return int(reference_out * 10**decimals_out), bid, ask


def plan_swap(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    w3: Web3,
    symbol: str,
    token_in: str,
    token_out: str,
    amount: int,
    slippage: float,
    account: str,
    refresh: bool = False,
    max_gap_bps: float = stocktokens.MAX_PRICE_GAP_BPS,
    signer: t.Any = None,
    separate_approvals: bool = False,
) -> Plan:
    """Pick a pool, price the trade against Robinhood, and build the calls.

    ``account`` pays and receives, and the two cannot be separated here: the
    router pulls from msg.sender, and the Permit2 allowance authorising that
    pull is signed by — and read from the nonce of — the same address.

    Raises:
        SwapError: for an unknown or untradable ticker; the helpers raise it
            for a halted ticker, a dislocated pool, a refused signature or bad
            calldata.
    """
    if not 0 <= slippage <= MAX_SLIPPAGE:
        raise evm.SwapError(
            f"slippage of {slippage}% is outside 0..{MAX_SLIPPAGE}%; a floor "
            f"that loose is not slippage protection"
        )
    if not 0 < max_gap_bps <= MAX_GAP_CEILING_BPS:
        raise evm.SwapError(
            f"a {max_gap_bps} bps dislocation limit is outside "
            f"0..{MAX_GAP_CEILING_BPS}; widening it that far turns the guard off"
        )
    asset = stocktokens.lookup(symbol)
    where = _addresses()
    candidates = pools.cached_discover(w3, asset["address"], "USDG", refresh)
    pool, quoted_out = uniswap.best_route(
        w3, stocktokens.CHAIN_ID, token_in, token_out, amount, candidates
    )
    decimals_in = evm.token_decimals(w3, token_in)
    decimals_out = evm.token_decimals(w3, token_out)
    buying = token_out == asset["address"]
    reference, bid, ask = reference_units(
        symbol, asset["multiplier"], amount, decimals_in, decimals_out, buying
    )
    gap = stocktokens.check_price_gap(quoted_out, reference, max_gap_bps)
    floor = int(quoted_out * (1 - Decimal(str(slippage)) / 100))

    spender = where["universal_router"]
    fold = signer is not None and not separate_approvals
    now = int(time.time())
    ahead = 1 if fold else 2
    deadline = now + DEADLINE_S + RECEIPT_TIMEOUT_S * ahead
    action = (
        permit.signed_action(
            w3,
            signer,
            account,
            token_in,
            amount,
            stocktokens.CHAIN_ID,
            where["permit2"],
            spender,
            deadline,
        )
        if fold
        else None
    )
    calldata = uniswap.build_execute(
        pool, token_in, token_out, amount, floor, account, deadline, action
    )
    uniswap.verify_execute(calldata, pool, token_in, token_out, amount, floor, account)
    signed = uniswap.permit_action_in(calldata)
    if fold != (signed is not None):
        raise evm.SwapError(
            "a permit was signed but is not in the calldata we would send"
            if fold
            else "the calldata carries a permit nobody asked for"
        )
    if signed is not None:
        permit.verify_action(signed, token_in, spender, amount)
    calls = (
        [evm.erc20_approval_call(token_in, where["permit2"], amount, "approve Permit2")]
        if fold
        else approval_calls(token_in, amount, deadline)
    )
    calls.append({"to": where["universal_router"], "data": calldata, "what": "swap"})
    shares_out = quoted_out / 10**decimals_out
    whole_in = amount / 10**decimals_in
    plan: Plan = {
        "symbol": symbol,
        "pool": pool,
        "amount_in": amount,
        "quoted_out": quoted_out,
        "reference_out": reference,
        "minimum_out": floor,
        "implied_price": (whole_in / shares_out) if buying and shares_out else None,
        "robinhood_bid": bid,
        "robinhood_ask": ask,
        "price_gap_bps": round(gap, 1),
        "slippage": slippage,
        "max_gap_bps": max_gap_bps,
        "token": asset["address"],
        "pending_multiplier": asset["pending_multiplier"],
        "price_warning": (
            f"pool is {gap:.0f} bps worse than Robinhood's price; say so before "
            f"trading size"
            if gap > stocktokens.WARN_PRICE_GAP_BPS
            else ""
        ),
        "permit": "signed into the swap" if fold else "separate transaction",
        "deadline": deadline,
        "calls": calls,
    }
    return plan


def _amount_in_units(w3: Web3, token: str, whole: float) -> int:
    """Whole units to base units, with decimals read from the token.

    Decimal, not float: at eighteen decimals ``int(12345.6789 * 10**18)`` lands
    over a million wei above the number the caller typed.
    """
    return int(Decimal(str(whole)) * 10 ** evm.token_decimals(w3, token))


def _cmd_quote(args: argparse.Namespace) -> int:
    """Price a buy without building or sending anything."""
    w3, _ = evm.connect(CHAIN)
    asset = stocktokens.lookup(args.symbol)
    amount = _amount_in_units(w3, USDG, args.usdg)
    candidates = pools.cached_discover(w3, asset["address"], "USDG", args.refresh)
    pool, out = uniswap.best_route(
        w3, stocktokens.CHAIN_ID, USDG, asset["address"], amount, candidates
    )
    decimals = evm.token_decimals(w3, asset["address"])
    reference, bid, ask = reference_units(
        args.symbol,
        asset["multiplier"],
        amount,
        evm.token_decimals(w3, USDG),
        decimals,
        buying=True,
    )
    shares = out / 10**decimals
    print(
        json.dumps(
            {
                "symbol": args.symbol,
                "usdg_in": args.usdg,
                "shares_out": shares,
                "implied_price": args.usdg / shares if shares else None,
                "robinhood_bid": bid,
                "robinhood_ask": ask,
                "price_gap_bps": round(stocktokens.price_gap_bps(out, reference), 1),
                "pool": pool,
                "candidates": len(candidates),
            },
            indent=2,
        )
    )
    return 0


def send_calls(w3: Web3, signer: t.Any, calls: list[evm.Call]) -> list[str]:
    """Send each call and confirm it before sending the next.

    A reverted approval makes the swap behind it impossible, and a reverted
    swap looks exactly like a successful one in a tx hash alone.

    Raises:
        SwapError: when a call reverts or does not confirm, naming what landed.
    """
    landed: list[str] = []
    for call in calls:
        try:
            tx_hash = signer.send_transaction(dict(call))
        except Exception as exc:  # pylint: disable=broad-except
            raise evm.SwapError(
                f"{call['what']} could not be sent ({exc}); confirmed so far: "
                f"{landed}. It may still have broadcast - check before resending."
            ) from exc
        try:
            receipt = w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=RECEIPT_TIMEOUT_S, poll_latency=RECEIPT_POLL_S
            )
        except Exception as exc:  # pylint: disable=broad-except
            raise evm.SwapError(
                f"{call['what']} ({tx_hash}) has not confirmed within "
                f"{RECEIPT_TIMEOUT_S}s ({exc}); its fate is unknown and it may "
                f"still land, so check that hash before resending anything. "
                f"Confirmed so far: {landed}"
            ) from exc
        if receipt["status"] != 1:
            raise evm.SwapError(
                f"{call['what']} ({tx_hash}) reverted; confirmed so far: {landed}"
            )
        print(f"{call['what']}: {tx_hash}")
        landed.append(f"{call['what']}: {tx_hash}")
    return landed


def _run_plan(
    args: argparse.Namespace, token_in: str, token_out: str, amount: int
) -> int:
    """Build a swap and, unless it is a dry run, send and confirm its calls.

    A dry run builds the same calls a real run would send, permit included —
    only the sending is skipped, so what is printed is what would broadcast.
    """
    w3, signer = evm.connect(CHAIN)
    safe = signer.chain_info(CHAIN)["safe"]
    plan = plan_swap(
        w3,
        args.symbol,
        token_in,
        token_out,
        amount,
        args.slippage,
        safe,
        args.refresh,
        args.max_gap_bps,
        signer,
        args.separate_approvals,
    )
    print(json.dumps({k: v for k, v in plan.items() if k != "calls"}, indent=2))
    if args.dry_run:
        for call in plan["calls"]:
            print(
                f"dry-run {call['what']}: to={call['to']} data={call['data'][:74]}..."
            )
        return 0
    for line in send_calls(w3, signer, plan["calls"]):
        print(line)
    return 0


def _cmd_buy(args: argparse.Namespace) -> int:
    """Spend USDG on a stock token."""
    w3, _ = evm.connect(CHAIN)
    amount = _amount_in_units(w3, USDG, args.usdg)
    token = stocktokens.lookup(args.symbol)["address"]
    return _run_plan(args, USDG, token, amount)


def _cmd_sell(args: argparse.Namespace) -> int:
    """Sell a stock token back into USDG."""
    w3, _ = evm.connect(CHAIN)
    token = stocktokens.lookup(args.symbol)["address"]
    amount = _amount_in_units(w3, token, args.shares)
    return _run_plan(args, token, USDG, amount)


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="stock-token swaps")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--symbol", required=True)
    common.add_argument("--refresh", action="store_true")
    trade = argparse.ArgumentParser(add_help=False)
    trade.add_argument("--slippage", type=float, default=0.5)
    trade.add_argument("--dry-run", action="store_true")
    trade.add_argument(
        "--max-gap-bps", type=float, default=stocktokens.MAX_PRICE_GAP_BPS
    )
    trade.add_argument("--separate-approvals", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    quote = sub.add_parser("quote", parents=[common])
    quote.add_argument("--usdg", type=float, required=True)
    quote.set_defaults(func=_cmd_quote)
    buy = sub.add_parser("buy", parents=[common, trade])
    buy.add_argument("--usdg", type=float, required=True)
    buy.set_defaults(func=_cmd_buy)
    sell = sub.add_parser("sell", parents=[common, trade])
    sell.add_argument("--shares", type=float, required=True)
    sell.set_defaults(func=_cmd_sell)
    args = parser.parse_args()
    try:
        result: int = args.func(args)
    except evm.SwapError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
