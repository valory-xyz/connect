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
import typing as t

from web3 import Web3

import _bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import cli  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import pools  # noqa: E402  pylint: disable=wrong-import-position
import router  # noqa: E402  pylint: disable=wrong-import-position
import stocktokens  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position

CHAIN = stocktokens.CHAIN
USDG = stocktokens.USDG
MAX_GAP_CEILING_BPS = 1000.0


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
    multiplier: str
    pending_multiplier: str
    permit: str
    deadline: int
    calls: list[evm.Call]


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
    dry_run: bool = False,
) -> Plan:
    """Pick a pool, price the trade against Robinhood, and build the calls.

    Raises:
        SwapError: for an unknown or untradable ticker; the helpers raise it
            for a halted ticker, a dislocated pool, a refused signature or bad
            calldata.
    """
    evm.check_slippage(slippage)
    if not 0 < max_gap_bps <= MAX_GAP_CEILING_BPS:
        raise evm.SwapError(
            f"a {max_gap_bps} bps dislocation limit is outside "
            f"0..{MAX_GAP_CEILING_BPS}; widening it that far turns the guard off"
        )
    asset = stocktokens.lookup(symbol)
    candidates = pools.cached_discover(w3, asset["address"], "USDG", refresh)
    pool, quoted_out = uniswap.best_route(
        w3, stocktokens.CHAIN_ID, token_in, token_out, amount, candidates
    )
    decimals_in = evm.token_decimals(w3, token_in)
    decimals_out = evm.token_decimals(w3, token_out)
    buying = token_out == asset["address"]
    multiplier = stocktokens.token_multiplier(w3, asset["address"])
    reference, bid, ask = reference_units(
        symbol, multiplier, amount, decimals_in, decimals_out, buying
    )
    gap = stocktokens.check_price_gap(quoted_out, reference, max_gap_bps)
    floor = evm.apply_slippage(quoted_out, slippage)

    routed = router.router_swap(
        w3,
        signer,
        account,
        stocktokens.CHAIN_ID,
        pool,
        token_in,
        token_out,
        amount,
        floor,
        separate_approvals,
        dry_run=dry_run,
    )
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
        "multiplier": multiplier,
        "pending_multiplier": asset["pending_multiplier"],
        "price_warning": (
            f"pool is {gap:.0f} bps worse than Robinhood's price; say so before "
            f"trading size"
            if gap > stocktokens.WARN_PRICE_GAP_BPS
            else ""
        ),
        "permit": routed.permit,
        "deadline": routed.deadline,
        "calls": routed.calls,
    }
    return plan


def _cmd_quote(args: argparse.Namespace) -> int:
    """Price a buy without building or sending anything."""
    w3, _ = evm.connect(CHAIN)
    asset = stocktokens.lookup(args.symbol)
    amount = evm.to_base_units(w3, USDG, args.usdg)
    candidates = pools.cached_discover(w3, asset["address"], "USDG", args.refresh)
    pool, out = uniswap.best_route(
        w3, stocktokens.CHAIN_ID, USDG, asset["address"], amount, candidates
    )
    decimals = evm.token_decimals(w3, asset["address"])
    multiplier = stocktokens.token_multiplier(w3, asset["address"])
    reference, bid, ask = reference_units(
        args.symbol,
        multiplier,
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
                "multiplier": multiplier,
                "price_gap_bps": round(stocktokens.price_gap_bps(out, reference), 1),
                "pool": pool,
                "candidates": len(candidates),
            },
            indent=2,
        )
    )
    return 0


def _run_plan(
    args: argparse.Namespace, token_in: str, token_out: str, amount: int
) -> int:
    """Build a swap and, unless it is a dry run, send and confirm its calls."""
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
        args.dry_run,
    )
    cli.print_plan(plan)
    if args.dry_run:
        evm.print_dry_run(plan["calls"])
        return 0
    evm.send_calls(w3, signer, plan["calls"])
    return 0


def _cmd_buy(args: argparse.Namespace) -> int:
    """Spend USDG on a stock token."""
    w3, _ = evm.connect(CHAIN)
    amount = evm.to_base_units(w3, USDG, args.usdg)
    token = stocktokens.lookup(args.symbol)["address"]
    return _run_plan(args, USDG, token, amount)


def _cmd_sell(args: argparse.Namespace) -> int:
    """Sell a stock token back into USDG."""
    w3, _ = evm.connect(CHAIN)
    token = stocktokens.lookup(args.symbol)["address"]
    amount = evm.to_base_units(w3, token, args.shares)
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
