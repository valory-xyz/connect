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

"""Quote and trade Pons tokens on their curve or their Uniswap pool.

Usage:
    python trade.py quote --token 0x.. (--spend 0.01 | --tokens 1000000)
    python trade.py buy   --token 0x.. --spend 0.01 [--slippage 0.5] [--dry-run]
    python trade.py sell  --token 0x.. --tokens 1000000 [--slippage 0.5] [--dry-run]
    ... [--max-impact-bps 500] [--separate-approvals]
"""

import argparse
import sys
import typing as t

from web3 import Web3

import _pons_bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import cli  # noqa: E402  pylint: disable=wrong-import-position
import curve  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import pons  # noqa: E402  pylint: disable=wrong-import-position
import router  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position


class Quote(t.NamedTuple):
    """What one venue says a trade fills at."""

    amount_out: int
    spent: int
    impact_bps: float
    snipe_tax_bps: int


class Plan(t.TypedDict):
    """A priced trade and, unless it is only a quote, the calls that execute it."""

    token: str
    symbol: str
    generation: pons.Generation
    venue: pons.Venue
    side: t.Literal["buy", "sell"]
    pay: str
    receive: str
    amount_in: float
    spent: float
    expected_out: float
    minimum_out: float
    price_impact_bps: float
    max_impact_bps: float
    slippage: float
    fee_bps: int
    creator_tax_bps: int
    snipe_tax_bps: int
    snipe_tax_payer: str
    pool: t.Optional[uniswap.Pool]
    permit: str
    audit: t.Optional[dict[str, str]]
    calls: list[evm.Call]


def _check_venue(launch: pons.Launch) -> None:
    """Refuse a launch that has nowhere to trade.

    Raises:
        SwapError: naming why the launch has no venue.
    """
    if launch["venue"] == "none":
        reason = pons.PHASE_REASONS.get(launch["phase"], f"phase {launch['phase']}")
        raise evm.SwapError(f"{launch['symbol']} cannot be traded now: {reason}")


def _pool_side(launch: pons.Launch, buying: bool) -> tuple[str, str]:
    """Return the pool's token in and out; a v3 pool trades WETH, not ETH."""
    pair = pons.WETH if launch["venue"] == "v3" else launch["pair_token"]
    return (pair, launch["token"]) if buying else (launch["token"], pair)


def _spend_asset(launch: pons.Launch, buying: bool) -> str:
    """Return what leaves the safe: ETH for a v3 buy, which wraps it first."""
    if not buying:
        return launch["token"]
    return evm.NATIVE if launch["venue"] == "v3" else launch["pair_token"]


def quote_venue(
    w3: Web3, launch: pons.Launch, buying: bool, amount: int, recipient: str
) -> Quote:
    """Price a trade on whichever venue the launch trades on now.

    Raises:
        SwapError: when the venue is closed or cannot fill the size.
    """
    _check_venue(launch)
    if launch["venue"] == "curve":
        state = curve.CurveState.read(w3, pons.curve_of(launch), recipient)
        if buying:
            out, spent = curve.buy_fill(state, amount)
        else:
            out, spent = curve.quote_sell(state, amount), amount
        impact = curve.price_impact_bps(state, amount, buying)
        return Quote(out, spent, impact, state.snipe_tax_bps)
    pool = pons.pool_of(launch)
    token_in, token_out = _pool_side(launch, buying)
    _, out = uniswap.best_route(w3, pons.CHAIN_ID, token_in, token_out, amount, [pool])
    impact = uniswap.price_impact_bps(
        w3, pons.CHAIN_ID, pool, token_in, token_out, amount, out
    )
    return Quote(out, amount, impact, 0)


def _venue_calls(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    w3: Web3,
    signer: t.Any,
    safe: str,
    launch: pons.Launch,
    buying: bool,
    amount: int,
    minimum: int,
    separate_approvals: bool,
    dry_run: bool,
) -> tuple[list[evm.Call], str]:
    """Build the checked calls that execute a priced trade, and how it is permitted."""
    if launch["venue"] == "curve":
        build = curve.buy_calls if buying else curve.sell_calls
        asset = launch["pair_token"] if buying else launch["token"]
        calls = build(pons.curve_of(launch), asset, amount, minimum, safe)
        return calls, "exact approval to the curve"
    token_in, token_out = _pool_side(launch, buying)
    wrap = buying and launch["venue"] == "v3"
    swap = router.router_swap(
        w3,
        signer,
        safe,
        pons.CHAIN_ID,
        pons.pool_of(launch),
        token_in,
        token_out,
        amount,
        minimum,
        separate_approvals,
        calls_ahead=1 if wrap else 0,
        dry_run=dry_run,
    )
    head = [evm.weth_deposit_call(pons.WETH, amount)] if wrap else []
    return head + swap.calls, swap.permit


def plan_trade(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    w3: Web3,
    launch: pons.Launch,
    buying: bool,
    amount: int,
    slippage: float,
    max_impact_bps: float,
    recipient: str,
    signer: t.Any = None,
    separate_approvals: bool = False,
    dry_run: bool = False,
) -> Plan:
    """Price a trade and, given a signer, apply every guard and build its calls.

    Raises:
        SwapError: when a limit, the venue, the balance or a guard refuses.
    """
    evm.check_slippage(slippage)
    evm.check_impact_limit(max_impact_bps)
    quote = quote_venue(w3, launch, buying, amount, recipient)
    minimum = evm.apply_slippage(quote.amount_out, slippage)
    decimals_in, decimals_out = (
        (launch["pair_decimals"], launch["decimals"])
        if buying
        else (launch["decimals"], launch["pair_decimals"])
    )
    pair_name = "ETH" if launch["venue"] == "v3" else launch["pair_symbol"]
    plan: Plan = {
        "token": launch["token"],
        "symbol": launch["symbol"],
        "generation": launch["generation"],
        "venue": launch["venue"],
        "side": "buy" if buying else "sell",
        "pay": pair_name if buying else launch["symbol"],
        "receive": launch["symbol"] if buying else pair_name,
        "amount_in": amount / 10**decimals_in,
        "spent": quote.spent / 10**decimals_in,
        "expected_out": quote.amount_out / 10**decimals_out,
        "minimum_out": minimum / 10**decimals_out,
        "price_impact_bps": round(quote.impact_bps, 1),
        "max_impact_bps": max_impact_bps,
        "slippage": slippage,
        "fee_bps": launch["fee_bps"],
        "creator_tax_bps": launch["creator_tax_bps"],
        "snipe_tax_bps": quote.snipe_tax_bps,
        "snipe_tax_payer": pons.snipe_tax_payer(recipient),
        "pool": launch["pool"],
        "permit": "",
        "audit": None,
        "calls": [],
    }
    if signer is None:
        return plan
    if launch["generation"] == "v2":
        plan["audit"] = pons.require_v2_ack()
    if buying and quote.snipe_tax_bps > 0:
        raise evm.SwapError(
            f"{launch['symbol']} still charges a {quote.snipe_tax_bps} bps snipe "
            f"tax on buys; it decays within seconds of launch, so wait and retry"
        )
    if quote.impact_bps > max_impact_bps:
        raise evm.SwapError(
            f"this trade moves the price {quote.impact_bps:.0f} bps, over the "
            f"{max_impact_bps:.0f} bps limit; trade a smaller size"
        )
    if minimum <= 0:
        raise evm.SwapError("the size is too small to set a minimum output")
    asset = _spend_asset(launch, buying)
    have = evm.raw_balance_of(w3, asset, recipient)
    if have < amount:
        raise evm.SwapError(
            f"the safe holds {have / 10**decimals_in} {plan['pay']}, less than the "
            f"{amount / 10**decimals_in} this trade spends"
        )
    plan["calls"], plan["permit"] = _venue_calls(
        w3,
        signer,
        recipient,
        launch,
        buying,
        amount,
        minimum,
        separate_approvals,
        dry_run,
    )
    return plan


def _send_wrapped_buy(w3: Web3, signer: t.Any, calls: list[evm.Call]) -> list[evm.Sent]:
    """Send a v3 buy, unwrapping exactly its wrap if a later call surely did nothing.

    Raises:
        SwapError: when a call fails, naming any WETH the wrap left in the safe.
    """
    try:
        return evm.send_calls(w3, signer, calls)
    except evm.SendError as exc:
        if not exc.landed:
            raise
        failed = str(exc).rstrip(".")
        wrapped = calls[0]["value"]
        weth = f"{wrapped / 10**18} WETH it wrapped"
        if not exc.inert:
            raise evm.SwapError(
                f"{failed}. If the buy did not land, the {weth} is still in the "
                f"safe and still needs unwrapping"
            ) from exc
        try:
            evm.send_calls(w3, signer, [evm.weth_withdraw_call(pons.WETH, wrapped)])
        except evm.SwapError as unwrap_exc:
            raise evm.SwapError(
                f"{failed}. Unwrapping the {weth} failed too ({unwrap_exc}); that "
                f"WETH is in the safe and still needs unwrapping"
            ) from exc
        raise evm.SwapError(f"{failed}. The {weth} was unwrapped") from exc


def execute(w3: Web3, signer: t.Any, safe: str, plan: Plan) -> list[evm.Sent]:
    """Send a plan's calls; a v3 sell then unwraps exactly the WETH it received.

    Raises:
        SwapError: when a call fails, or a v3 sell returns no WETH to unwrap.
    """
    if plan["venue"] == "v3" and plan["side"] == "buy":
        return _send_wrapped_buy(w3, signer, plan["calls"])
    unwrap = plan["venue"] == "v3" and plan["side"] == "sell"
    before = evm.raw_balance_of(w3, pons.WETH, safe) if unwrap else 0
    landed = evm.send_calls(w3, signer, plan["calls"])
    if not unwrap:
        return landed
    try:
        received = evm.raw_balance_of(w3, pons.WETH, safe) - before
    except Exception as exc:  # pylint: disable=broad-except
        raise evm.SwapError(
            f"the swap landed ({evm.summary(landed)}) but the safe's WETH could "
            f"not be read ({exc}); the WETH it received still needs unwrapping"
        ) from exc
    if received <= 0:
        raise evm.SwapError(
            f"the swap confirmed but the safe's WETH did not grow; nothing to "
            f"unwrap. Confirmed so far: {evm.summary(landed)}"
        )
    return landed + evm.send_calls(
        w3, signer, [evm.weth_withdraw_call(pons.WETH, received)]
    )


def _amount(w3: Web3, launch: pons.Launch, args: argparse.Namespace) -> int:
    """Convert the size the caller typed to base units of what they pay.

    Raises:
        SwapError: when the size is not positive in whole or base units.
    """
    spending = args.spend is not None
    whole = args.spend if spending else args.tokens
    flag = "--spend" if spending else "--tokens"
    if not whole > 0:
        raise evm.SwapError(f"{flag} must be positive, got {whole}")
    amount = evm.to_base_units(
        w3, launch["pair_token"] if spending else launch["token"], whole
    )
    if not amount:
        raise evm.SwapError(f"{flag} {whole} is less than one base unit")
    return amount


def _cmd_quote(args: argparse.Namespace) -> int:
    """Price a trade without building or sending anything."""
    w3, safe = evm.read_web3(pons.CHAIN, pons.PUBLIC_RPC)
    launch = pons.launch_record(w3, args.token)
    plan = plan_trade(
        w3,
        launch,
        args.spend is not None,
        _amount(w3, launch, args),
        args.slippage,
        args.max_impact_bps,
        safe or evm.NATIVE,
    )
    plan["permit"] = "not built for a quote"
    cli.print_plan(plan)
    return 0


def _cmd_trade(args: argparse.Namespace) -> int:
    """Build a trade and, unless it is a dry run, send and confirm its calls."""
    w3, signer = evm.connect(pons.CHAIN)
    safe = signer.chain_info(pons.CHAIN)["safe"]
    launch = pons.launch_record(w3, args.token)
    plan = plan_trade(
        w3,
        launch,
        args.command == "buy",
        _amount(w3, launch, args),
        args.slippage,
        args.max_impact_bps,
        safe,
        signer,
        args.separate_approvals,
        args.dry_run,
    )
    cli.print_plan(plan)
    if args.dry_run:
        evm.print_dry_run(plan["calls"])
        if plan["venue"] == "v3" and plan["side"] == "sell":
            print("dry-run unwrap WETH: the WETH the swap returns, once it confirms")
        return 0
    execute(w3, signer, safe, plan)
    return 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Pons token trades")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--token", required=True)
    common.add_argument("--slippage", type=float, default=0.5)
    common.add_argument(
        "--max-impact-bps", type=float, default=evm.DEFAULT_MAX_IMPACT_BPS
    )
    trade = argparse.ArgumentParser(add_help=False)
    trade.add_argument("--dry-run", action="store_true")
    trade.add_argument("--separate-approvals", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    quote = sub.add_parser("quote", parents=[common])
    size = quote.add_mutually_exclusive_group(required=True)
    size.add_argument("--spend", type=float)
    size.add_argument("--tokens", type=float)
    quote.set_defaults(func=_cmd_quote)
    buy = sub.add_parser("buy", parents=[common, trade])
    buy.add_argument("--spend", type=float, required=True)
    buy.set_defaults(func=_cmd_trade, tokens=None)
    sell = sub.add_parser("sell", parents=[common, trade])
    sell.add_argument("--tokens", type=float, required=True)
    sell.set_defaults(func=_cmd_trade, spend=None)
    args = parser.parse_args()
    try:
        result: int = args.func(args)
    except evm.SwapError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
