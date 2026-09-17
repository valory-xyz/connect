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

"""Find and inspect Pons launches, and record the operator's V2 answer.

Usage:
    python tokens.py search [--query Q] [--sort marketCap] [--page 1]
                            [--quote ETH|USDG] [--limit 10]
    python tokens.py show --token 0x...
    python tokens.py audit
    python tokens.py acknowledge-v2 --answer "<the operator's words>"
"""

import argparse
import sys
import typing as t

from web3 import Web3

import _pons_bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import cli  # noqa: E402  pylint: disable=wrong-import-position
import curve  # noqa: E402  pylint: disable=wrong-import-position
import discovery  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import pons  # noqa: E402  pylint: disable=wrong-import-position
import web  # noqa: E402  pylint: disable=wrong-import-position

SEL_THRESHOLD = evm.selector("graduationThreshold()")
SEL_REAL_QUOTE = evm.selector("realQuoteReserve()")
QUOTES = ("ETH", "USDG")


def _cmd_search(args: argparse.Namespace) -> int:
    """Search launches and print the on-chain-verified results."""
    w3, _ = evm.read_web3(pons.CHAIN, pons.PUBLIC_RPC)
    results, source = discovery.search(
        w3, args.query, args.sort, args.page, args.quote, args.limit
    )
    cli.print_json(
        {
            "source": source,
            "query": args.query,
            "page": args.page,
            "results": results,
        }
    )
    return 0


def _curve_state(w3: Web3, launch: pons.Launch, buyer: str) -> dict[str, t.Any]:
    """Live curve reserves, graduation progress and the buyer's snipe tax."""
    address = pons.curve_of(launch)
    state = curve.CurveState.read(w3, address, buyer)
    threshold = evm.call_int(w3, address, SEL_THRESHOLD)
    raised = evm.call_int(w3, address, SEL_REAL_QUOTE)
    scale = 10 ** launch["pair_decimals"]
    return {
        "quote_reserve_incl_phantom": state.quote_reserve / scale,
        "raised": raised / scale,
        "graduation_threshold": threshold / scale,
        "graduation_progress_pct": (
            min(100.0, raised * 100 / threshold) if threshold else None
        ),
        "token_reserve": state.token_reserve / 10 ** launch["decimals"],
        "sellable_tokens": state.sellable / 10 ** launch["decimals"],
        "fee_bps": state.fee_bps,
        "creator_tax_bps": state.creator_tax_bps,
        "snipe_tax_bps_now": state.snipe_tax_bps,
        "snipe_tax_payer": pons.snipe_tax_payer(buyer),
        "ready_to_graduate": state.ready_to_graduate,
    }


def _cmd_show(args: argparse.Namespace) -> int:
    """Print one launch as the chain reports it, plus the API's market readout."""
    w3, safe = evm.read_web3(pons.CHAIN, pons.PUBLIC_RPC)
    launch = pons.launch_record(w3, args.token)
    doc: dict[str, t.Any] = dict(launch)
    if launch["venue"] == "none":
        doc["not_tradable"] = pons.PHASE_REASONS[launch["phase"]]
    if launch["venue"] == "curve":
        doc["curve_state"] = _curve_state(w3, launch, safe or evm.NATIVE)
    if launch["generation"] == "v2":
        doc["audit"] = pons.audit_status()
        doc["v2_acknowledged"] = pons.v2_acknowledged()
    try:
        items = pons.api_search(launch["token"], "relevance")["items"]
    except web.Unavailable as exc:
        print(
            f"NOTICE: no market data; the Pons API is unavailable ({exc})",
            file=sys.stderr,
        )
        items = []
    for item in items:
        if item["token"].lower() == launch["token"].lower():
            doc["market"] = pons.market_readout(item)
            break
    cli.print_json(doc)
    return 0


def _cmd_audit(_: argparse.Namespace) -> int:
    """Print V2's live audit status and whether the operator has answered."""
    cli.print_json({**pons.audit_status(), "v2_acknowledged": pons.v2_acknowledged()})
    return 0


def _cmd_acknowledge(args: argparse.Namespace) -> int:
    """Record the operator's acceptance of V2's audit risk."""
    pons.record_v2_ack(args.answer)
    cli.print_json({"recorded": True, "file": str(pons.ACK_FILE)})
    return 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Pons launch discovery")
    sub = parser.add_subparsers(dest="command", required=True)
    find = sub.add_parser("search")
    find.add_argument("--query", default="")
    find.add_argument("--sort", choices=pons.SORTS, default="marketCap")
    find.add_argument("--page", type=int, default=1)
    find.add_argument("--quote", choices=QUOTES)
    find.add_argument("--limit", type=int, default=10)
    find.set_defaults(func=_cmd_search)
    show = sub.add_parser("show")
    show.add_argument("--token", required=True)
    show.set_defaults(func=_cmd_show)
    sub.add_parser("audit").set_defaults(func=_cmd_audit)
    ack = sub.add_parser("acknowledge-v2")
    ack.add_argument("--answer", required=True)
    ack.set_defaults(func=_cmd_acknowledge)
    args = parser.parse_args()
    if getattr(args, "page", 1) < 1 or not 0 < getattr(args, "limit", 1) <= 24:
        parser.error("--page must be >= 1 and --limit between 1 and 24")
    try:
        result: int = args.func(args)
    except evm.SwapError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
