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

"""Portfolio reads from the public data API — no auth, works in any mode.

Positions live wherever the funds flow put them: in the SAFE after a sweep
(the normal, recoverable place) or briefly in the DW mid-trade. Default is
the safe; use --wallet to look elsewhere.

Usage:
    python positions.py positions [--wallet safe|dw|eoa|0x...] [--redeemable]
    python positions.py trades    [--wallet safe|dw|eoa|0x...] [--limit 50]
"""

import argparse

import pm_common as pm
from deposit_wallet import dw_or_exit

POSITIONS_PAGE_LIMIT = 500
POSITIONS_MAX_OFFSET = 10_000


def _wallet_address(cs: pm.ConnectSigner, wallet: str) -> str:
    if wallet == "safe":
        return cs.safe_address
    if wallet == "dw":
        return dw_or_exit(cs)
    if wallet == "eoa":
        return cs.agent_eoa
    return wallet  # a literal address


def _slim(position: dict) -> dict:
    return {
        "title": position.get("title"),
        "outcome": position.get("outcome"),
        "condition_id": position.get("conditionId"),
        "token_id": position.get("asset"),
        "size": position.get("size"),
        "avg_price": position.get("avgPrice"),
        "cur_price": position.get("curPrice"),
        "value": position.get("currentValue"),
        "cash_pnl": position.get("cashPnl"),
        "redeemable": position.get("redeemable"),
        "neg_risk": position.get("negativeRisk"),
        "outcome_index": position.get("outcomeIndex"),
    }


def cmd_positions(cs: pm.ConnectSigner, wallet: str, redeemable: bool) -> None:
    """Open (or redeemable) positions held by a wallet, across all pages."""
    params: dict = {"user": _wallet_address(cs, wallet), "sizeThreshold": 0}
    if redeemable:
        params["redeemable"] = "true"
    positions = pm.fetch_all_positions(
        params,
        label="position",
        page_limit=POSITIONS_PAGE_LIMIT,
        max_offset=POSITIONS_MAX_OFFSET,
    )
    pm.print_json([_slim(p) for p in positions])


def cmd_trades(cs: pm.ConnectSigner, wallet: str, limit: int) -> None:
    """Trade history for a wallet."""
    trades = pm.http_get_json(
        f"{pm.DATA_API}/trades",
        params={"user": _wallet_address(cs, wallet), "limit": limit},
    )
    pm.print_json(trades)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    positions = sub.add_parser("positions")
    positions.add_argument("--wallet", default="safe")
    positions.add_argument("--redeemable", action="store_true")
    trades = sub.add_parser("trades")
    trades.add_argument("--wallet", default="safe")
    trades.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    if args.command == "positions":
        cmd_positions(cs, args.wallet, args.redeemable)
    elif args.command == "trades":
        cmd_trades(cs, args.wallet, args.limit)


if __name__ == "__main__":
    main()
