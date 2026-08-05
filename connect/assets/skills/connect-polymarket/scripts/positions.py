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

"""Portfolio reads from the public data API, checked against the chain.

Positions live wherever the funds flow put them: in the SAFE after a sweep
(the normal, recoverable place) or briefly in the DW mid-trade. Default is
the safe; use --wallet to look elsewhere.

The data API is an indexer and lags the chain (see INDEXER_LAG_NOTE), so
every read names its source and any token this skill has reason to think is
held is confirmed straight from the CTF contract rather than taken on the
indexer's word.

Usage:
    python positions.py positions [--wallet safe|dw|eoa|0x...] [--redeemable]
                                  [--token-ids 123,456] [--no-onchain]
    python positions.py trades    [--wallet safe|dw|eoa|0x...] [--limit 50]
"""

import argparse
import math

import pm_common as pm
from deposit_wallet import _resolve_dw, dw_or_exit

POSITIONS_PAGE_LIMIT = 500
POSITIONS_MAX_OFFSET = 10_000

# The indexer truncates `size` to 4 decimals while the chain carries 6
# (411.4355 vs 411.435578, seen live), so an exact comparison called every
# healthy position a disagreement. Below this is presentation, not substance.
SIZE_EPSILON = 1.5e-4

INDEXER_LAG_NOTE = (
    "the data API is an indexer and lags the chain; an empty or short list "
    "does not prove there is no position. Confirm on-chain with "
    "`positions.py positions --token-ids <id>` before concluding that a buy "
    "did not fill."
)


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


def _parse_token_ids(raw: str | None) -> list:
    """Parse `--token-ids 123,456` into ints, rejecting junk loudly."""
    if not raw:
        return []
    try:
        return [int(part) for part in raw.replace(",", " ").split()]
    except ValueError as e:
        raise SystemExit(f"--token-ids must be comma/space separated ids: {e}") from e


def _candidate_token_ids(cs: pm.ConnectSigner, explicit: list) -> list:
    """Token ids worth confirming on-chain.

    The recorded holdings hints and unresolved buy submissions are written at
    order time, so they are populated the instant a buy is sent — exactly the
    window in which the indexer still has nothing to say.
    """
    if explicit:
        return list(dict.fromkeys(explicit))
    return sorted({*pm.dw_open_tokens(cs), *pm.dw_pending_buy_tokens(cs)})


def _check_addresses(cs: pm.ConnectSigner, wallet_address: str) -> list:
    """Which wallets the on-chain confirmation reads: the one asked about + the DW.

    An unswept buy sits in the DepositWallet, a swept one in the safe, and the
    caller rarely knows which. Since `--wallet` defaults to the safe, reading
    only that would return zero for the fresh fill this check exists to
    confirm — while `INDEXER_LAG_NOTE` and SKILL.md both send the caller here
    with a bare `--token-ids`.
    """
    dw = _resolve_dw(cs)
    return [
        {
            "address": address,
            "location": (
                "deposit_wallet" if dw and address == dw else "requested_wallet"
            ),
        }
        for address in dict.fromkeys([wallet_address, *([dw] if dw else [])])
    ]


def _onchain_holdings(cs: pm.ConnectSigner, addresses: list, token_ids: list) -> list:
    """Read CTF balances straight from the chain, per wallet and token id.

    Each hit names the wallet holding it, because "you hold 12.5 shares" and
    "they are still in the DepositWallet, unswept" are different facts and the
    second one decides what to do next.
    """
    held = []
    for wallet in addresses:
        for token_id in token_ids:
            units = pm.erc1155_balance_of(cs.w3, pm.CTF, wallet["address"], token_id)
            if units > 0:
                held.append(
                    {
                        "token_id": str(token_id),
                        "address": wallet["address"],
                        "location": wallet["location"],
                        # CTF outcome tokens carry the collateral's decimals
                        "size": units / 10**pm.PUSD_DECIMALS,
                        "size_base_units": units,
                    }
                )
    return held


def _indexer_disagrees(indexed: list, held: list) -> set:
    """Token ids where the chain and the indexer tell different stories.

    Presence alone is not enough: buying more of a position you already hold
    leaves the token id listed at its OLD size, so a membership-only check
    stays silent on exactly the case this exists for.

    Balances are summed across wallets first — a half-swept position is one
    holding in two places, and comparing each leg alone would cry wolf.
    """
    indexed_sizes = {
        str(p["token_id"]): p.get("size") for p in indexed if p.get("token_id")
    }
    on_chain: dict = {}
    for hit in held:
        on_chain[hit["token_id"]] = on_chain.get(hit["token_id"], 0.0) + hit["size"]
    disagreeing = set()
    for token_id, chain_size in on_chain.items():
        reported = pm.price_or_none(indexed_sizes.get(token_id))
        # `isfinite` is load-bearing: NaN survives both float() and
        # json.loads(), and every comparison against it is False — so it would
        # read as "the two agree", the one value that most clearly means not.
        if (
            reported is None
            or not math.isfinite(reported)
            or not math.isclose(
                reported, chain_size, rel_tol=1e-6, abs_tol=SIZE_EPSILON
            )
        ):
            disagreeing.add(token_id)
    return disagreeing


def cmd_positions(  # pylint: disable=too-many-arguments
    cs: pm.ConnectSigner,
    wallet: str,
    redeemable: bool,
    token_ids: list | None = None,
    onchain: bool = True,
) -> None:
    """Open (or redeemable) positions held by a wallet, across all pages.

    `onchain_check` is present whenever the on-chain confirmation ran, even if
    it had nothing to check. Its absence therefore means one thing only —
    `--no-onchain` — so a caller can always tell a verified answer from an
    unverified one.
    """
    address = _wallet_address(cs, wallet)
    params: dict = {"user": address, "sizeThreshold": 0}
    if redeemable:
        params["redeemable"] = "true"
    positions = pm.fetch_all_positions(
        params,
        label="position",
        page_limit=POSITIONS_PAGE_LIMIT,
        max_offset=POSITIONS_MAX_OFFSET,
    )
    indexed = [_slim(p) for p in positions]
    result: dict = {
        "wallet": wallet,
        "address": address,
        "source": "data-api (indexer)",
        "positions": indexed,
    }
    held: list = []
    if onchain:
        # Every candidate is read, including ones the indexer already listed
        # (see _indexer_disagrees); filtering those would silently no-op an
        # explicit --token-ids, the one command INDEXER_LAG_NOTE recommends.
        try:
            candidates = _candidate_token_ids(cs, list(token_ids or []))
            checked_at = _check_addresses(cs, address)
            held = _onchain_holdings(cs, checked_at, candidates)
            result["onchain_check"] = {
                "addresses": checked_at,
                "checked_token_ids": [str(token_id) for token_id in candidates],
                "held": held,
            }
        # Advisory: an RPC blip must not discard the portfolio already
        # fetched. SystemExit is listed deliberately — `_resolve_dw` raises it
        # to abort a DW *deployment*, far too blunt for a read-only query.
        # Reported, never swallowed.
        except (Exception, SystemExit) as e:  # noqa: BLE001
            result["onchain_check"] = {
                "error": (
                    f"could not confirm on-chain ({type(e).__name__}: {e}); the "
                    "positions above are the indexer's word alone, and it lags"
                )
            }
    disagreeing = _indexer_disagrees(indexed, held)
    if disagreeing:
        result["warning"] = (
            f"{len(disagreeing)} position(s) are missing from the indexer's "
            "answer or listed there at a different size — the chain is right "
            "and the API has not caught up; treat onchain_check.held as the "
            "authoritative reading"
        )
    if not indexed and not held:
        result["note"] = INDEXER_LAG_NOTE
    pm.print_json(result)


def cmd_trades(cs: pm.ConnectSigner, wallet: str, limit: int) -> None:
    """Trade history for a wallet (indexed, so it lags the chain too)."""
    trades = pm.http_get_json(
        f"{pm.DATA_API}/trades",
        params={"user": _wallet_address(cs, wallet), "limit": limit},
    )
    result: dict = {
        "wallet": wallet,
        "source": "data-api (indexer)",
        "trades": trades,
    }
    if not trades:
        result["note"] = INDEXER_LAG_NOTE
    pm.print_json(result)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    positions = sub.add_parser("positions")
    positions.add_argument("--wallet", default="safe")
    positions.add_argument("--redeemable", action="store_true")
    positions.add_argument(
        "--token-ids",
        default=None,
        help="confirm these token ids on-chain instead of the recorded hints",
    )
    positions.add_argument(
        "--no-onchain",
        action="store_true",
        help="trust the indexer alone (skips the CTF balance check)",
    )
    trades = sub.add_parser("trades")
    trades.add_argument("--wallet", default="safe")
    trades.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    if args.command == "positions":
        cmd_positions(
            cs,
            args.wallet,
            args.redeemable,
            _parse_token_ids(args.token_ids),
            not args.no_onchain,
        )
    elif args.command == "trades":
        cmd_trades(cs, args.wallet, args.limit)


if __name__ == "__main__":
    main()
