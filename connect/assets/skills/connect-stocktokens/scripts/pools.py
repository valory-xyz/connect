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

"""Pool discovery for Robinhood Chain stock tokens.

Usage:
    python pools.py list --symbol NVDA [--refresh]
    python pools.py census [--limit 25] [--quote USDG|WETH]

Depth does not compare across versions: v2/v3 report the quote asset in the
pool, v4 reports in-range liquidity because its funds sit in the singleton.
"""

import argparse
import json
import os
import sys
import time
import typing as t
from pathlib import Path

from web3 import Web3

import _bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import evm  # noqa: E402  pylint: disable=wrong-import-position
import stocktokens  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position

CACHE_FILE = Path("stocktokens.pools.json")
CACHE_MAX_AGE_S = 3600.0


def discover(w3: Web3, token: str, quote_name: str = "USDG") -> list[uniswap.Pool]:
    """Candidate pools for a ticker, with a depth reading for the priced ones."""
    quote = stocktokens.QUOTE_ASSETS[quote_name]
    decimals = evm.token_decimals(w3, quote)
    candidates = uniswap.discover(w3, stocktokens.CHAIN_ID, token, quote)
    priced = [c for c in candidates if c["version"] != "v4"]
    singleton = [c for c in candidates if c["version"] == "v4"]
    for candidate in priced:
        candidate["quote_depth"] = evm.balance_of(
            w3, quote, candidate["address"], decimals
        )
    priced.sort(key=lambda c: float(c.get("quote_depth", 0.0)), reverse=True)
    singleton.sort(key=lambda c: int(c["liquidity"]), reverse=True)
    found: list[uniswap.Pool] = [*priced, *singleton]
    for pool in found:
        pool["quote"] = quote_name
        pool["quote_address"] = quote
    return found


def _validated(raw: t.Any, token: str, quote_name: str) -> list[uniswap.Pool]:
    """Pools read back from disk, checked before they can reach the router.

    The cache is a plain file in the agent's cwd, so an entry is untrusted
    input, and ``verify_execute`` cannot be what validates it: that compares
    the calldata against this same entry. Every field discovery would have
    chosen is therefore re-derived or re-checked here — the fee tier as much
    as the hooks, since a forged tier routes the trade through a pool the
    operator never picked.

    Raises:
        SwapError: when an entry is not a pool discovery wrote.
    """
    if not isinstance(raw, list):
        raise evm.SwapError(f"cached pools are {type(raw).__name__}, expected a list")
    quote = stocktokens.QUOTE_ASSETS[quote_name]
    for pool in raw:
        version = pool.get("version") if isinstance(pool, dict) else None
        if version not in uniswap.SWAP_COMMANDS:
            raise evm.SwapError(f"cached pool has version {version!r}")
        if pool.get("quote_address") != quote or pool.get("quote") != quote_name:
            raise evm.SwapError(f"cached {version} pool is not quoted in {quote_name}")
        if version == "v3" and pool.get("fee") not in uniswap.V3_FEES:
            raise evm.SwapError(
                f"cached v3 pool has fee {pool.get('fee')!r}; discovery only "
                f"ever writes {uniswap.V3_FEES}"
            )
        if version == "v4":
            tier = (pool.get("fee"), pool.get("tick_spacing"))
            if tier not in uniswap.V4_TIERS:
                raise evm.SwapError(
                    f"cached v4 pool has tier {tier!r}; discovery only ever "
                    f"writes {uniswap.V4_TIERS}"
                )
            if pool.get("hooks") != uniswap.NO_HOOKS:
                raise evm.SwapError(
                    f"cached v4 pool carries hooks {pool.get('hooks')!r}; discovery "
                    f"only ever writes hook-less pools"
                )
            derived = uniswap.v4_pool_id(
                token, quote, tier[0], tier[1], uniswap.NO_HOOKS
            )
            if pool.get("pool_id") != "0x" + derived.hex():
                raise evm.SwapError(
                    f"cached v4 pool_id {pool.get('pool_id')!r} is not the id its "
                    f"own PoolKey derives"
                )
        if version != "v4" and not pool.get("address"):
            raise evm.SwapError(f"cached {version} pool has no address")
    pools: list[uniswap.Pool] = raw
    return pools


def _load_cache() -> dict[str, t.Any]:
    """Read cached discovery, or an empty book when there is none or it is corrupt."""
    if not CACHE_FILE.exists():
        return {}
    try:
        cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"pool cache unusable ({exc}); rediscovering", file=sys.stderr)
        return {}
    return cached if isinstance(cached, dict) else {}


def _store_cache(cache: dict[str, t.Any]) -> None:
    """Persist discovery atomically; a half-written file is the corrupt one."""
    scratch = CACHE_FILE.with_suffix(".tmp")
    scratch.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    os.replace(scratch, CACHE_FILE)


def cached_discover(
    w3: Web3, token: str, quote_name: str = "USDG", refresh: bool = False
) -> list[uniswap.Pool]:
    """Discovery behind an hour-long cache; the public RPC rate-limits hard."""
    cache = _load_cache()
    key = f"{token}:{quote_name}"
    entry = cache.get(key)
    if not refresh and isinstance(entry, dict):
        age = time.time() - float(entry.get("fetched_at", 0.0))
        if 0 <= age < CACHE_MAX_AGE_S:
            return _validated(entry.get("pools"), token, quote_name)
    pools = discover(w3, token, quote_name)
    cache[key] = {
        "fetched_at": time.time(),
        "block": w3.eth.block_number,
        "pools": pools,
    }
    _store_cache(cache)
    return pools


def _cmd_list(args: argparse.Namespace) -> int:
    """Print every candidate pool for one ticker."""
    asset = stocktokens.lookup(args.symbol)
    w3, _ = evm.connect(stocktokens.CHAIN)
    print(
        json.dumps(
            {
                "symbol": args.symbol,
                "token": asset["address"],
                "multiplier": asset["multiplier"],
                "pending_multiplier": asset["pending_multiplier"],
                "quote": args.quote,
                "pools": cached_discover(
                    w3, asset["address"], args.quote, args.refresh
                ),
            },
            indent=2,
        )
    )
    return 0


def _cmd_census(args: argparse.Namespace) -> int:
    """Walk the registry and report where liquidity actually sits."""
    registry = stocktokens.asset_registry()
    w3, _ = evm.connect(stocktokens.CHAIN)
    rows = []
    for symbol, asset in list(registry.items())[: args.limit]:
        found = cached_discover(w3, asset["address"], args.quote, args.refresh)
        rows.append(
            (sum(float(p.get("quote_depth", 0.0)) for p in found), symbol, found)
        )
    rows.sort(reverse=True, key=lambda row: row[0])
    for depth, symbol, found in rows:
        versions = ",".join(sorted({str(p["version"]) for p in found})) or "none"
        print(
            f"{symbol:<8} {depth:>14,.0f} {args.quote:<5} "
            f"{len(found):>2} pools  {versions}"
        )
    return 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="stock-token pool discovery")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--quote", choices=sorted(stocktokens.QUOTE_ASSETS), default="USDG"
    )
    common.add_argument("--refresh", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list", parents=[common])
    listing.add_argument("--symbol", required=True)
    listing.set_defaults(func=_cmd_list)
    census = sub.add_parser("census", parents=[common])
    census.add_argument("--limit", type=int, default=25)
    census.set_defaults(func=_cmd_census)
    args = parser.parse_args()
    try:
        result: int = args.func(args)
    except evm.SwapError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
