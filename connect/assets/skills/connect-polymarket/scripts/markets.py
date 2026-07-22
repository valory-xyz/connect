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

"""Market discovery and prices — public endpoints, no auth, works in any mode.

Usage:
    python markets.py list [--limit 20] [--query "bitcoin"] [--tag politics]
    python markets.py market --slug will-x-happen        # or --condition-id 0x...
    python markets.py book  --token-id 123...            # CLOB order book
    python markets.py price --token-id 123... --side buy # best price
"""

import argparse
import json

import pm_common as pm


def _json_field(market: dict, key: str):
    """Read a Gamma field that may be a JSON-encoded string (list) or native."""
    value = market.get(key)
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _slim(market: dict) -> dict:
    """Return the fields a trading decision actually needs."""
    return {
        "question": market.get("question"),
        "slug": market.get("slug"),
        "condition_id": market.get("conditionId"),
        "outcomes": _json_field(market, "outcomes"),
        "outcome_prices": _json_field(market, "outcomePrices"),
        "clob_token_ids": _json_field(market, "clobTokenIds"),
        "neg_risk": market.get("negRisk"),
        "volume": market.get("volumeNum") or market.get("volume"),
        "liquidity": market.get("liquidityNum") or market.get("liquidity"),
        "end_date": market.get("endDate"),
        "active": market.get("active"),
        "closed": market.get("closed"),
    }


def cmd_list(limit: int, query: str | None, tag: str | None) -> None:
    """Active markets by volume; --query filters question text client-side."""
    params: dict = {
        "active": "true",
        "closed": "false",
        "order": "volumeNum",
        "ascending": "false",
        # over-fetch when filtering client-side so a narrow query still fills
        "limit": limit if not query else max(limit * 10, 100),
    }
    if tag:
        params["tag_slug"] = tag
    markets = pm.http_get_json(f"{pm.GAMMA_API}/markets", params=params) or []
    if query:
        needle = query.lower()
        markets = [m for m in markets if needle in (m.get("question") or "").lower()]
    pm.print_json([_slim(m) for m in markets[:limit]])


def cmd_market(slug: str | None, condition_id: str | None) -> None:
    """One market's full trading parameters, by slug or condition id.

    Falls back to the events index for slugs /markets doesn't serve — the
    recurring crypto up/down series (slugs like ``btc-updown-5m-<unixts>``,
    one market per window) resolves only there. Mind the year: date-named
    slugs match the oldest edition.
    """
    if slug:
        markets = pm.http_get_json(f"{pm.GAMMA_API}/markets", params={"slug": slug})
        if not markets:
            events = pm.http_get_json(f"{pm.GAMMA_API}/events", params={"slug": slug})
            markets = [m for e in events or [] for m in e.get("markets") or []]
    elif condition_id:
        markets = pm.http_get_json(
            f"{pm.GAMMA_API}/markets", params={"condition_ids": condition_id}
        )
    else:
        raise SystemExit("pass --slug or --condition-id")
    if not markets:
        raise SystemExit("no market found")
    pm.print_json([_slim(m) for m in markets])


def cmd_book(token_id: str) -> None:
    """Fetch the CLOB order book for an outcome token."""
    pm.print_json(
        pm.http_get_json(f"{pm.CLOB_HOST}/book", params={"token_id": token_id})
    )


def cmd_price(token_id: str, side: str) -> None:
    """Best CLOB price for an outcome token, per side."""
    pm.print_json(
        pm.http_get_json(
            f"{pm.CLOB_HOST}/price",
            params={"token_id": token_id, "side": side.upper()},
        )
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list")
    lst.add_argument("--limit", type=int, default=20)
    lst.add_argument("--query", default=None)
    lst.add_argument("--tag", default=None)
    market = sub.add_parser("market")
    market.add_argument("--slug", default=None)
    market.add_argument("--condition-id", default=None)
    book = sub.add_parser("book")
    book.add_argument("--token-id", required=True)
    price = sub.add_parser("price")
    price.add_argument("--token-id", required=True)
    price.add_argument("--side", choices=["buy", "sell"], default="buy")
    args = parser.parse_args()
    if args.command == "list":
        cmd_list(args.limit, args.query, args.tag)
    elif args.command == "market":
        cmd_market(args.slug, args.condition_id)
    elif args.command == "book":
        cmd_book(args.token_id)
    elif args.command == "price":
        cmd_price(args.token_id, args.side)


if __name__ == "__main__":
    main()
