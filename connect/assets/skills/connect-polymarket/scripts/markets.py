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

"""Market discovery and prices — public endpoints, no auth needed.

Usage:
    python markets.py list [--limit 20] [--query "bitcoin"] [--tag politics]
                           [--ends-within 48h] [--no-live]
    python markets.py market --slug will-x-happen        # or --condition-id 0x...
    python markets.py group  --slug will-x-happen        # neg-risk siblings
    python markets.py book  --token-id 123...            # CLOB order book
    python markets.py price --token-id 123...            # live top of book

Prices arrive from two different places and they do NOT agree. Gamma's
``outcomePrices`` is a cached snapshot that can sit whole cents away from the
live book, so it is reported as ``outcome_prices_indicative`` and must never
be quoted as the current price. ``live_prices`` is the CLOB's own top of
book, fetched on every call unless you pass --no-live.
"""

import argparse
import json
import re
from datetime import datetime, timedelta, timezone

import pm_common as pm

_DURATION = re.compile(r"^(\d+)([hdw])$")
_DURATION_UNITS = {"h": "hours", "d": "days", "w": "weeks"}

# over-fetch, because the search page is filtered locally (see _search_markets)
_SEARCH_OVERFETCH = 5
_SEARCH_MIN_FETCH = 20


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
        "group_item_title": market.get("groupItemTitle"),
        "outcomes": _json_field(market, "outcomes"),
        "outcome_prices_indicative": _json_field(market, "outcomePrices"),
        "clob_token_ids": _json_field(market, "clobTokenIds"),
        "neg_risk": market.get("negRisk"),
        "volume": market.get("volumeNum") or market.get("volume"),
        "liquidity": market.get("liquidityNum") or market.get("liquidity"),
        "end_date": market.get("endDate"),
        "active": market.get("active"),
        "closed": market.get("closed"),
    }


def _token_ids(slim: dict) -> list:
    """Return a slimmed market's outcome token ids, as strings."""
    tokens = slim.get("clob_token_ids")
    if not isinstance(tokens, list):
        return []
    return [str(token) for token in tokens if token]


def _attach_live_prices(slims: list, live: bool = True) -> list:
    """Add the CLOB's live top of book to each slimmed market, in one call.

    A failure is reported per market rather than raised: discovery still has
    value without live prices. Every market gets either ``live_prices`` or
    ``live_prices_error`` and never neither, so "I could not check" cannot
    read as "the cache is current".
    """
    if not live:
        return slims
    try:
        prices = pm.clob_live_prices(
            [token for slim in slims for token in _token_ids(slim)]
        )
    except Exception as e:  # noqa: BLE001 - advisory read: report, don't abort
        for slim in slims:
            slim["live_prices_error"] = (
                f"could not read the live CLOB book ({type(e).__name__}: {e}); "
                "prices here are unknown, not the cached snapshot"
            )
        return slims
    for slim in slims:
        outcomes = slim.get("outcomes")
        outcomes = outcomes if isinstance(outcomes, list) else []
        quoted = {}
        for index, token in enumerate(_token_ids(slim)):
            name = outcomes[index] if index < len(outcomes) else f"outcome_{index}"
            if token in prices:
                quoted[str(name)] = prices[token]
        slim["live_prices"] = quoted or None
    return slims


def _tradeable(market: dict) -> bool:
    """Whether a market can still be traded."""
    return not market.get("closed") and market.get("active") is not False


def _volume(market: dict) -> float:
    """Sort key: Gamma reports volume as a number or as a numeric string."""
    try:
        return float(market.get("volumeNum") or market.get("volume") or 0)
    except (TypeError, ValueError):
        return 0.0


def _event_tag_slugs(event: dict) -> set:
    """Collect an event's tag slugs, for local --tag filtering."""
    tags = event.get("tags")
    return {
        str(tag.get("slug"))
        for tag in (tags if isinstance(tags, list) else [])
        if isinstance(tag, dict) and tag.get("slug")
    }


def _search_markets(query: str, limit: int, tag: str | None) -> list:
    """Full-text market search through Gamma's public-search index.

    ``/markets`` has no text parameter at all — it ignores ``q``, ``search``
    and ``question`` and serves the default page regardless — so the substring
    scan this replaces only ever matched inside the volume-ordered head, and
    markets that plainly existed came back as no results.

    public-search is relevance-ranked and event-shaped, so its markets are
    flattened, re-filtered for tradeability (it returns resolved ones even
    with ``events_status=active``) and ordered by volume.
    """
    payload = pm.http_get_json(
        f"{pm.GAMMA_API}/public-search",
        params={
            "q": query,
            "limit_per_type": max(limit * _SEARCH_OVERFETCH, _SEARCH_MIN_FETCH),
            "events_status": "active",
        },
    )
    events = payload.get("events") if isinstance(payload, dict) else None
    markets: list = []
    for event in events if isinstance(events, list) else []:
        if tag and tag not in _event_tag_slugs(event):
            continue
        markets.extend(event.get("markets") or [])
    return sorted(
        (market for market in markets if _tradeable(market)),
        key=_volume,
        reverse=True,
    )


def _ends_within_bounds(
    window: str, now: datetime | None = None
) -> tuple[datetime, datetime]:
    """Return the (start, end) a `48h` / `7d` / `2w` window covers from now.

    The lower bound is now, so a market that already ended cannot come back.
    """
    match = _DURATION.match(window.strip().lower())
    if not match:
        raise SystemExit(
            f"--ends-within must be <number><h|d|w> (e.g. 48h, 7d, 2w), got '{window}'"
        )
    amount, unit = match.groups()
    if int(amount) <= 0:
        raise SystemExit(f"--ends-within must be a positive window, got '{window}'")
    start = now or datetime.now(timezone.utc)
    return start, start + timedelta(**{_DURATION_UNITS[unit]: int(amount)})


def _ends_within_params(start: datetime, end: datetime) -> dict:
    """Gamma's server-side end-date filter for the window."""
    return {
        "end_date_min": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_date_max": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _ends_in_window(market: dict, start: datetime, end: datetime) -> bool:
    """Whether this market's own endDate really falls inside the window.

    Gamma ignores query parameters it does not recognise, so the server-side
    filter alone cannot be trusted to have been applied — the caller would get
    a full unfiltered page with no sign that "resolves within N" was dropped.
    Re-checking each market's own endDate makes the answer right either way; a
    market whose endDate is missing or unparseable is excluded rather than
    assumed to qualify.
    """
    raw = market.get("endDate")
    if not isinstance(raw, str):
        return False
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return start <= when <= end


def cmd_list(  # pylint: disable=too-many-arguments
    limit: int,
    query: str | None,
    tag: str | None,
    ends_within: str | None = None,
    live: bool = True,
) -> None:
    """Markets by volume; --query searches, --ends-within bounds resolution."""
    bounds = _ends_within_bounds(ends_within) if ends_within else None
    if query:
        markets = _search_markets(query, limit, tag)
    else:
        params: dict = {
            "active": "true",
            "closed": "false",
            "order": "volumeNum",
            "ascending": "false",
            # over-fetch when filtering client-side so a narrow filter still fills
            "limit": limit if not bounds else max(limit * 10, 100),
        }
        if tag:
            params["tag_slug"] = tag
        if bounds:
            params.update(_ends_within_params(*bounds))
        markets = pm.http_get_json(f"{pm.GAMMA_API}/markets", params=params) or []
    if bounds:
        markets = [m for m in markets if _ends_in_window(m, *bounds)]
    pm.print_json(_attach_live_prices([_slim(m) for m in markets[:limit]], live))


def _lookup_markets(slug: str | None, condition_id: str | None) -> list:
    """Find a market by slug or condition id, raw as Gamma returns it.

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
    return markets


def cmd_market(slug: str | None, condition_id: str | None, live: bool = True) -> None:
    """One market's full trading parameters, by slug or condition id."""
    markets = _lookup_markets(slug, condition_id)
    pm.print_json(_attach_live_prices([_slim(m) for m in markets], live))


def _event_slug_of(market: dict) -> str | None:
    """Return the slug of the event a market belongs to, if Gamma linked one."""
    for event in market.get("events") or []:
        if isinstance(event, dict) and event.get("slug"):
            return str(event["slug"])
    return None


def _fetch_event(event_slug: str) -> dict | None:
    """One event — the container a market group lives in — or None."""
    events = pm.http_get_json(f"{pm.GAMMA_API}/events", params={"slug": event_slug})
    return events[0] if events else None


def _require_event(event_slug: str) -> dict:
    """_fetch_event, for the callers that cannot continue without one."""
    event = _fetch_event(event_slug)
    if not event:
        raise SystemExit(f"no event found for slug '{event_slug}'")
    return event


def _resolve_event(
    slug: str | None, condition_id: str | None, event_slug: str | None
) -> dict:
    """Find the event holding a market, from any of the three identifiers."""
    if event_slug:
        return _require_event(event_slug)
    market = _lookup_markets(slug, condition_id)[0]
    found = _event_slug_of(market)
    if found:
        return _require_event(found)
    # No `events` key — which is also true of markets reached through
    # _lookup_markets' events-index fallback, even though that lookup just
    # proved `slug` names an event. Try it as one before giving up.
    event = _fetch_event(slug) if slug else None
    if event:
        return event
    raise SystemExit(
        f"'{slug or condition_id}' is not part of a market group Gamma exposes"
        " — pass --event-slug if you know the event"
    )


def _first_outcome_price(slim: dict) -> tuple:
    """Return the first outcome's price and whether it came from the live book.

    Live first: the sum it feeds is only a sanity check if the numbers are
    current. The source travels with the price because a sibling with a
    one-sided book falls back to the cache inside the same total, and a sum
    that is quietly part-cache should not read as "live and complete".
    """
    outcomes = slim.get("outcomes")
    outcomes = outcomes if isinstance(outcomes, list) else []
    if not outcomes:
        return None, False
    live = (slim.get("live_prices") or {}).get(str(outcomes[0])) or {}
    if live.get("mid") is not None:
        return float(live["mid"]), True
    indicative = slim.get("outcome_prices_indicative")
    if isinstance(indicative, list) and indicative:
        return pm.price_or_none(indicative[0]), False
    return None, False


def cmd_group(
    slug: str | None,
    condition_id: str | None,
    event_slug: str | None,
    live: bool = True,
) -> None:
    """Every sibling market in a group, plus the price sum that checks them.

    A neg-risk event ("which company is largest?") is one market per outcome,
    and the siblings only mean anything together — exactly one can resolve
    YES. Finding them should not depend on noticing them by accident; the sum
    reported alongside is the sanity check (see ``sum_note``).
    """
    event = _resolve_event(slug, condition_id, event_slug)
    siblings = _attach_live_prices([_slim(m) for m in event.get("markets") or []], live)
    priced = [
        (price, is_live)
        for price, is_live in (_first_outcome_price(s) for s in siblings)
        if price is not None
    ]
    prices = [price for price, _ in priced]
    from_live = sum(1 for _, is_live in priced if is_live)
    pm.print_json(
        {
            "event": event.get("title"),
            "event_slug": event.get("slug"),
            "neg_risk": event.get("negRisk"),
            "markets": len(siblings),
            "priced_markets": len(prices),
            "priced_from_live_book": from_live,
            "priced_from_cache": len(prices) - from_live,
            "first_outcome_price_sum": round(sum(prices), 4) if prices else None,
            "sum_note": (
                "a neg-risk group's first-outcome prices should sum to ~1.0; "
                "a sum well off 1.0 means the set is incomplete or the prices "
                "are not live. Any priced_from_cache > 0 means the sum is "
                "partly the indicative snapshot, so it is not a live check"
            ),
            "siblings": siblings,
        }
    )


def cmd_book(token_id: str) -> None:
    """Fetch the CLOB order book for an outcome token."""
    pm.print_json(
        pm.http_get_json(f"{pm.CLOB_HOST}/book", params={"token_id": token_id})
    )


def cmd_price(token_id: str) -> None:
    """Live top of book for an outcome token: best bid, best ask and mid.

    Takes no --side deliberately: the CLOB's own /price answers ``side=buy``
    with the best *bid*, and reading that as "the price to buy" misprices
    everything downstream (see ``pm.clob_live_prices``).
    """
    prices = pm.clob_live_prices([token_id])
    if not prices:
        raise SystemExit(f"the CLOB returned no prices for token {token_id}")
    pm.print_json(prices)


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    lst = sub.add_parser("list")
    lst.add_argument("--limit", type=int, default=20)
    lst.add_argument("--query", default=None)
    lst.add_argument("--tag", default=None)
    lst.add_argument(
        "--ends-within",
        default=None,
        help="only markets resolving within this window, e.g. 48h, 7d, 2w",
    )
    lst.add_argument(
        "--no-live",
        action="store_true",
        help="skip the live CLOB prices, leaving only Gamma's cached snapshot",
    )
    market = sub.add_parser("market")
    market.add_argument("--slug", default=None)
    market.add_argument("--condition-id", default=None)
    market.add_argument("--no-live", action="store_true")
    group = sub.add_parser("group")
    group.add_argument("--slug", default=None)
    group.add_argument("--condition-id", default=None)
    group.add_argument(
        "--event-slug", default=None, help="the group itself, if you know its slug"
    )
    group.add_argument("--no-live", action="store_true")
    book = sub.add_parser("book")
    book.add_argument("--token-id", required=True)
    price = sub.add_parser("price")
    price.add_argument("--token-id", required=True)
    args = parser.parse_args()
    if args.command == "list":
        cmd_list(args.limit, args.query, args.tag, args.ends_within, not args.no_live)
    elif args.command == "market":
        cmd_market(args.slug, args.condition_id, not args.no_live)
    elif args.command == "group":
        cmd_group(args.slug, args.condition_id, args.event_slug, not args.no_live)
    elif args.command == "book":
        cmd_book(args.token_id)
    elif args.command == "price":
        cmd_price(args.token_id)


if __name__ == "__main__":
    main()
