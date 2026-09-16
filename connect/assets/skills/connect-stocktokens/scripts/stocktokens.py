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

"""Everything specific to Robinhood's Stock Tokens: registry, prices, multiplier."""

import functools
import json
import math
import typing as t
import urllib.request
from decimal import Decimal

from eth_utils import to_checksum_address
from web3 import Web3

import _bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

from evm import (  # noqa: E402  pylint: disable=wrong-import-position
    SwapError,
    call_int,
    selector,
)

CHAIN = "robinhood"
CHAIN_ID = 4663
ASSETS_URL = "https://api.robinhood.com/rhj/assets"
PRICES_URL = "https://api.robinhood.com/rhj/prices/{symbol}"
USER_AGENT = "connect-stocktokens/0.1"

USDG = to_checksum_address("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")
WETH = to_checksum_address("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73")
QUOTE_ASSETS = {"USDG": USDG, "WETH": WETH}

TRADABLE_STATUS = frozenset({"ASSET_STATUS_ACTIVE"})
SEL_UI_MULTIPLIER = selector("uiMultiplier()")
MULTIPLIER_SCALE = Decimal(10**18)
WARN_PRICE_GAP_BPS = 50.0
MAX_PRICE_GAP_BPS = 150.0


def get_json(url: str) -> t.Any:
    """GET a JSON document with the User-Agent Robinhood's edge requires.

    Raises:
        SwapError: when the endpoint is unreachable or does not answer with
            JSON. The agent is told to report a refusal, so a Robinhood outage
            has to arrive as one rather than as a traceback.
    """
    request = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
            return json.load(response)
    except (OSError, ValueError) as exc:
        raise SwapError(f"could not read {url} ({type(exc).__name__}: {exc})") from exc


def _field(doc: t.Any, *path: t.Any) -> t.Any:
    """Walk a Robinhood document, refusing a shape it no longer has.

    Raises:
        SwapError: when any step is missing; a feed that changed shape must
            not be indexed into and reported as a price.
    """
    here: t.Any = doc
    for step in path:
        try:
            here = here[step]
        except (KeyError, IndexError, TypeError) as exc:
            where = " -> ".join(str(p) for p in path)
            raise SwapError(
                f"Robinhood answered with a document this skill does not "
                f"recognise; no {where}"
            ) from exc
    return here


def token_multiplier(w3: Web3, token: str) -> str:
    """Read how many shares one token represents from the token contract.

    Raises:
        SwapError: when the token does not answer, or answers zero; defaulting
            it to 1 would misprice every comparison this skill makes.
    """
    raw = call_int(w3, token, SEL_UI_MULTIPLIER)
    if raw <= 0:
        raise SwapError(f"{token} reports uiMultiplier {raw}; refusing to price it")
    return str(Decimal(raw) / MULTIPLIER_SCALE)


class AssetBook(t.NamedTuple):
    """The tradable stock tokens, and why every other listed ticker is not."""

    tokens: dict[str, dict[str, t.Any]]
    excluded: dict[str, str]


@functools.lru_cache(maxsize=1)
def asset_book() -> AssetBook:
    """Live stock-token registry for this chain, tradable tickers separated out.

    An unusable listing excludes its own ticker and nothing else: one suspended
    or malformed token must not take the other two hundred down with it.

    Raises:
        SwapError: when the registry lists nothing at all for this chain.
    """
    tokens: dict[str, dict[str, t.Any]] = {}
    excluded: dict[str, str] = {}
    for index, asset in enumerate(_field(get_json(ASSETS_URL), "assets")):
        symbol = asset.get("tokenSymbol") if isinstance(asset, dict) else None
        if not isinstance(symbol, str) or not symbol:
            excluded[f"<listing {index}>"] = "has no tokenSymbol"
            continue
        try:
            entry = _listing(asset)
        except (SwapError, KeyError, TypeError, ValueError, AttributeError) as exc:
            tokens.pop(symbol, None)
            excluded[symbol] = (
                str(exc)
                if isinstance(exc, SwapError)
                else (f"listing is malformed ({type(exc).__name__}: {exc})")
            )
            continue
        if entry is None:
            continue
        if symbol in tokens or symbol in excluded:
            tokens.pop(symbol, None)
            excluded[symbol] = (
                f"listed twice on chain {CHAIN_ID}; refusing to guess which "
                f"contract you meant"
            )
            continue
        tokens[symbol] = entry
    if not tokens and not excluded:
        raise SwapError(f"no stock tokens for chain {CHAIN_ID} in {ASSETS_URL}")
    return AssetBook(tokens, excluded)


def _listing(asset: dict[str, t.Any]) -> t.Optional[dict[str, t.Any]]:
    """Build one listing's entry on this chain, or None when it is not here.

    Raises:
        SwapError: when the listing is here but cannot be traded.
    """
    here = [d for d in asset.get("deployments", []) if d.get("chainId") == CHAIN_ID]
    if not here:
        return None
    if len(here) > 1:
        raise SwapError(
            f"listed twice on chain {CHAIN_ID}; refusing to guess which "
            f"contract you meant"
        )
    if asset.get("status") not in TRADABLE_STATUS:
        raise SwapError(
            f"status is {asset.get('status')!r}; refusing to trade a token "
            f"Robinhood does not call active"
        )
    return {
        "address": to_checksum_address(here[0]["contractAddress"]),
        "name": asset.get("tokenName", ""),
        "pending_multiplier": asset.get("pendingMultiplier", ""),
        "status": asset["status"],
    }


def asset_registry() -> dict[str, dict[str, t.Any]]:
    """Return the tickers this skill will trade, keyed by symbol."""
    return asset_book().tokens


def lookup(symbol: str) -> dict[str, t.Any]:
    """One ticker's registry entry.

    Raises:
        SwapError: when the ticker is not listed on this chain, or is listed
            but was excluded — the reason it was excluded is the refusal.
    """
    book = asset_book()
    entry = book.tokens.get(symbol)
    if entry is not None:
        return entry
    if symbol in book.excluded:
        raise SwapError(f"{symbol} is not tradable: {book.excluded[symbol]}")
    raise SwapError(f"unknown ticker {symbol}; {len(book.tokens)} are listed")


def reference_price(symbol: str, multiplier: str) -> tuple[float, float, bool]:
    """Robinhood's own bid/ask for a ticker, scaled to one token.

    Raises:
        SwapError: when the quote or multiplier is not usable.
    """
    quote = _field(get_json(PRICES_URL.format(symbol=symbol)), "quotes", 0)
    if _field(quote, "tokenSymbol") != symbol:
        raise SwapError(
            f"asked for {symbol} and got a quote for {quote.get('tokenSymbol')!r}"
        )
    halted = _field(quote, "isTradingHalt")
    if not isinstance(halted, bool):
        raise SwapError(
            f"{symbol} quote has isTradingHalt {halted!r}; refusing to trade "
            f"without knowing whether the ticker is halted"
        )
    factor = _positive(multiplier)
    bid, ask = _positive(_field(quote, "bid")), _positive(_field(quote, "ask"))
    if None in (factor, bid, ask):
        raise SwapError(
            f"{symbol} priced at bid {quote.get('bid')!r} ask {quote.get('ask')!r} "
            f"with multiplier {multiplier!r}; refusing to trade without a usable "
            f"reference price"
        )
    return bid * factor, ask * factor, halted


def _positive(raw: t.Any) -> t.Any:
    """Parse a finite positive number from a feed value, or return None."""
    if isinstance(raw, bool):
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and value > 0 else None


def price_gap_bps(quoted_out: int, reference_out: int) -> float:
    """How far below Robinhood's own price a fill lands, in basis points.

    Raises:
        SwapError: when there is no reference to compare against; a zero
            reference must never read as "priced exactly right".
    """
    if reference_out <= 0:
        raise SwapError(
            f"no usable Robinhood reference price (got {reference_out}); "
            f"refusing to price a trade against nothing"
        )
    return (reference_out - quoted_out) / reference_out * 10000


def check_price_gap(
    quoted_out: int, reference_out: int, max_gap_bps: float = MAX_PRICE_GAP_BPS
) -> float:
    """Refuse a fill that has drifted too far from the underlying.

    Raises:
        SwapError: when the gap exceeds max_gap_bps.
    """
    gap = price_gap_bps(quoted_out, reference_out)
    if gap > max_gap_bps:
        raise SwapError(
            f"best pool is {gap:.0f} bps worse than Robinhood's own price "
            f"(limit {max_gap_bps:.0f}); refusing to trade at a dislocated pool"
        )
    if gap < -max_gap_bps:
        raise SwapError(
            f"best pool is {-gap:.0f} bps better than Robinhood's own price "
            f"(limit {max_gap_bps:.0f}); that is a broken reading, not a bargain"
        )
    return gap
