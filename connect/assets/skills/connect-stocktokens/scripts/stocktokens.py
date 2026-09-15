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
import typing as t
import urllib.request

from eth_utils import to_checksum_address

import _bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

from evm import SwapError  # noqa: E402  pylint: disable=wrong-import-position

CHAIN = "robinhood"
CHAIN_ID = 4663
ASSETS_URL = "https://api.robinhood.com/rhj/assets"
PRICES_URL = "https://api.robinhood.com/rhj/prices/{symbol}"
USER_AGENT = "connect-stocktokens/0.1"

USDG = to_checksum_address("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")
WETH = to_checksum_address("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73")
QUOTE_ASSETS = {"USDG": USDG, "WETH": WETH}

TRADABLE_STATUS = frozenset({"ASSET_STATUS_ACTIVE"})
WARN_PRICE_GAP_BPS = 50.0
MAX_PRICE_GAP_BPS = 150.0


def get_json(url: str) -> t.Any:
    """GET a JSON document with the User-Agent Robinhood's edge requires."""
    request = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
        return json.load(response)


def _multiplier(asset: dict[str, t.Any]) -> str:
    """Read the ticker's corporate-action multiplier, refusing a missing one.

    Raises:
        SwapError: when the field is absent or unparseable; defaulting it to 1
            would misprice every comparison this skill makes.
    """
    raw = asset.get("currentMultiplier")
    try:
        if raw is None or float(raw) <= 0:
            raise ValueError(raw)
    except (TypeError, ValueError) as exc:
        raise SwapError(
            f"no usable currentMultiplier ({raw!r}); refusing to price it"
        ) from exc
    return str(raw)


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
    for asset in get_json(ASSETS_URL)["assets"]:
        for deployment in asset.get("deployments", []):
            if deployment.get("chainId") != CHAIN_ID:
                continue
            symbol = asset["tokenSymbol"]
            if symbol in tokens or symbol in excluded:
                tokens.pop(symbol, None)
                excluded[symbol] = (
                    f"listed twice on chain {CHAIN_ID}; refusing to guess which "
                    f"contract you meant"
                )
                continue
            if asset.get("status") not in TRADABLE_STATUS:
                excluded[symbol] = (
                    f"status is {asset.get('status')!r}; refusing to trade a token "
                    f"Robinhood does not call active"
                )
                continue
            try:
                multiplier = _multiplier(asset)
            except SwapError as exc:
                excluded[symbol] = str(exc)
                continue
            tokens[symbol] = {
                "address": to_checksum_address(deployment["contractAddress"]),
                "name": asset.get("tokenName", ""),
                "multiplier": multiplier,
                "pending_multiplier": asset.get("pendingMultiplier", ""),
                "status": asset.get("status", ""),
            }
    if not tokens and not excluded:
        raise SwapError(f"no stock tokens for chain {CHAIN_ID} in {ASSETS_URL}")
    return AssetBook(tokens, excluded)


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
    """Robinhood's own bid/ask for a ticker, divided by its multiplier.

    Raises:
        SwapError: when the quote or multiplier is not usable.
    """
    quote = get_json(PRICES_URL.format(symbol=symbol))["quotes"][0]
    factor = float(multiplier or 1.0)
    if quote.get("tokenSymbol", symbol) != symbol:
        raise SwapError(
            f"asked for {symbol} and got a quote for {quote.get('tokenSymbol')!r}"
        )
    if "isTradingHalt" not in quote:
        raise SwapError(
            f"{symbol} quote has no isTradingHalt field; refusing to trade "
            f"against a quote whose shape we no longer recognise"
        )
    bid, ask = float(quote["bid"]), float(quote["ask"])
    if factor <= 0 or bid <= 0 or ask <= 0:
        raise SwapError(
            f"{symbol} priced at bid {bid} ask {ask} with multiplier {factor}; "
            f"refusing to trade without a usable reference price"
        )
    return bid / factor, ask / factor, bool(quote["isTradingHalt"])


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
