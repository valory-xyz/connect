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

"""Find Pons launches: the API verified on-chain, else an index of factory logs."""

import sys
import time
import typing as t
from pathlib import Path

from eth_utils import is_address, keccak, to_checksum_address
from web3 import Web3

import _pons_bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import evm  # noqa: E402  pylint: disable=wrong-import-position
import pons  # noqa: E402  pylint: disable=wrong-import-position
import state  # noqa: E402  pylint: disable=wrong-import-position
import web  # noqa: E402  pylint: disable=wrong-import-position

TOPIC_V2_GRADUATED = keccak(text="PoolGraduated(address,uint256,uint256,uint256)")
TOPIC_V1_LAUNCHED = keccak(
    text="TokenLaunched(address,address,address,address,address,uint256,uint256,"
    "uint256,uint256,uint256)"
)
V2_DEPLOYED_BLOCK = 26841846
FEEDS = {
    "v2-launched": (pons.V2_FACTORY, pons.TOPIC_V2_LAUNCHED, V2_DEPLOYED_BLOCK, True),
    "v2-graduated": (pons.V2_FACTORY, TOPIC_V2_GRADUATED, V2_DEPLOYED_BLOCK, False),
    "v1-launched": (pons.V1_FACTORIES[0], TOPIC_V1_LAUNCHED, 8991118, True),
    "v1-legacy-launched": (pons.V1_FACTORIES[1], TOPIC_V1_LAUNCHED, 8600612, True),
}

INDEX_FILE = Path("pons.index.json")
LOOKBACK_BLOCKS = 250_000
LOG_CHUNK = 2_000_000
MIN_LOG_CHUNK = 1_000
MAX_LOG_REQUESTS = 40
METADATA_BATCH = 400
MAX_METADATA_BATCHES = 12
REQUEST_PAUSE_S = 0.2
RATE_LIMIT_RETRIES = 3


class IndexEntry(t.TypedDict):
    """One indexed launch: where and when it was seen, and what it is called."""

    factory: str
    block: int
    name: t.Optional[str]
    symbol: t.Optional[str]
    graduated: bool


class Index(t.TypedDict):
    """The on-chain discovery index: scanned block spans per feed, and tokens."""

    ranges: dict[str, list[int]]
    tokens: dict[str, IndexEntry]


def _verified(w3: Web3, item: dict[str, t.Any]) -> t.Optional[dict[str, t.Any]]:
    """Confirm an API item on-chain, or return None after saying why it was dropped."""
    token = item["token"]
    try:
        launch = pons.launch_record(w3, token)
    except evm.SwapError as exc:
        print(f"NOTE: dropped API result {token}: {exc}", file=sys.stderr)
        return None
    claims = {
        "factory": (launch["factory"], to_checksum_address(item["factory"])),
        "pair token": (launch["pair_token"], to_checksum_address(item["pairToken"])),
    }
    for what, (chain, api) in claims.items():
        if chain != api:
            print(
                f"NOTE: dropped API result {token}: the API says {what} {api}, "
                f"the chain says {chain}",
                file=sys.stderr,
            )
            return None
    return {**launch, "market": pons.market_readout(item)}


def search(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    w3: Web3,
    query: str,
    sort: str = "marketCap",
    page: int = 1,
    quote: t.Optional[str] = None,
    limit: int = 10,
) -> tuple[list[dict[str, t.Any]], str]:
    """Find launches, verified on-chain; the second value names the source."""
    try:
        doc = pons.api_search(query, sort, page, quote)
    except web.Unavailable as exc:
        print(
            f"NOTICE: the Pons API is unavailable ({exc}); falling back to "
            f"on-chain discovery (slower; graduated tokens first, then newest)",
            file=sys.stderr,
        )
        return _onchain_search(w3, query, page, quote, limit), "onchain"
    found = []
    for item in doc["items"][:limit]:
        entry = _verified(w3, item)
        if entry is not None:
            found.append(entry)
    return found, "api"


def _entry(raw: dict[str, t.Any]) -> IndexEntry:
    """Rebuild a stored index entry, keeping only well-typed names."""
    name, symbol = raw["name"], raw["symbol"]
    return {
        "factory": to_checksum_address(raw["factory"]),
        "block": int(raw["block"]),
        "name": name if isinstance(name, str) else None,
        "symbol": symbol if isinstance(symbol, str) else None,
        "graduated": raw["graduated"] is True,
    }


def _index(raw: t.Any) -> Index:
    """Rebuild a stored index, keeping only the feeds this skill scans."""
    return {
        "ranges": {
            feed: [int(raw["ranges"][feed][0]), int(raw["ranges"][feed][1])]
            for feed in FEEDS
            if feed in raw["ranges"]
        },
        "tokens": {
            to_checksum_address(token): _entry(entry)
            for token, entry in raw["tokens"].items()
        },
    }


def _load_index() -> Index:
    """Load the on-chain discovery index from cwd, or a fresh one when unreadable."""
    index = state.read_json(INDEX_FILE, "rebuilding it from scratch", _index)
    return index or {"ranges": {}, "tokens": {}}


def _scan_span(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    w3: Web3,
    index: Index,
    feed: str,
    first: int,
    last: int,
    forward: bool,
    budget: list[int],
) -> None:
    """Index one feed over [first, last], recording each scanned chunk.

    Raises:
        SwapError: when the RPC fails the scan.
    """
    factory, topic, _, windowed = FEEDS[feed]
    span = index["ranges"][feed]

    def fetch(lo: int, hi: int) -> list[t.Any]:
        """Read the feed's logs in one span."""
        query = {
            "address": factory,
            "fromBlock": lo,
            "toBlock": hi,
            "topics": ["0x" + topic.hex()],
        }
        return evm.get_logs(
            w3,
            query,
            f"{INDEX_FILE} keeps what was indexed, so retry in a minute",
            RATE_LIMIT_RETRIES,
            REQUEST_PAUSE_S,
        )

    def record(logs: list[t.Any], lo: int, hi: int) -> None:
        """Index a chunk's launches and extend the feed's scanned span."""
        for log in logs:
            token = to_checksum_address(bytes(log["topics"][1])[-20:])
            entry = index["tokens"].setdefault(
                token,
                {
                    "factory": factory,
                    "block": int(log["blockNumber"]),
                    "name": None,
                    "symbol": None,
                    "graduated": False,
                },
            )
            entry["graduated"] = entry["graduated"] or not windowed
        if forward:
            span[1] = hi
        else:
            span[0] = lo

    evm.scan_logs(fetch, first, last, forward, budget, record, LOG_CHUNK, MIN_LOG_CHUNK)


def _feed_start(feed: str, head: int) -> int:
    """Return the oldest block a feed is indexed from."""
    _, _, deployed, windowed = FEEDS[feed]
    return max(deployed, head - LOOKBACK_BLOCKS) if windowed else deployed


def _scan(w3: Web3, index: Index) -> bool:
    """Extend every feed to the head and back to its start; True when all are whole."""
    head = int(w3.eth.block_number)
    stale = [
        token
        for token, entry in index["tokens"].items()
        if not entry["graduated"] and entry["block"] < head - LOOKBACK_BLOCKS
    ]
    for token in stale:
        del index["tokens"][token]
    budget = [MAX_LOG_REQUESTS]
    for feed in FEEDS:
        span = index["ranges"].setdefault(feed, [head + 1, head])
        _scan_span(w3, index, feed, span[1] + 1, head, True, budget)
        _scan_span(w3, index, feed, _feed_start(feed, head), span[0] - 1, False, budget)
    return all(
        index["ranges"][feed][0] <= _feed_start(feed, head)
        and index["ranges"][feed][1] >= head
        for feed in FEEDS
    )


def _fill_metadata(w3: Web3, tokens: list[str], index: Index) -> bool:
    """Read missing names and symbols through Multicall3; True when none remain.

    Raises:
        SwapError: when Multicall3 answers a different number of results.
    """
    missing = [
        token
        for token in tokens
        if index["tokens"][token]["name"] is None
        or index["tokens"][token]["symbol"] is None
    ]
    for batch_no in range(MAX_METADATA_BATCHES):
        batch = missing[batch_no * METADATA_BATCH : (batch_no + 1) * METADATA_BATCH]
        if not batch:
            return True
        calls = [
            (token, sel) for token in batch for sel in (evm.SEL_NAME, evm.SEL_SYMBOL)
        ]
        time.sleep(REQUEST_PAUSE_S)
        results = evm.multicall(w3, calls)
        for offset, token in enumerate(batch):
            entry = index["tokens"][token]
            (name_ok, name), (symbol_ok, symbol) = results[2 * offset : 2 * offset + 2]
            entry["name"] = evm.decode_string_result(name_ok, name, f"{token}'s name")
            entry["symbol"] = evm.decode_string_result(
                symbol_ok, symbol, f"{token}'s symbol"
            )
    return len(missing) <= MAX_METADATA_BATCHES * METADATA_BATCH


def _quote_matches(launch: pons.Launch, quote: t.Optional[str]) -> bool:
    """Whether a launch trades against the requested pair asset symbol."""
    if not quote:
        return True
    return launch["pair_symbol"].lower() == quote.strip().lower()


def _onchain_search(
    w3: Web3, query: str, page: int, quote: t.Optional[str], limit: int
) -> list[dict[str, t.Any]]:
    """Discovery from factory logs: graduated V2 tokens, then the newest launches."""
    needle = query.strip()
    if is_address(needle):
        launch = pons.launch_record(w3, needle)
        return [dict(launch)] if _quote_matches(launch, quote) else []
    print(
        f"NOTICE: on-chain discovery covers every graduated V2 token and launches "
        f"from the last {LOOKBACK_BLOCKS:,} blocks; look anything else up by "
        f"address",
        file=sys.stderr,
    )
    index = _load_index()
    tokens = index["tokens"]
    try:
        complete = _scan(w3, index)
        ranked = sorted(
            tokens, key=lambda k: (not tokens[k]["graduated"], -tokens[k]["block"])
        )
        complete = _fill_metadata(w3, ranked, index) and complete
    finally:
        state.write_json_atomic(INDEX_FILE, index, compact=True)
    if not complete:
        print(
            f"NOTICE: {INDEX_FILE} is still being built; results are partial, and "
            f"running the search again can extend it",
            file=sys.stderr,
        )
    needle = needle.lower()
    hits = [
        token
        for token in ranked
        if needle in (tokens[token]["name"] or "").lower()
        or needle in (tokens[token]["symbol"] or "").lower()
    ]
    found: list[dict[str, t.Any]] = []
    for token in hits[(page - 1) * limit :]:
        if len(found) >= limit:
            break
        try:
            launch = pons.launch_record(w3, token)
        except evm.SwapError as exc:
            print(f"NOTE: skipped {token}: {exc}", file=sys.stderr)
            continue
        if _quote_matches(launch, quote):
            found.append(dict(launch))
    return found


__all__ = ["INDEX_FILE", "search"]
