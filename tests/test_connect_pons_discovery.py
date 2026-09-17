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

"""Unit tests for the connect-pons skill's search and on-chain discovery index."""

import json
import typing as t

import pytest
from eth_utils import to_checksum_address
from web3.exceptions import Web3RPCError

from tests.conftest import (
    CURVE,
    Chain,
    OTHER,
    TOKEN,
    _item,
    _v1,
    _v2,
    discovery,
    evm,
    pons,
)


def test_search_verifies_every_api_result(chain: Chain, api: dict) -> None:
    """API results come back as on-chain launches with the market readout."""
    _v2(chain)
    found, source = discovery.search(chain, "pons")
    assert source == "api"
    assert found[0]["curve"] == CURVE
    assert found[0]["market"]["market_cap_usd"] == 5000
    assert found[0]["market"]["source"] == "pons api (unverified)"
    assert api["urls"][0].endswith("sort=marketCap&age=all&page=1")


def test_search_drops_results_the_chain_does_not_back(
    chain: Chain, api: dict, capsys: pytest.CaptureFixture
) -> None:
    """Unknown tokens and misreported factories or pairs are dropped, loudly."""
    _v2(chain)
    _v1(chain, token=OTHER, factory=9)
    third = to_checksum_address("0x" + "33" * 20)
    _v2(chain, token=third)
    api["search"]["items"] = [
        _item(factory=pons.V1_FACTORIES[0]),
        _item(token=OTHER),
        _item(token=third, pairToken=pons.WETH),
        _item(),
    ]
    found, _ = discovery.search(chain, "pons", limit=3)
    assert found == []
    err = capsys.readouterr().err
    assert "the API says factory" in err
    assert "not launched by any Pons factory" in err
    assert "the API says pair token" in err


def test_search_falls_back_to_the_chain_for_an_address(
    chain: Chain, api: dict, capsys: pytest.CaptureFixture
) -> None:
    """With the API down, an address is looked up directly."""
    api["error"] = OSError("down")
    _v2(chain)
    found, source = discovery.search(chain, TOKEN)
    assert source == "onchain"
    assert [f["token"] for f in found] == [TOKEN]
    assert "NOTICE: the Pons API is unavailable" in capsys.readouterr().err
    assert discovery.search(chain, TOKEN, quote="ETH") == ([], "onchain")
    assert not chain.log_queries


LAUNCHED = 30_000_000 - discovery.LOOKBACK_BLOCKS // 2


def _feeds(chain: Chain) -> None:
    """Script launches and a graduation across the factories' logs."""
    chain.feed_logs = {
        pons.TOPIC_V2_LAUNCHED: [(LAUNCHED, TOKEN), (29_999_990, OTHER)],
        discovery.TOPIC_V2_GRADUATED: [(27_000_000, TOKEN)],
        discovery.TOPIC_V1_LAUNCHED: [],
    }
    chain.names = {TOKEN: ("Pons", "PONS"), OTHER: ("Other", "PONSX")}
    _v2(chain)
    _v2(chain, token=OTHER)


def test_onchain_search_ranks_graduated_first_and_filters(
    chain: Chain, api: dict, capsys: pytest.CaptureFixture
) -> None:
    """Graduated tokens come first, then newest; quote and paging apply."""
    api["error"] = OSError("down")
    _feeds(chain)
    found, source = discovery.search(chain, "pons")
    assert source == "onchain"
    assert [f["token"] for f in found] == [TOKEN, OTHER]
    assert "covers every graduated V2 token" in capsys.readouterr().err
    index = json.loads(discovery.INDEX_FILE.read_text())
    assert index["tokens"][TOKEN] == {
        "factory": pons.V2_FACTORY,
        "block": LAUNCHED,
        "name": "Pons",
        "symbol": "PONS",
        "graduated": True,
    }
    assert index["ranges"]["v2-launched"] == [
        30_000_000 - discovery.LOOKBACK_BLOCKS,
        30_000_000,
    ]
    assert index["ranges"]["v2-graduated"] == [discovery.V2_DEPLOYED_BLOCK, 30_000_000]
    queries = len(chain.log_queries)
    assert [f["token"] for f in discovery.search(chain, "ponsx")[0]] == [OTHER]
    assert discovery.search(chain, "pons", page=2, limit=1)[0][0]["token"] == OTHER
    assert discovery.search(chain, "pons", quote="ETH")[0] == []
    assert len(chain.log_queries) == queries


def test_onchain_search_resumes_a_partial_index(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A spent budget leaves a partial index that the next run completes."""
    api["error"] = OSError("down")
    _feeds(chain)
    monkeypatch.setattr(discovery, "MAX_LOG_REQUESTS", 1)
    monkeypatch.setattr(discovery, "LOG_CHUNK", 100_000)
    assert [f["token"] for f in discovery.search(chain, "pons")[0]] == [OTHER]
    assert "still being built" in capsys.readouterr().err
    monkeypatch.setattr(discovery, "MAX_LOG_REQUESTS", 100)
    assert len(discovery.search(chain, "pons")[0]) == 2
    assert "still being built" not in capsys.readouterr().err


def test_onchain_search_fills_names_in_bounded_batches(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Names are read a batch at a time; undecodable ones are retried, not blanked."""
    api["error"] = OSError("down")
    _feeds(chain)
    chain.names = {TOKEN: ("bad", "bad")}
    monkeypatch.setattr(discovery, "METADATA_BATCH", 1)
    monkeypatch.setattr(discovery, "MAX_METADATA_BATCHES", 1)
    assert discovery.search(chain, "pons")[0] == []
    err = capsys.readouterr().err
    assert "still being built" in err
    assert f"NOTE: {TOKEN}'s name did not decode" in err
    index = json.loads(discovery.INDEX_FILE.read_text())
    assert index["tokens"][TOKEN]["name"] is None
    assert index["tokens"][TOKEN]["symbol"] is None
    chain.names = {TOKEN: ("Pons", "PONS")}
    assert [f["token"] for f in discovery.search(chain, "pons")[0]] == [TOKEN]
    assert len(discovery.search(chain, "")[0]) == 2
    stored = json.loads(discovery.INDEX_FILE.read_text())["tokens"][OTHER]
    assert (stored["name"], stored["symbol"]) == ("", "")


def test_onchain_search_skips_tokens_that_fail_verification(
    chain: Chain, api: dict, capsys: pytest.CaptureFixture
) -> None:
    """An indexed token the chain no longer backs is skipped, not fatal."""
    api["error"] = OSError("down")
    _feeds(chain)
    _v1(chain, token=OTHER, factory=9)
    assert [f["token"] for f in discovery.search(chain, "pons")[0]] == [TOKEN]
    assert f"skipped {OTHER}" in capsys.readouterr().err


def test_multicall_answering_short_is_refused(chain: Chain, api: dict) -> None:
    """A batch whose answers do not line up with its calls is not trusted."""
    api["error"] = OSError("down")
    _feeds(chain)
    chain.multicall_short = True
    with pytest.raises(evm.SwapError, match="Multicall3 answered"):
        discovery.search(chain, "pons")
    assert discovery.INDEX_FILE.exists()


def test_launches_that_left_the_window_are_forgotten(chain: Chain, api: dict) -> None:
    """Old ungraduated launches are pruned; graduated ones stay."""
    api["error"] = OSError("down")
    _feeds(chain)
    stale = to_checksum_address("0x" + "44" * 20)
    old = {"factory": pons.V2_FACTORY, "block": 1, "name": "Pons", "symbol": "PONS"}
    discovery.INDEX_FILE.write_text(
        json.dumps(
            {
                "ranges": {},
                "tokens": {
                    stale: {**old, "graduated": False},
                    OTHER: {**old, "graduated": True},
                },
            }
        )
    )
    discovery.search(chain, "pons")
    kept = json.loads(discovery.INDEX_FILE.read_text())["tokens"]
    assert stale not in kept
    assert kept[OTHER]["graduated"] is True


@pytest.mark.parametrize(
    "entry", [{"block": 1}, [pons.V2_FACTORY, 1, "Pons", "PONS", True]]
)
def test_a_corrupt_index_is_rebuilt(
    chain: Chain, api: dict, capsys: pytest.CaptureFixture, entry: t.Any
) -> None:
    """An index the skill cannot read, old shape included, is rebuilt and says so."""
    api["error"] = OSError("down")
    _feeds(chain)
    discovery.INDEX_FILE.write_text(
        json.dumps({"ranges": {}, "tokens": {TOKEN: entry}})
    )
    assert len(discovery.search(chain, "pons")[0]) == 2
    assert f"NOTE: {discovery.INDEX_FILE} is unreadable" in capsys.readouterr().err


def _rpc_error() -> Web3RPCError:
    """Build the RPC's answer to a log query matching too much."""
    return Web3RPCError("logs matched by query exceeds limit of 10000")


class _HTTPError(OSError):
    """An HTTP failure carrying its response, as web3's provider raises it."""

    def __init__(self, status: t.Optional[int]) -> None:
        """Carry a response with this status."""
        super().__init__(f"HTTP {status}")
        self.response = type("Response", (), {"status_code": status})()


def _throttled() -> _HTTPError:
    """Build an HTTP 429."""
    return _HTTPError(429)


def test_log_scan_halves_chunks_and_backs_off(
    chain: Chain, api: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Too-large answers shrink the chunk; throttling is waited out."""
    api["error"] = OSError("down")
    _feeds(chain)
    chain.log_errors = [_rpc_error(), _throttled(), _throttled()]
    monkeypatch.setattr(discovery, "LOOKBACK_BLOCKS", 3_000_000)
    assert len(discovery.search(chain, "pons")[0]) == 2
    spans = [q["toBlock"] - q["fromBlock"] + 1 for q in chain.log_queries[:4]]
    assert spans == [2_000_000, 1_000_000, 1_000_000, 1_000_000]


@pytest.mark.parametrize(
    ("errors", "match"),
    [
        ([_throttled()] * (discovery.RATE_LIMIT_RETRIES + 1), "keeps throttling"),
        ([_HTTPError(500)], "failed a log query"),
        ([ConnectionResetError("reset")], "failed a log query"),
        ([_rpc_error()] * 30, "refuses even"),
    ],
)
def test_log_scan_gives_up_with_a_reason(
    chain: Chain, api: dict, errors: list, match: str
) -> None:
    """A broken RPC is reported, never read as an empty market."""
    api["error"] = OSError("down")
    _feeds(chain)
    chain.log_errors = list(errors)
    with pytest.raises(evm.SwapError, match=match):
        discovery.search(chain, "pons")


def test_onchain_search_extends_the_index_forward(
    chain: Chain, api: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later head is scanned from the stored bound, chunked, with no gap or overlap."""
    api["error"] = OSError("down")
    _feeds(chain)
    discovery.search(chain, "pons")
    old = chain.head
    new_v2 = to_checksum_address("0x" + "55" * 20)
    new_v1 = to_checksum_address("0x" + "66" * 20)
    chain.feed_logs[pons.TOPIC_V2_LAUNCHED].append((old + 1, new_v2))
    chain.feed_logs[discovery.TOPIC_V1_LAUNCHED].append((old + 2_500, new_v1))
    chain.names.update({new_v2: ("Pons New", "PN"), new_v1: ("Pons V1", "PV1")})
    _v2(chain, token=new_v2)
    _v1(chain, token=new_v1)
    chain.head = chain.eth.block_number = old + 2_500
    monkeypatch.setattr(discovery, "LOG_CHUNK", 1_000)
    chain.log_queries.clear()
    found, _ = discovery.search(chain, "pons")
    assert [f["token"] for f in found] == [TOKEN, new_v1, new_v2, OTHER]
    spans = [(q["fromBlock"], q["toBlock"]) for q in chain.log_queries]
    step = [
        (old + 1, old + 1_000),
        (old + 1_001, old + 2_000),
        (old + 2_001, old + 2_500),
    ]
    assert spans == step * len(discovery.FEEDS)
    index = json.loads(discovery.INDEX_FILE.read_text())
    assert index["ranges"]["v2-launched"] == [
        old - discovery.LOOKBACK_BLOCKS,
        old + 2_500,
    ]
    assert index["ranges"]["v2-graduated"] == [discovery.V2_DEPLOYED_BLOCK, old + 2_500]
    assert index["tokens"][new_v2]["block"] == old + 1
    assert index["tokens"][new_v1]["block"] == old + 2_500


@pytest.mark.parametrize(
    ("page", "limit", "expected"),
    [(1, 1, [0]), (1, 2, [0, 1]), (2, 1, [1]), (2, 2, [2]), (1, 3, [0, 1, 2])],
)
def test_onchain_search_stops_reading_launches_at_the_limit(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    page: int,
    limit: int,
    expected: list[int],
) -> None:
    """Only the requested page is verified on-chain; later hits are never read."""
    api["error"] = OSError("down")
    _feeds(chain)
    third = to_checksum_address("0x" + "33" * 20)
    chain.feed_logs[pons.TOPIC_V2_LAUNCHED].append((29_999_995, third))
    chain.names[third] = ("Pons Three", "PONS3")
    _v2(chain, token=third)
    ranked = [TOKEN, third, OTHER]
    read: list[str] = []
    real = pons.launch_record

    def _spy(w3: t.Any, token: str) -> pons.Launch:
        """Record which tokens are verified."""
        read.append(token)
        return real(w3, token)

    monkeypatch.setattr(pons, "launch_record", _spy)
    found, _ = discovery.search(chain, "pons", page=page, limit=limit)
    assert [f["token"] for f in found] == [ranked[i] for i in expected]
    assert read == [ranked[i] for i in expected]
