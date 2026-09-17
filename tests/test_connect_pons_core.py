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

"""Unit tests for the connect-pons skill's launch records, API and audit gate."""

import http.client
import json
import sys
import typing as t

import pytest

from tests.conftest import (
    CURVE,
    Chain,
    DEPLOYER,
    OTHER,
    STATE_VIEW,
    TOKEN,
    V3_FACTORY,
    _item,
    _v1,
    _v2,
    _word,
    evm,
    pons,
    tokens,
    uniswap,
    web,
)


def test_v2_curve_launch_reads_every_field(chain: Chain) -> None:
    """A curve launch reports its curve, fee and pair, and no pool."""
    _v2(chain)
    launch = pons.launch_record(chain, TOKEN.lower())
    assert launch == {
        "token": TOKEN,
        "name": "Pons",
        "symbol": "PONS",
        "decimals": 18,
        "generation": "v2",
        "factory": pons.V2_FACTORY,
        "phase": 0,
        "venue": "curve",
        "pair_token": pons.USDG,
        "pair_symbol": "USDG",
        "pair_decimals": 6,
        "curve": CURVE,
        "pool": None,
        "fee_bps": 100,
        "creator_tax_bps": 100,
        "deployer": DEPLOYER,
        "buyback_enabled": True,
    }


def test_v2_graduated_native_launch_carries_its_hooked_pool(chain: Chain) -> None:
    """A graduated native launch trades on the MemeHook pool keyed with ETH."""
    _v2(chain, pair=evm.NATIVE, phase=pons.PHASE_POOL)
    pool_id = uniswap.v4_pool_id(evm.NATIVE, TOKEN, 0, 200, pons.MEME_HOOK)
    chain.on(STATE_VIEW, uniswap.SEL_GET_LIQUIDITY + pool_id, _word(123))
    launch = pons.launch_record(chain, TOKEN)
    assert launch["venue"] == "v4"
    assert launch["pair_symbol"] == "ETH"
    assert launch["pair_decimals"] == 18
    assert launch["fee_bps"] == 250
    assert launch["pool"] == {
        "version": "v4",
        "fee": 0,
        "tick_spacing": 200,
        "hooks": pons.MEME_HOOK,
        "pool_id": "0x" + pool_id.hex(),
        "liquidity": 123,
        "quote": "ETH",
        "quote_address": evm.NATIVE,
    }


def test_fee_policy_reads_the_frozen_terms_by_name(chain: Chain) -> None:
    """The factory's fee policy snapshot decodes into named fields."""
    _v2(chain)
    assert pons.fee_policy(chain, TOKEN) == pons.FeePolicy(
        protocolFeeRecipient=DEPLOYER.lower(),
        protocolFeeShareBps=3000,
        buybackBurnBps=5000,
        hookFeeBps=250,
        maxInternalPriceImpactBps=300,
    )


@pytest.mark.parametrize("phase", [pons.PHASE_SWEPT, pons.PHASE_RESCUED])
def test_v2_launch_without_a_venue(chain: Chain, phase: int) -> None:
    """Swept and rescued launches have nowhere to trade."""
    _v2(chain, phase=phase)
    launch = pons.launch_record(chain, TOKEN)
    assert (launch["venue"], launch["pool"], launch["phase"]) == ("none", None, phase)
    assert phase in pons.PHASE_REASONS


def test_accessors_name_the_missing_venue(chain: Chain) -> None:
    """A curve launch has a curve and no pool; asking for the pool says so."""
    _v2(chain)
    launch = pons.launch_record(chain, TOKEN)
    assert pons.curve_of(launch) == CURVE
    with pytest.raises(evm.SwapError, match=f"{TOKEN} has no Uniswap pool"):
        pons.pool_of(launch)
    launch["curve"] = None
    with pytest.raises(evm.SwapError, match=f"{TOKEN} has no bonding curve"):
        pons.curve_of(launch)


def test_v2_unknown_phase_is_refused(chain: Chain) -> None:
    """A phase this skill does not know is not guessed at."""
    _v2(chain, phase=7)
    with pytest.raises(evm.SwapError, match="unknown graduation phase 7"):
        pons.launch_record(chain, TOKEN)


@pytest.mark.parametrize("factory", [0, 1])
def test_v1_launch_trades_on_its_derived_v3_pool(chain: Chain, factory: int) -> None:
    """V1 launches, on either factory, route through the WETH 1% v3 pool."""
    _v1(chain, factory=factory)
    launch = pons.launch_record(chain, TOKEN)
    assert launch["generation"] == "v1"
    assert launch["factory"] == pons.V1_FACTORIES[factory]
    assert (launch["venue"], launch["phase"], launch["curve"]) == ("v3", 2, None)
    assert launch["pool"] == {
        "version": "v3",
        "fee": 10000,
        "address": uniswap.pool_address(4663, TOKEN, pons.WETH, 10000),
        "quote": "WETH",
        "quote_address": pons.WETH,
    }
    assert launch["buyback_enabled"] is None


def test_v1_pool_the_uniswap_factory_disagrees_with_is_refused(chain: Chain) -> None:
    """A derived pool the factory does not list is not traded."""
    _v1(chain)
    chain.on(V3_FACTORY, uniswap.SEL_GET_POOL, _word(0))
    with pytest.raises(evm.SwapError, match="Uniswap factory lists None"):
        pons.launch_record(chain, TOKEN)


def test_v1_launch_not_paired_with_weth_is_refused(chain: Chain) -> None:
    """Only WETH-paired V1 launches are understood."""
    _v1(chain, paired=pons.USDG)
    with pytest.raises(evm.SwapError, match="not WETH"):
        pons.launch_record(chain, TOKEN)


def test_unknown_token_is_refused(chain: Chain) -> None:
    """A token no factory launched is not a Pons token."""
    _v1(chain, factory=5)
    with pytest.raises(evm.SwapError, match="not launched by any Pons factory"):
        pons.launch_record(chain, TOKEN)


def test_non_address_is_refused(chain: Chain) -> None:
    """Garbage never reaches the chain."""
    with pytest.raises(evm.SwapError, match="not an address"):
        pons.launch_record(chain, "pons")


def test_short_record_is_refused(chain: Chain) -> None:
    """A factory answering something else is not read as a record."""
    chain.on(pons.V2_FACTORY, pons.SEL_GET_LAUNCHED, b"\x00" * 31)
    with pytest.raises(evm.SwapError, match="did not answer a launch record"):
        pons.launch_record(chain, TOKEN)


def test_unreadable_name_is_refused(chain: Chain) -> None:
    """A token whose name does not decode is refused, not blanked."""
    _v2(chain)
    chain.on(TOKEN, evm.SEL_NAME, b"\x01")
    with pytest.raises(evm.SwapError, match=f"{TOKEN} returned 1 bytes"):
        pons.launch_record(chain, TOKEN)


def test_api_search_asks_with_every_parameter(api: dict) -> None:
    """The search URL carries the query, sort, age, page and quote."""
    doc = pons.api_search(" pons ", "newest", 2, "USDG")
    assert doc["items"][0]["token"] == TOKEN
    assert api["urls"] == [
        f"{pons.API_BASE}/pons-launches/search?q=pons&sort=newest&age=all&page=2"
        "&quote=usdg"
    ]


def test_api_search_refuses_an_unknown_sort(api: dict) -> None:
    """A sort the API does not offer is a caller error, not an outage."""
    with pytest.raises(evm.SwapError, match="sort must be one of"):
        pons.api_search("pons", "hot")
    assert not api["urls"]


@pytest.mark.parametrize(
    ("setup", "match"),
    [
        ({"status": 204}, "HTTP 204"),
        ({"error": OSError("down")}, "unreachable"),
        ({"error": http.client.IncompleteRead(b"")}, "unreachable"),
        ({"search": b"<html>"}, "did not answer JSON"),
        ({"search": {"items": {}}}, "without an items list"),
        ({"search": {"page": "1", "pageSize": 24, "total": 1, "items": []}}, "'page'"),
        ({"search": {"page": 1, "pageSize": 24, "total": True, "items": []}}, "total"),
    ],
)
def test_api_search_reports_an_unusable_answer(
    api: dict, setup: dict, match: str
) -> None:
    """Every way the API can fail arrives as Unavailable."""
    api.update(setup)
    with pytest.raises(web.Unavailable, match=match):
        pons.api_search("pons")


@pytest.mark.parametrize(
    ("item", "match"),
    [
        ("token", "not an object"),
        (_item(token="0x1234"), "'token' is not an address"),  # nosec B106
        ({k: v for k, v in _item().items() if k != "name"}, "no usable 'name'"),
        (_item(symbol=5), "'symbol' is int"),
        (_item(priceUsd=True), "no usable 'priceUsd'"),
        (_item(blockNumber="1"), "'blockNumber' is str"),
        (_item(venue=3), "'venue' is int"),
        (_item(quoteAsset={"symbol": "USDG"}), "'quoteAsset' is malformed"),
    ],
)
def test_api_search_refuses_a_malformed_item(
    api: dict, item: t.Any, match: str
) -> None:
    """One malformed item means the API's shape is no longer understood."""
    api["search"] = {"page": 1, "pageSize": 24, "total": 1, "items": [item]}
    with pytest.raises(web.Unavailable, match=match):
        pons.api_search("pons")


def test_api_search_accepts_a_v1_item_without_version(api: dict) -> None:
    """V1 items omit version and venue; that is their normal shape."""
    item = _item(quoteAsset=None)
    del item["version"], item["venue"]
    api["search"]["items"] = [item]
    assert pons.api_search("pons")["items"] == [item]


@pytest.mark.parametrize(
    ("docs", "status"),
    [
        (b"<p>No audit has closed.</p>", "unaudited"),
        (b"<p>Treat&nbsp;v2 as   unaudited</p>", "unaudited"),
        (b"<p>All three audits have closed; see below.</p>", "audited"),
        (b"<p>Reports are now published.</p>", "audited"),
        (b"<p>Security reviews.</p>", "unknown"),
    ],
)
def test_audit_status_reads_the_live_docs(api: dict, docs: bytes, status: str) -> None:
    """The status follows the words on the page."""
    api["docs"] = docs
    result = pons.audit_status()
    assert result["status"] == status
    assert result["url"] == pons.DOCS_V2_URL
    assert result["detail"]


def test_audit_status_when_the_docs_are_down(api: dict) -> None:
    """An unreadable page is unknown and treated as unaudited."""
    api["error"] = OSError("down")
    result = pons.audit_status()
    assert result["status"] == "unknown"
    assert "treat v2 as unaudited" in result["detail"]


def test_v2_acknowledgement_round_trip(chain: Chain, api: dict) -> None:
    """Without an answer V2 is refused; with one it is allowed, with status."""
    del chain
    assert not pons.v2_acknowledged()
    with pytest.raises(evm.SwapError, match="acknowledge-v2"):
        pons.require_v2_ack()
    pons.record_v2_ack("  Yes, go ahead  ")
    stored = json.loads(pons.ACK_FILE.read_text())
    assert stored["answer"] == "Yes, go ahead"
    assert stored["audit"]["status"] == "unaudited"
    assert pons.v2_acknowledged()
    assert pons.require_v2_ack()["status"] == "unaudited"


@pytest.mark.parametrize("answer", ["", "   "])
def test_an_empty_answer_is_not_recorded(chain: Chain, answer: str) -> None:
    """An empty answer leaves V2 off."""
    del chain
    with pytest.raises(evm.SwapError, match="the answer is empty"):
        pons.record_v2_ack(answer)
    assert not pons.ACK_FILE.exists()


@pytest.mark.parametrize("content", ["{", "[]", '{"answer": ""}', '{"answer": 1}'])
def test_a_malformed_acknowledgement_does_not_count(
    chain: Chain, content: str, capsys: pytest.CaptureFixture
) -> None:
    """Only a readable, non-empty answer counts; anything else is named."""
    del chain
    pons.ACK_FILE.write_text(content)
    assert not pons.v2_acknowledged()
    assert f"NOTE: {pons.ACK_FILE} is unreadable" in capsys.readouterr().err


def test_a_missing_acknowledgement_is_silent(
    chain: Chain, capsys: pytest.CaptureFixture
) -> None:
    """No acknowledgement file is the normal state, not a problem to report."""
    del chain
    assert not pons.v2_acknowledged()
    assert capsys.readouterr().err == ""


def _run(monkeypatch: pytest.MonkeyPatch, chain: Chain, *argv: str) -> int:
    """Run tokens.py against the scripted chain."""
    monkeypatch.setattr(evm, "read_web3", lambda chain_, rpc: chain)
    monkeypatch.setattr(sys, "argv", ["tokens.py", *argv])
    return tokens.main()


def test_cli_search_prints_verified_results(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Search prints the source and the verified launches."""
    del api
    _v2(chain)
    assert _run(monkeypatch, chain, "search", "--query", "pons", "--quote", "USDG") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["source"] == "api"
    assert doc["results"][0]["token"] == TOKEN


def _curve_reads(chain: Chain) -> None:
    """Script a live curve."""
    chain.on(CURVE, evm.selector("getReserves()"), _word(3236 * 10**6) + _word(10**27))
    chain.on(CURVE, evm.selector("sellableTokens()"), _word(7 * 10**26))
    chain.on(CURVE, evm.selector("creatorTaxBps()"), _word(100))
    chain.on(CURVE, evm.selector("currentSnipeTaxBps(address)"), _word(0))
    chain.on(CURVE, evm.selector("readyToGraduate()"), _word(0))
    chain.on(CURVE, tokens.SEL_THRESHOLD, _word(8090 * 10**6))
    chain.on(CURVE, tokens.SEL_REAL_QUOTE, _word(809 * 10**6))


def test_cli_show_reports_curve_progress_audit_and_market(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Show combines the record, the curve, the audit and the market."""
    del api
    _v2(chain)
    _curve_reads(chain)
    assert _run(monkeypatch, chain, "show", "--token", TOKEN) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["curve_state"]["graduation_progress_pct"] == pytest.approx(10.0)
    assert doc["curve_state"]["raised"] == 809
    assert doc["audit"]["status"] == "unaudited"
    assert doc["v2_acknowledged"] is False
    assert doc["market"]["price_usd"] == 1e-6


def test_cli_show_without_a_venue_or_api(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """A swept launch says why it cannot trade; a dead API only loses market data."""
    _v2(chain, phase=pons.PHASE_SWEPT)
    api["error"] = OSError("down")
    assert _run(monkeypatch, chain, "show", "--token", TOKEN) == 0
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["not_tradable"] == pons.PHASE_REASONS[pons.PHASE_SWEPT]
    assert "market" not in doc
    assert "no market data" in captured.err


def test_cli_show_v1_has_no_audit_gate(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """V1 output carries no V2 audit readout; unmatched API items are ignored."""
    api["search"]["items"] = [_item(token=OTHER)]
    _v1(chain)
    assert _run(monkeypatch, chain, "show", "--token", TOKEN) == 0
    doc = json.loads(capsys.readouterr().out)
    assert "audit" not in doc
    assert "market" not in doc


def test_cli_audit_and_acknowledge(
    chain: Chain,
    api: dict,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Audit reports the answer's state; acknowledge-v2 records it."""
    del api
    assert _run(monkeypatch, chain, "audit") == 0
    assert json.loads(capsys.readouterr().out)["v2_acknowledged"] is False
    assert _run(monkeypatch, chain, "acknowledge-v2", "--answer", "yes") == 0
    assert json.loads(capsys.readouterr().out)["recorded"] is True
    assert _run(monkeypatch, chain, "audit") == 0
    assert json.loads(capsys.readouterr().out)["v2_acknowledged"] is True


def test_cli_refusals_exit_non_zero(
    chain: Chain, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A refusal is printed and exits 1."""
    assert _run(monkeypatch, chain, "acknowledge-v2", "--answer", " ") == 1
    assert "refused:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv", [("search", "--page", "0"), ("search", "--limit", "25")]
)
def test_cli_rejects_bad_paging(
    chain: Chain, monkeypatch: pytest.MonkeyPatch, argv: tuple
) -> None:
    """Paging outside the API's bounds is a usage error."""
    with pytest.raises(SystemExit):
        _run(monkeypatch, chain, *argv)
