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

"""Everything specific to Pons: factories, launch records, its API, audit gate."""

import json
import re
import typing as t
import urllib.parse
from pathlib import Path

import evm
import state
import uniswap
import web
from eth_utils import is_address, keccak, to_checksum_address
from web3 import Web3

CHAIN = "robinhood"
CHAIN_ID = 4663
PUBLIC_RPC = "https://rpc.mainnet.chain.robinhood.com"
USER_AGENT = "connect-pons/0.1"
HTTP_TIMEOUT_S = 15

WETH = to_checksum_address("0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73")
USDG = to_checksum_address("0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168")
V1_FACTORIES = (
    to_checksum_address("0xA5aAb3F0c6EeadF30Ef1D3Eb997108E976351feB"),
    to_checksum_address("0x0c37a24F5D23A486FA692d1500881d698B1F77a4"),
)
V2_FACTORY = to_checksum_address("0x7eD598BcEf8bd9Edd8C97A195C6d13f40801EC7e")
MEME_HOOK = to_checksum_address("0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044")
FEE_ESCROW = to_checksum_address("0xd3AFEB2a57f70eF218Aa82451c51B2fb0416Ac9e")
LAUNCH_ROUTER = to_checksum_address("0xe33E9E479dF8802cb0866d5d05258bEc4cF62948")
DOCS_V2_URL = "https://docs.ponsfamily.com/v2"
API_BASE = "https://www.ponsfamily.com/api"

Phase = t.Literal[0, 1, 2, 3]
PHASE_CURVE: Phase = 0
PHASE_SWEPT: Phase = 1
PHASE_POOL: Phase = 2
PHASE_RESCUED: Phase = 3
PHASE_REASONS = {
    PHASE_SWEPT: "graduating: its curve is closed and its v4 pool is not seeded yet",
    PHASE_RESCUED: "rescued: graduation failed and its reserves were released",
}
OPTIONAL_ITEM_FIELDS: dict[str, tuple[type, ...]] = {
    "blockNumber": (int,),
    "graduated": (bool,),
    **dict.fromkeys(
        ("logo", "description", "launchedAt", "version", "venue"), (str, type(None))
    ),
    **dict.fromkeys(
        ("priceUsd", "marketCapUsd", "liquidityUsd", "graduationProgressPct"),
        (int, float, type(None)),
    ),
}
SORTS = ("relevance", "marketCap", "volume", "newest", "oldest")


class V2Record(t.NamedTuple):
    """The V2 factory's LaunchedToken, as getLaunchedToken returns it."""

    token: t.Annotated[str, "address"]
    curve: t.Annotated[str, "address"]
    deployer: t.Annotated[str, "address"]
    creatorFeeRecipient: t.Annotated[str, "address"]
    pairToken: t.Annotated[str, "address"]
    graduationThreshold: t.Annotated[int, "uint256"]
    poolFee: t.Annotated[int, "uint24"]
    tickSpacing: t.Annotated[int, "int24"]
    creatorTaxBps: t.Annotated[int, "uint16"]
    buybackEnabled: t.Annotated[bool, "bool"]
    phase: t.Annotated[int, "uint8"]
    sweptQuote: t.Annotated[int, "uint256"]
    sweptTokens: t.Annotated[int, "uint256"]
    sweptAt: t.Annotated[int, "uint256"]
    exists: t.Annotated[bool, "bool"]


class FeePolicy(t.NamedTuple):
    """The fee policy the V2 factory froze for a launch."""

    protocolFeeRecipient: t.Annotated[str, "address"]
    protocolFeeShareBps: t.Annotated[int, "uint16"]
    buybackBurnBps: t.Annotated[int, "uint16"]
    hookFeeBps: t.Annotated[int, "uint16"]
    maxInternalPriceImpactBps: t.Annotated[int, "uint16"]


class V1Record(t.NamedTuple):
    """A V1 factory's LaunchedToken, as getLaunchedToken returns it."""

    token: t.Annotated[str, "address"]
    deployer: t.Annotated[str, "address"]
    pairedToken: t.Annotated[str, "address"]
    positionManager: t.Annotated[str, "address"]
    positionId: t.Annotated[int, "uint256"]
    dexId: t.Annotated[int, "uint256"]
    launchConfigId: t.Annotated[int, "uint256"]
    restrictionsEndBlock: t.Annotated[int, "uint256"]
    supply: t.Annotated[int, "uint256"]
    isToken0: t.Annotated[bool, "bool"]
    poolFee: t.Annotated[int, "uint24"]
    exists: t.Annotated[bool, "bool"]
    initialBuyAmount: t.Annotated[int, "uint256"]


V2_RECORD = evm.abi_tuple(V2Record)
V1_RECORD = evm.abi_tuple(V1Record)
FEE_POLICY = evm.abi_tuple(FeePolicy)
_RECORD_TYPES: dict[type, str] = {V2Record: V2_RECORD, V1Record: V1_RECORD}
RecordT = t.TypeVar("RecordT", V2Record, V1Record)
SEL_GET_LAUNCHED = evm.selector("getLaunchedToken(address)")
SEL_FEE_BPS = evm.selector("feeBps()")
SEL_FEE_POLICY = evm.selector("getLaunchFeePolicy(address)")
TOPIC_V2_LAUNCHED = keccak(
    text="TokenLaunched(address,address,address,address,uint256,uint256)"
)

ACK_FILE = Path("pons.audit.json")
UNAUDITED_MARKERS = ("no audit has closed", "treat v2 as unaudited")
AUDITED_PATTERN = re.compile(
    r"audits? (?:have|has) (?:closed|completed|concluded)"
    r"|reports? (?:are|is) now published"
)


Generation = t.Literal["v1", "v2"]
Venue = t.Literal["curve", "v4", "v3", "none"]


class Launch(t.TypedDict):
    """One Pons launch as the chain describes it, with where it trades now."""

    token: str
    name: str
    symbol: str
    decimals: int
    generation: Generation
    factory: str
    phase: Phase
    venue: Venue
    pair_token: str
    pair_symbol: str
    pair_decimals: int
    curve: t.Optional[str]
    pool: t.Optional[uniswap.Pool]
    fee_bps: int
    creator_tax_bps: int
    deployer: str
    buyback_enabled: t.Optional[bool]


def curve_of(launch: Launch) -> str:
    """Return the launch's bonding curve address.

    Raises:
        SwapError: when the launch has no curve.
    """
    address = launch["curve"]
    if address is None:
        raise evm.SwapError(f"{launch['token']} has no bonding curve")
    return address


def pool_of(launch: Launch) -> uniswap.Pool:
    """Return the launch's Uniswap pool.

    Raises:
        SwapError: when the launch has no pool.
    """
    pool = launch["pool"]
    if pool is None:
        raise evm.SwapError(f"{launch['token']} has no Uniswap pool")
    return pool


def snipe_tax_payer(buyer: str) -> str:
    """Name whose snipe tax a reading is; a read for address(0) is an estimate."""
    if evm.is_native(buyer):
        return "an estimate for a buyer the launch does not exempt"
    return buyer


def _record(w3: Web3, factory: str, token: str, shape: type[RecordT]) -> RecordT:
    """Read a factory's getLaunchedToken record for this token.

    Raises:
        SwapError: when the factory answers something that is not the record.
    """
    data = evm.encode_call(SEL_GET_LAUNCHED, ["address"], [token])
    try:
        fields = evm.call_types(w3, factory, data, [_RECORD_TYPES[shape]])[0]
    except evm.SwapError as exc:
        raise evm.SwapError(
            f"{factory} did not answer a launch record for {token} ({exc})"
        ) from exc
    return shape(*fields)


def fee_policy(w3: Web3, token: str) -> FeePolicy:
    """Read the fee policy the V2 factory froze for a launch."""
    data = evm.encode_call(SEL_FEE_POLICY, ["address"], [token])
    return FeePolicy(*evm.call_types(w3, V2_FACTORY, data, [FEE_POLICY])[0])


def _v2_launch(w3: Web3, token: str, record: V2Record) -> Launch:
    """Build a V2 launch from its factory record."""
    curve, phase = record.curve, t.cast(Phase, record.phase)
    pool_fee, tick_spacing = record.poolFee, record.tickSpacing
    pair = to_checksum_address(record.pairToken)
    pair_symbol, pair_decimals = evm.asset_info(w3, pair)
    name, symbol, decimals = evm.token_identity(w3, token)
    venue: Venue = "none"
    pool: t.Optional[uniswap.Pool] = None
    fee_bps = 0
    if phase == PHASE_CURVE:
        venue = "curve"
        fee_bps = evm.call_int(w3, curve, SEL_FEE_BPS)
    elif phase == PHASE_POOL:
        venue = "v4"
        fee_bps = fee_policy(w3, token).hookFeeBps
        pool_id = uniswap.v4_pool_id(pair, token, pool_fee, tick_spacing, MEME_HOOK)
        state_view = uniswap.deployment(CHAIN_ID)["v4_state_view"]
        v4: uniswap.PoolV4 = {
            "version": "v4",
            "fee": pool_fee,
            "tick_spacing": tick_spacing,
            "hooks": MEME_HOOK,
            "pool_id": "0x" + pool_id.hex(),
            "liquidity": evm.call_int(
                w3, state_view, uniswap.SEL_GET_LIQUIDITY + pool_id
            ),
            "quote": pair_symbol,
            "quote_address": pair,
        }
        pool = v4
    elif phase not in PHASE_REASONS:
        raise evm.SwapError(f"{token} reports unknown graduation phase {phase}")
    return {
        "token": token,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "generation": "v2",
        "factory": V2_FACTORY,
        "phase": phase,
        "venue": venue,
        "pair_token": pair,
        "pair_symbol": pair_symbol,
        "pair_decimals": pair_decimals,
        "curve": to_checksum_address(curve),
        "pool": pool,
        "fee_bps": fee_bps,
        "creator_tax_bps": record.creatorTaxBps,
        "deployer": to_checksum_address(record.deployer),
        "buyback_enabled": record.buybackEnabled,
    }


def _v1_launch(w3: Web3, token: str, factory: str, record: V1Record) -> Launch:
    """Build a V1 launch from its factory record, its v3 pool checked on-chain.

    Raises:
        SwapError: when it is not paired with WETH, or the Uniswap factory
            does not know the pool its record implies.
    """
    paired, pool_fee = to_checksum_address(record.pairedToken), record.poolFee
    if paired != WETH:
        raise evm.SwapError(f"{token} is a V1 launch paired with {paired}, not WETH")
    derived = uniswap.pool_address(CHAIN_ID, token, WETH, pool_fee)
    lookup = evm.encode_call(
        uniswap.SEL_GET_POOL, ["address", "address", "uint24"], [token, WETH, pool_fee]
    )
    listed = evm.call_address(w3, uniswap.deployment(CHAIN_ID)["v3_factory"], lookup)
    if listed != derived:
        raise evm.SwapError(
            f"{token}'s v3 pool should be {derived}, but the Uniswap factory "
            f"lists {listed}; refusing to guess where it trades"
        )
    name, symbol, decimals = evm.token_identity(w3, token)
    pool: uniswap.PoolV3 = {
        "version": "v3",
        "fee": pool_fee,
        "address": derived,
        "quote": "WETH",
        "quote_address": WETH,
    }
    return {
        "token": token,
        "name": name,
        "symbol": symbol,
        "decimals": decimals,
        "generation": "v1",
        "factory": factory,
        "phase": PHASE_POOL,
        "venue": "v3",
        "pair_token": WETH,
        "pair_symbol": "WETH",
        "pair_decimals": evm.token_decimals(w3, WETH),
        "curve": None,
        "pool": pool,
        "fee_bps": 0,
        "creator_tax_bps": 0,
        "deployer": to_checksum_address(record.deployer),
        "buyback_enabled": None,
    }


def v2_record(w3: Web3, token: str) -> V2Record:
    """Read the V2 factory's launch record for a token."""
    return _record(w3, V2_FACTORY, token, V2Record)


def launch_record(w3: Web3, token: str) -> Launch:
    """Read the launch behind a token from the Pons factories alone.

    Raises:
        SwapError: when no Pons factory launched this token.
    """
    if not is_address(token):
        raise evm.SwapError(f"{token!r} is not an address")
    token = to_checksum_address(token)
    v2 = v2_record(w3, token)
    if v2.exists:
        return _v2_launch(w3, token, v2)
    for factory in V1_FACTORIES:
        v1 = _record(w3, factory, token, V1Record)
        if v1.exists:
            return _v1_launch(w3, token, factory, v1)
    raise evm.SwapError(f"{token} was not launched by any Pons factory")


def _check_item(item: t.Any) -> None:
    """Refuse a search item whose shape this skill does not recognise.

    Raises:
        Unavailable: on the first field that is missing or mistyped.
    """
    if not isinstance(item, dict):
        raise web.Unavailable("search item is not an object")
    for field in ("factory", "token", "pairToken", "deployer"):
        web.check_json_type(item, field, (str,), web.Unavailable, "search item")
        if not is_address(item[field]):
            raise web.Unavailable(f"search item {field!r} is not an address")
    for field in ("name", "symbol"):
        web.check_json_type(item, field, (str,), web.Unavailable, "search item")
    for field, kinds in OPTIONAL_ITEM_FIELDS.items():
        if field in item:
            web.check_json_type(item, field, kinds, web.Unavailable, "search item")
    quote = item.get("quoteAsset")
    if quote is not None and not (
        isinstance(quote, dict)
        and isinstance(quote.get("symbol"), str)
        and isinstance(quote.get("address"), str)
    ):
        raise web.Unavailable("search item 'quoteAsset' is malformed")


def api_search(
    query: str,
    sort: str = "marketCap",
    page: int = 1,
    quote: t.Optional[str] = None,
) -> dict[str, t.Any]:
    """One page of Pons's own search, every item's shape checked.

    Raises:
        SwapError: for a sort the API does not offer.
        Unavailable: when the API cannot be read or its shape changed.
    """
    if sort not in SORTS:
        raise evm.SwapError(f"sort must be one of {', '.join(SORTS)}")
    params = {"q": query.strip(), "sort": sort, "age": "all", "page": str(page)}
    if quote:
        params["quote"] = quote.strip().lower()
    url = f"{API_BASE}/pons-launches/search?{urllib.parse.urlencode(params)}"
    try:
        doc = json.loads(web.get(url, USER_AGENT, HTTP_TIMEOUT_S))
    except ValueError as exc:
        raise web.Unavailable(f"{url} did not answer JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("items"), list):
        raise web.Unavailable(f"{url} answered without an items list")
    for field in ("page", "pageSize", "total"):
        web.check_json_type(doc, field, (int,), web.Unavailable, "search item")
    for item in doc["items"]:
        _check_item(item)
    return doc


def market_readout(item: dict[str, t.Any]) -> dict[str, t.Any]:
    """Return the API's market readout for a launch, labelled as unverified."""
    return {
        "source": "pons api (unverified)",
        "price_usd": item.get("priceUsd"),
        "market_cap_usd": item.get("marketCapUsd"),
        "liquidity_usd": item.get("liquidityUsd"),
        "graduation_progress_pct": item.get("graduationProgressPct"),
        "launched_at": item.get("launchedAt"),
        "logo": item.get("logo"),
        "description": item.get("description"),
    }


def audit_status() -> dict[str, str]:
    """Pons v2's audit status as its live docs state it right now."""
    status = {"status": "unknown", "url": DOCS_V2_URL}
    try:
        text = web.page_text(DOCS_V2_URL, USER_AGENT, HTTP_TIMEOUT_S)
    except web.Unavailable as exc:
        return {
            **status,
            "detail": f"could not read the docs ({exc}); treat v2 as unaudited",
        }
    for marker in UNAUDITED_MARKERS:
        if marker in text:
            return {
                **status,
                "status": "unaudited",
                "detail": "the docs say: no audit has closed; treat v2 as unaudited "
                "until the reports are published",
            }
    found = AUDITED_PATTERN.search(text)
    if found:
        excerpt = text[max(0, found.start() - 80) : found.end() + 120]
        return {
            **status,
            "status": "audited",
            "detail": f"the docs say: ...{excerpt}...",
        }
    return {
        **status,
        "detail": "the docs no longer state the audit status in words this skill "
        "recognises; read the page and treat v2 as unaudited meanwhile",
    }


def v2_acknowledged() -> bool:
    """Whether the operator has accepted the V2 audit risk in this workspace."""
    return state.read_answer(ACK_FILE, "treating V2 as not acknowledged") is not None


def record_v2_ack(answer: str) -> None:
    """Record the operator's acceptance of trading and launching on V2.

    Raises:
        SwapError: when the answer is empty.
    """
    state.record_answer(ACK_FILE, answer, audit=audit_status)


def require_v2_ack() -> dict[str, str]:
    """Return the live audit status, once the operator has accepted V2's risk.

    Raises:
        SwapError: when no acknowledgement is recorded.
    """
    status = audit_status()
    if not v2_acknowledged():
        raise evm.SwapError(
            f"Pons v2 audit status: {status['status']} ({status['detail']}; "
            f"{status['url']}). Ask the operator once whether they accept trading "
            f"and launching on these contracts; only if they agree, run "
            f'`tokens.py acknowledge-v2 --answer "<their words>"` and retry'
        )
    return status


__all__ = [
    "ACK_FILE",
    "API_BASE",
    "CHAIN",
    "CHAIN_ID",
    "DOCS_V2_URL",
    "FEE_ESCROW",
    "FEE_POLICY",
    "FeePolicy",
    "Generation",
    "LAUNCH_ROUTER",
    "Launch",
    "MEME_HOOK",
    "PHASE_REASONS",
    "Phase",
    "PUBLIC_RPC",
    "SEL_FEE_BPS",
    "SEL_FEE_POLICY",
    "SEL_GET_LAUNCHED",
    "SORTS",
    "TOPIC_V2_LAUNCHED",
    "USDG",
    "V1Record",
    "V1_FACTORIES",
    "V1_RECORD",
    "V2Record",
    "V2_FACTORY",
    "V2_RECORD",
    "Venue",
    "WETH",
    "api_search",
    "audit_status",
    "curve_of",
    "fee_policy",
    "launch_record",
    "market_readout",
    "pool_of",
    "record_v2_ack",
    "require_v2_ack",
    "snipe_tax_payer",
    "v2_acknowledged",
    "v2_record",
]
