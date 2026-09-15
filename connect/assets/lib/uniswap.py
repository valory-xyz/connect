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

"""Uniswap v2/v3/v4 on the chains in DEPLOYMENTS: discovery, quoting, calldata.

Every router input carries an undocumented ``uint256[] minHopPriceX36``; omit
it and the router reverts with SliceOutOfBounds().
"""

import typing as t

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from evm import SwapError, call_address, call_int, check_fields, selector
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput, ContractLogicError


class Deployment(t.TypedDict, total=False):
    """Uniswap addresses on one chain; a missing key means that piece is absent."""

    v2_factory: str
    v3_factory: str
    quoter_v2: str
    v4_state_view: str
    v4_quoter: str
    universal_router: str
    permit2: str


DEPLOYMENTS: dict[int, Deployment] = {
    4663: {
        "v2_factory": "0x8bcEaA40B9AcdfAedF85AdF4FF01F5Ad6517937f",
        "v3_factory": "0x1f7d7550B1b028f7571E69A784071F0205FD2EfA",
        "quoter_v2": "0x33e885eD0Ec9bF04EcfB19341582aADCb4c8A9E7",
        "v4_state_view": "0xF3334192D15450CdD385c8B70e03f9A6bD9E673b",
        "v4_quoter": "0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94",
        "universal_router": "0x8876789976dEcBfCbBbe364623C63652db8C0904",
        "permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    },
    137: {
        "v2_factory": "0x9e5A52f57b3038F1B8EeE45F28b3C1967e22799C",
        "v3_factory": "0x1F98431c8aD98523631AE4a59f267346ea31F984",
        "quoter_v2": "0x61fFE014bA17989E743c5F6cB21bF9697530B21e",
        "v4_state_view": "0x5eA1bD7974c8A611cBAB0bDCAFcB1D9CC9b3BA5a",
        "v4_quoter": "0xb3d5c3Dfc3a7aEbFF71895A7191796BFFc2c81b9",
        "universal_router": "0x1095692A6237d83C6a72F3F5eFEdb9A670C49223",
        "permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    },
    100: {
        "v3_factory": "0xe32F7dD7e3f098D518ff19A22d5f028e076489B1",
        "quoter_v2": "0x7E9cB3499A6cee3baBe5c8a3D328EA7FD36578f4",
        "universal_router": "0x75FC67473A91335B5b8F8821277262a13B38c9b3",
        "permit2": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    },
}

NO_HOOKS = to_checksum_address("0x" + "00" * 20)
V3_FEES = (100, 500, 3000, 10000)
V4_TIERS = ((100, 1), (500, 10), (3000, 60), (10000, 200))
V2_FEE = 3000
V2_FEE_NUMERATOR = 997
V2_FEE_DENOMINATOR = 1000

COMMAND_PERMIT2_PERMIT = 0x0A
COMMAND_V3_SWAP_EXACT_IN = 0x00
COMMAND_V2_SWAP_EXACT_IN = 0x08
COMMAND_V4_SWAP = 0x10
SWAP_COMMANDS = {
    "v2": COMMAND_V2_SWAP_EXACT_IN,
    "v3": COMMAND_V3_SWAP_EXACT_IN,
    "v4": COMMAND_V4_SWAP,
}
ACTION_SWAP_EXACT_IN = 0x07
ACTION_SETTLE = 0x0B
ACTION_TAKE = 0x0E
OPEN_DELTA = 0
PAYER_IS_USER = True
NO_HOP_PRICE_LIMIT = [0]
V4_EXACT_INPUT_PARAMS = (
    "(address,(address,uint24,int24,address,bytes)[],uint256[],uint128,uint128)"
)

SEL_GET_PAIR = selector("getPair(address,address)")
SEL_GET_POOL = selector("getPool(address,address,uint24)")
SEL_GET_LIQUIDITY = selector("getLiquidity(bytes32)")
SEL_GET_RESERVES = selector("getReserves()")
SEL_TOKEN0 = selector("token0()")
SEL_UR_EXECUTE = selector("execute(bytes,bytes[],uint256)")
SEL_QUOTE_V3 = selector(
    "quoteExactInputSingle((address,address,uint256,uint24,uint160))"
)
SEL_QUOTE_V4 = selector(
    "quoteExactInputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))"
)


class _PoolBase(t.TypedDict, total=False):
    """Fields discovery annotates onto any pool after it is found."""

    quote_depth: float
    quote: str
    quote_address: str


class PoolV2(_PoolBase):
    """A v2 pair."""

    version: t.Literal["v2"]
    fee: int
    address: str


class PoolV3(_PoolBase):
    """A v3 pool at one fee tier."""

    version: t.Literal["v3"]
    fee: int
    address: str


class PoolV4(_PoolBase):
    """A v4 pool, whose funds sit in the PoolManager singleton."""

    version: t.Literal["v4"]
    fee: int
    tick_spacing: int
    hooks: str
    pool_id: str
    liquidity: int


Pool = t.Union[PoolV2, PoolV3, PoolV4]


def deployment(chain_id: int) -> Deployment:
    """Contract addresses for a chain; a missing key means that piece is absent.

    Raises:
        SwapError: when the chain has no entry at all.
    """
    if chain_id not in DEPLOYMENTS:
        raise SwapError(f"no Uniswap deployment recorded for chain {chain_id}")
    return DEPLOYMENTS[chain_id]


def v4_pool_id(token_a: str, token_b: str, fee: int, spacing: int, hooks: str) -> bytes:
    """Pool id for a v4 PoolKey, whose currencies are sorted by address."""
    currency0, currency1 = sorted((token_a, token_b), key=lambda a: int(a, 16))
    return keccak(
        abi_encode(
            ["address", "address", "uint24", "int24", "address"],
            [currency0, currency1, fee, spacing, hooks],
        )
    )


def _v2_candidate(
    w3: Web3, chain_id: int, token: str, quote: str
) -> t.Optional[PoolV2]:
    """Find the v2 pair for a token/quote couple, when the factory has one."""
    factory = deployment(chain_id).get("v2_factory")
    if factory is None:
        return None
    data = SEL_GET_PAIR + abi_encode(["address", "address"], [token, quote])
    address = call_address(w3, factory, data)
    if address is None:
        return None
    pair: PoolV2 = {"version": "v2", "fee": V2_FEE, "address": address}
    return pair


def _v3_candidates(w3: Web3, chain_id: int, token: str, quote: str) -> list[PoolV3]:
    """Every v3 fee tier with a deployed pool for this couple."""
    factory = deployment(chain_id).get("v3_factory")
    if factory is None:
        return []
    found = []
    for fee in V3_FEES:
        data = SEL_GET_POOL + abi_encode(
            ["address", "address", "uint24"], [token, quote, fee]
        )
        address = call_address(w3, factory, data)
        if address is not None:
            pool: PoolV3 = {"version": "v3", "fee": fee, "address": address}
            found.append(pool)
    return found


def _v4_candidates(w3: Web3, chain_id: int, token: str, quote: str) -> list[PoolV4]:
    """Hook-less v4 pools at the standard tiers, with in-range liquidity."""
    state_view = deployment(chain_id).get("v4_state_view")
    if state_view is None:
        return []
    found = []
    for fee, spacing in V4_TIERS:
        pool_id = v4_pool_id(token, quote, fee, spacing, NO_HOOKS)
        liquidity = call_int(w3, state_view, SEL_GET_LIQUIDITY + pool_id)
        if liquidity:
            pool: PoolV4 = {
                "version": "v4",
                "fee": fee,
                "tick_spacing": spacing,
                "hooks": NO_HOOKS,
                "pool_id": "0x" + pool_id.hex(),
                "liquidity": liquidity,
            }
            found.append(pool)
    return found


def discover(w3: Web3, chain_id: int, token: str, quote: str) -> list[Pool]:
    """Every candidate pool for a token against one quote asset, v2/v3 then v4."""
    pairs: list[Pool] = []
    pair = _v2_candidate(w3, chain_id, token, quote)
    if pair is not None:
        pairs.append(pair)
    pairs.extend(_v3_candidates(w3, chain_id, token, quote))
    pairs.extend(_v4_candidates(w3, chain_id, token, quote))
    return pairs


def _quote_v3(  # pylint: disable=too-many-positional-arguments
    w3: Web3, chain_id: int, pool: PoolV3, token_in: str, token_out: str, amount: int
) -> int:
    """Output of a v3 pool for this size, read from the deployed QuoterV2."""
    data = SEL_QUOTE_V3 + abi_encode(
        ["(address,address,uint256,uint24,uint160)"],
        [(token_in, token_out, amount, int(pool["fee"]), 0)],
    )
    quoter = deployment(chain_id).get("quoter_v2")
    if quoter is None:
        raise SwapError(
            f"chain {chain_id} has no quoter_v2 recorded; cannot price v3 pools"
        )
    return call_int(w3, quoter, data)


def _quote_v4(  # pylint: disable=too-many-positional-arguments
    w3: Web3, chain_id: int, pool: PoolV4, token_in: str, token_out: str, amount: int
) -> int:
    """Output of a v4 pool for this size, read from the deployed V4Quoter."""
    currency0, currency1 = sorted((token_in, token_out), key=lambda a: int(a, 16))
    pool_key = (
        currency0,
        currency1,
        int(pool["fee"]),
        int(pool["tick_spacing"]),
        pool["hooks"],
    )
    data = SEL_QUOTE_V4 + abi_encode(
        ["((address,address,uint24,int24,address),bool,uint128,bytes)"],
        [(pool_key, token_in == currency0, amount, b"")],
    )
    quoter = deployment(chain_id).get("v4_quoter")
    if quoter is None:
        raise SwapError(
            f"chain {chain_id} has no v4_quoter recorded; cannot price v4 pools"
        )
    return call_int(w3, quoter, data)


def _quote_v2(
    w3: Web3, pool: PoolV2, token_in: str, token_out: str, amount: int
) -> int:
    """Output of a v2 pair, computed locally from its reserves."""
    raw = bytes(w3.eth.call({"to": pool["address"], "data": SEL_GET_RESERVES}))
    if len(raw) < 64:
        raise SwapError(f"{pool['address']} returned {len(raw)} bytes of reserves")
    reserve0 = int.from_bytes(raw[0:32], "big")
    reserve1 = int.from_bytes(raw[32:64], "big")
    token0_raw = bytes(w3.eth.call({"to": pool["address"], "data": SEL_TOKEN0}))
    if len(token0_raw) < 32:
        raise SwapError(f"{pool['address']} did not answer token0()")
    token0 = to_checksum_address("0x" + token0_raw[-20:].hex())
    if token0 not in (to_checksum_address(token_in), to_checksum_address(token_out)):
        raise SwapError(
            f"{pool['address']} holds {token0}, which is neither side of this "
            f"trade; refusing to guess the reserve orientation"
        )
    reserve_in, reserve_out = (
        (reserve0, reserve1)
        if token0 == to_checksum_address(token_in)
        else (reserve1, reserve0)
    )
    if not reserve_in or not reserve_out:
        return 0
    amount_with_fee = amount * V2_FEE_NUMERATOR
    return (amount_with_fee * reserve_out) // (
        reserve_in * V2_FEE_DENOMINATOR + amount_with_fee
    )


def quote_pool(  # pylint: disable=too-many-positional-arguments
    w3: Web3, chain_id: int, pool: Pool, token_in: str, token_out: str, amount: int
) -> int:
    """Output this one pool would give, or zero when it reverts.

    Raises:
        Exception: anything that is not a revert, so a degraded RPC cannot
            masquerade as an empty market.
    """
    try:
        if pool["version"] == "v3":
            return _quote_v3(w3, chain_id, pool, token_in, token_out, amount)
        if pool["version"] == "v4":
            return _quote_v4(w3, chain_id, pool, token_in, token_out, amount)
        return _quote_v2(w3, pool, token_in, token_out, amount)
    except (ContractLogicError, BadFunctionCallOutput):
        return 0


def best_route(  # pylint: disable=too-many-positional-arguments
    w3: Web3,
    chain_id: int,
    token_in: str,
    token_out: str,
    amount: int,
    candidates: list[Pool],
) -> tuple[Pool, int]:
    """Pick the candidate pool with the best output for this exact size.

    Raises:
        SwapError: when a candidate was discovered for a different pair, or
            when none of them can fill the size.
    """
    for pool in candidates:
        pair = pool.get("quote_address")
        if pair is None:
            raise SwapError(
                f"{pool['version']} pool carries no quote_address; it did not come "
                f"from discovery and cannot be matched to this trade"
            )
        if to_checksum_address(pair) not in (
            to_checksum_address(token_in),
            to_checksum_address(token_out),
        ):
            raise SwapError(
                f"{pool['version']} pool was discovered against {pair}, which is "
                f"neither side of this trade"
            )
    quoted = [
        (quote_pool(w3, chain_id, pool, token_in, token_out, amount), pool)
        for pool in candidates
    ]
    fillable = [(out, pool) for out, pool in quoted if out > 0]
    if not fillable:
        raise SwapError(
            f"no pool quoted {token_in} -> {token_out} for {amount}; "
            f"all {len(candidates)} candidates returned zero"
        )
    fillable.sort(key=lambda pair: pair[0], reverse=True)
    best_out, best_pool = fillable[0]
    return best_pool, best_out


def _v4_swap_input(  # pylint: disable=too-many-positional-arguments
    pool: PoolV4, token_in: str, token_out: str, amount: int, minimum: int, to: str
) -> bytes:
    """Router input for a single-hop v4 swap, settle and take."""
    actions = bytes([ACTION_SWAP_EXACT_IN, ACTION_SETTLE, ACTION_TAKE])
    path_key = (
        token_out,
        int(pool["fee"]),
        int(pool["tick_spacing"]),
        pool["hooks"],
        b"",
    )
    swap_params = abi_encode(
        [V4_EXACT_INPUT_PARAMS],
        [(token_in, [path_key], NO_HOP_PRICE_LIMIT, amount, minimum)],
    )
    settle = abi_encode(
        ["address", "uint256", "bool"], [token_in, OPEN_DELTA, PAYER_IS_USER]
    )
    take = abi_encode(["address", "address", "uint256"], [token_out, to, OPEN_DELTA])
    return abi_encode(["bytes", "bytes[]"], [actions, [swap_params, settle, take]])


def _v3_swap_input(  # pylint: disable=too-many-positional-arguments
    pool: PoolV3, token_in: str, token_out: str, amount: int, minimum: int, to: str
) -> bytes:
    """Router input for a single-hop v3 exact-input swap."""
    path = (
        bytes.fromhex(token_in[2:])
        + int(pool["fee"]).to_bytes(3, "big")
        + bytes.fromhex(token_out[2:])
    )
    return abi_encode(
        ["address", "uint256", "uint256", "bytes", "bool", "uint256[]"],
        [to, amount, minimum, path, PAYER_IS_USER, NO_HOP_PRICE_LIMIT],
    )


def _v2_swap_input(
    token_in: str, token_out: str, amount: int, minimum: int, to: str
) -> bytes:
    """Router input for a single-hop v2 exact-input swap."""
    return abi_encode(
        ["address", "uint256", "uint256", "address[]", "bool", "uint256[]"],
        [to, amount, minimum, [token_in, token_out], PAYER_IS_USER, NO_HOP_PRICE_LIMIT],
    )


def build_execute(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    pool: Pool,
    token_in: str,
    token_out: str,
    amount: int,
    minimum: int,
    to: str,
    deadline: int,
    permit_action: t.Optional[bytes] = None,
) -> str:
    """Universal Router execute() calldata for the chosen pool.

    A permit action rides in front of the swap when the caller granted its
    Permit2 allowance by signature instead of by transaction.

    Raises:
        SwapError: when the pool carries a version this cannot encode.
    """
    if pool["version"] == "v4":
        payload = _v4_swap_input(pool, token_in, token_out, amount, minimum, to)
    elif pool["version"] == "v3":
        payload = _v3_swap_input(pool, token_in, token_out, amount, minimum, to)
    elif pool["version"] == "v2":
        payload = _v2_swap_input(token_in, token_out, amount, minimum, to)
    else:
        raise SwapError(f"unknown pool version {pool['version']!r}")
    command = SWAP_COMMANDS[pool["version"]]
    commands, inputs = bytes([command]), [payload]
    if permit_action is not None:
        commands = bytes([COMMAND_PERMIT2_PERMIT]) + commands
        inputs = [permit_action] + inputs
    calldata = SEL_UR_EXECUTE + abi_encode(
        ["bytes", "bytes[]", "uint256"], [commands, inputs, deadline]
    )
    return "0x" + calldata.hex()


def _decode_execute(  # pylint: disable=too-many-locals
    calldata: str, pool: Pool
) -> tuple[str, str, str, int, int, tuple[int, int, str]]:
    """Read back token in, token out, recipient, amount and floor.

    Raises:
        SwapError: when the calldata is not one swap, optionally permitted.
    """
    body = bytes.fromhex(calldata[10:])
    commands, inputs, _ = abi_decode(["bytes", "bytes[]", "uint256"], body)
    if len(commands) != len(inputs) or not commands:
        raise SwapError(f"malformed commands {commands.hex()!r}")
    if commands[0] == COMMAND_PERMIT2_PERMIT:
        commands, inputs = commands[1:], inputs[1:]
    if len(commands) != 1:
        raise SwapError(f"expected one swap command, got {commands.hex()!r}")
    expected = SWAP_COMMANDS[pool["version"]]
    if commands[0] != expected:
        raise SwapError(
            f"calldata carries command 0x{commands[0]:02x}, but a {pool['version']} "
            f"exact-input swap is 0x{expected:02x}"
        )
    if pool["version"] == "v4":
        actions, params = abi_decode(["bytes", "bytes[]"], inputs[0])
        if actions != bytes([ACTION_SWAP_EXACT_IN, ACTION_SETTLE, ACTION_TAKE]):
            raise SwapError(f"unexpected v4 actions {actions.hex()}")
        currency_in, path, _, amount_in, minimum_out = abi_decode(
            [V4_EXACT_INPUT_PARAMS], params[0]
        )[0]
        recipient = abi_decode(["address", "address", "uint256"], params[2])[1]
        token_out_seen = path[0][0]
        venue = (int(path[0][1]), int(path[0][2]), to_checksum_address(path[0][3]))
    elif pool["version"] == "v3":
        recipient, amount_in, minimum_out, path_bytes, _, _ = abi_decode(
            ["address", "uint256", "uint256", "bytes", "bool", "uint256[]"], inputs[0]
        )
        currency_in = "0x" + path_bytes[:20].hex()
        token_out_seen = "0x" + path_bytes[23:43].hex()
        venue = (int.from_bytes(path_bytes[20:23], "big"), 0, NO_HOOKS)
    else:
        recipient, amount_in, minimum_out, path_list, _, _ = abi_decode(
            ["address", "uint256", "uint256", "address[]", "bool", "uint256[]"],
            inputs[0],
        )
        currency_in, token_out_seen = path_list[0], path_list[-1]
        venue = (V2_FEE, 0, NO_HOOKS)
    return currency_in, token_out_seen, recipient, amount_in, minimum_out, venue


def verify_execute(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    calldata: str,
    pool: Pool,
    token_in: str,
    token_out: str,
    amount: int,
    minimum: int,
    to: str,
) -> None:
    """Decode our own calldata and check it says what we meant.

    Raises:
        SwapError: when any field disagrees with what was planned.
    """
    (
        currency_in,
        token_out_seen,
        recipient,
        amount_in,
        minimum_out,
        venue,
    ) = _decode_execute(calldata, pool)
    planned = (
        int(pool["fee"]),
        int(pool["tick_spacing"]) if pool["version"] == "v4" else 0,
        pool["hooks"] if pool["version"] == "v4" else NO_HOOKS,
    )
    checks: dict[str, tuple[t.Any, t.Any]] = {
        "token_in": (to_checksum_address(currency_in), to_checksum_address(token_in)),
        "token_out": (
            to_checksum_address(token_out_seen),
            to_checksum_address(token_out),
        ),
        "recipient": (to_checksum_address(recipient), to_checksum_address(to)),
        "amount_in": (amount_in, amount),
        "minimum_out": (minimum_out, minimum),
        "venue": (venue, planned),
    }
    check_fields("calldata", checks)


def permit_action_in(calldata: str) -> t.Optional[bytes]:
    """Read the PERMIT2_PERMIT input carried by this execute(), when there is one."""
    commands, inputs, _ = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    if commands and commands[0] == COMMAND_PERMIT2_PERMIT:
        blob: bytes = inputs[0]
        return blob
    return None
