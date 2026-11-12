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

"""Read-only chain tools: call a contract, find its ABI, decode calldata.

Nothing here signs or spends. `get_abi` resolves only what Connect ships: a
few well-known contracts by address, and the standard interfaces a contract
answers to (ERC-20 by its `decimals()`, ERC-721/1155 by `supportsInterface`).
It follows the EIP-1967 implementation slot, as the reference gate does, and
makes no block-explorer call; `verified` says whether the ABI came from a
contract Connect knows by address rather than from an interface it answers to.
"""

import typing as t

from eth_abi import decode as abi_decode
from eth_abi.exceptions import DecodingError
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.exceptions import ContractLogicError

# EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
IMPLEMENTATION_SLOT = int(
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
)

ERC20_SIGNATURES = (
    "transfer(address,uint256)",
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",
    "balanceOf(address)",
    "allowance(address,address)",
    "decimals()",
    "symbol()",
    "name()",
    "totalSupply()",
)
ERC721_SIGNATURES = (
    "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256,bytes)",
    "setApprovalForAll(address,bool)",
    "ownerOf(uint256)",
    "isApprovedForAll(address,address)",
)
ERC1155_SIGNATURES = (
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)",
    "setApprovalForAll(address,bool)",
    "balanceOf(address,uint256)",
)
WETH_SIGNATURES = ("deposit()", "withdraw(uint256)")
OTHER_SIGNATURES = (
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    "aggregate3((address,bool,bytes)[])",
    "execute(bytes,bytes[],uint256)",
    "execute(bytes,bytes[])",
    "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
    "splitPosition(address,bytes32,bytes32,uint256[],uint256)",
    "mergePositions(address,bytes32,bytes32,uint256[],uint256)",
    "redeemPositions(address,bytes32,bytes32,uint256[])",
    "multicall(bytes[])",
)

# the calls Connect's own skills make, named per contract
MULTICALL3_SIGNATURES = ("aggregate3((address,bool,bytes)[])",)
PERMIT2_SIGNATURES = (
    "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)",
    "approve(address,address,uint160,uint48)",
    "allowance(address,address,address)",
)
UNIVERSAL_ROUTER_SIGNATURES = (
    "execute(bytes,bytes[],uint256)",
    "execute(bytes,bytes[])",
)
CTF_SIGNATURES = ERC1155_SIGNATURES + (
    "splitPosition(address,bytes32,bytes32,uint256[],uint256)",
    "mergePositions(address,bytes32,bytes32,uint256[],uint256)",
    "redeemPositions(address,bytes32,bytes32,uint256[])",
)
CTF_ADAPTER_SIGNATURES = ("redeemPositions(address,bytes32,bytes32,uint256[])",)
ONRAMP_SIGNATURES = ("wrap(address,address,uint256)",)
PONS_FEE_ESCROW_SIGNATURES = ("claim()", "claimToken(address)")
PONS_HOOK_SIGNATURES = ("sweepPoolFees(bytes32,uint256,uint256)",)
SKILL_SIGNATURES = (
    MULTICALL3_SIGNATURES
    + PERMIT2_SIGNATURES
    + UNIVERSAL_ROUTER_SIGNATURES
    + CTF_SIGNATURES
    + ONRAMP_SIGNATURES
    + PONS_FEE_ESCROW_SIGNATURES
    + PONS_HOOK_SIGNATURES
)


# Contracts Connect ships an ABI for: the shared ones, and the ones its bundled
# skills call (connect-polymarket's pm_common, the lib's uniswap DEPLOYMENTS,
# connect-pons's pons.py), lower-case. tests/test_chain_read.py reads those
# files to keep the two in step.
class KnownContract(t.NamedTuple):
    """A contract Connect ships an ABI for, and the chains it is deployed on."""

    name: str
    signatures: tuple[str, ...]
    chains: frozenset[int] | None  # None: the same address on every chain


KNOWN_CONTRACTS: dict[str, "KnownContract"] = {
    # the same address on every chain these are deployed to
    "0xca11bde05977b3631167028862be2a173976ca11": KnownContract(
        "Multicall3", MULTICALL3_SIGNATURES, None
    ),
    "0x000000000022d473030f116ddee9f6b43ac78ba3": KnownContract(
        "Permit2", PERMIT2_SIGNATURES, None
    ),
    # Uniswap Universal Router: Robinhood Chain, Polygon, Gnosis
    "0x8876789976decbfcbbbe364623c63652db8c0904": KnownContract(
        "Uniswap Universal Router", UNIVERSAL_ROUTER_SIGNATURES, frozenset({4663})
    ),
    "0x1095692a6237d83c6a72f3f5efedb9a670c49223": KnownContract(
        "Uniswap Universal Router", UNIVERSAL_ROUTER_SIGNATURES, frozenset({137})
    ),
    "0x75fc67473a91335b5b8f8821277262a13b38c9b3": KnownContract(
        "Uniswap Universal Router", UNIVERSAL_ROUTER_SIGNATURES, frozenset({100})
    ),
    # Polymarket, Polygon
    "0x4d97dcd97ec945f40cf65f87097ace5ea0476045": KnownContract(
        "Polymarket ConditionalTokens", CTF_SIGNATURES, frozenset({137})
    ),
    "0xada100db00ca00073811820692005400218fce1f": KnownContract(
        "Polymarket CTF collateral adapter", CTF_ADAPTER_SIGNATURES, frozenset({137})
    ),
    "0xada2005600dec949baf300f4c6120000bdb6eaab": KnownContract(
        "Polymarket NegRisk CTF collateral adapter",
        CTF_ADAPTER_SIGNATURES,
        frozenset({137}),
    ),
    "0x93070a847efef7f70739046a929d47a521f5b8ee": KnownContract(
        "Polymarket collateral onramp", ONRAMP_SIGNATURES, frozenset({137})
    ),
    "0xc011a7e12a19f7b1f670d46f03b03f3342e82dfb": KnownContract(
        "Polymarket pUSD", ERC20_SIGNATURES, frozenset({137})
    ),
    "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": KnownContract(
        "USDC.e", ERC20_SIGNATURES, frozenset({137})
    ),
    "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": KnownContract(
        "USDC", ERC20_SIGNATURES, frozenset({137})
    ),
    # Pons, Robinhood Chain
    "0xd3afeb2a57f70ef218aa82451c51b2fb0416ac9e": KnownContract(
        "Pons fee escrow", PONS_FEE_ESCROW_SIGNATURES, frozenset({4663})
    ),
    "0xe5e702641ea86f4ae6cc3cdaed2b886f976be044": KnownContract(
        "Pons meme hook", PONS_HOOK_SIGNATURES, frozenset({4663})
    ),
    "0x0bd7d308f8e1639fab988df18a8011f41eacad73": KnownContract(
        "WETH", ERC20_SIGNATURES + WETH_SIGNATURES, frozenset({4663})
    ),
    "0x5fc5360d0400a0fd4f2af552add042d716f1d168": KnownContract(
        "USDG", ERC20_SIGNATURES, frozenset({4663})
    ),
}

COMMON_SIGNATURES = (
    ERC20_SIGNATURES
    + ERC721_SIGNATURES
    + ERC1155_SIGNATURES
    + WETH_SIGNATURES
    + OTHER_SIGNATURES
    + SKILL_SIGNATURES
)


def selector_of(signature: str) -> str:
    """Return the 0x-hex 4-byte selector of a function signature."""
    return "0x" + keccak(text=signature)[:4].hex()


SELECTORS: dict[str, list[str]] = {}
for _signature in dict.fromkeys(COMMON_SIGNATURES):
    SELECTORS.setdefault(selector_of(_signature), []).append(_signature)


def _abi_entry(signature: str) -> dict:
    """Return a minimal JSON ABI entry for a function signature."""
    name, _, rest = signature.partition("(")
    types = _split_types(rest[:-1])
    return {
        "type": "function",
        "name": name,
        "inputs": [{"name": f"arg{i}", "type": t_} for i, t_ in enumerate(types)],
    }


def _split_types(text: str) -> list[str]:
    """Split a comma-separated type list, keeping tuples whole."""
    types, depth, current = [], 0, ""
    for char in text:
        if char == "," and depth == 0:
            types.append(current)
            current = ""
            continue
        depth += {"(": 1, ")": -1}.get(char, 0)
        current += char
    if current:
        types.append(current)
    return types


def chain_call(w3: Web3, to: str, data: str, block: str = "latest") -> dict:
    """Run an eth_call; return {result} or {reverted, reason}.

    Only a revert is reported as one: an RPC that is down or times out raises,
    so an unreachable chain never reads as a contract that said no, and a
    malformed argument raises ValueError naming it before anything is asked.
    """
    address = to_checksum_address(to)  # ValueError: not an address
    data = data or "0x"
    if not data.startswith("0x"):
        raise ValueError(f"data must be 0x-hex, got '{data}'")
    bytes.fromhex(data[2:])  # ValueError: not hex
    try:
        raw = w3.eth.call(
            {"to": address, "data": t.cast(t.Any, data)},
            block_identifier=_block(block),
        )
    except ContractLogicError as e:
        return {"reverted": True, "reason": e.message or str(e)}
    return {"result": "0x" + bytes(raw).hex()}


BLOCK_TAGS = ("latest", "pending", "earliest", "safe", "finalized")


def _block(block: str) -> t.Any:
    """Return a block tag or number for eth_call; ValueError for anything else."""
    if block in BLOCK_TAGS:
        return block
    try:
        number = int(block, 0)
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"block must be one of {', '.join(BLOCK_TAGS)} or a number, got '{block}'"
        ) from e
    if number < 0:
        raise ValueError(f"block must be >= 0, got {number}")
    return number


def _answers(w3: Web3, address: str, signature: str, args: bytes = b"") -> bool:
    """Whether a read of `signature` on `address` succeeds with a non-empty answer."""
    answer = chain_call(w3, address, selector_of(signature) + args.hex())
    return "result" in answer and answer["result"] != "0x"


def _supports(w3: Web3, address: str, interface_id: str) -> bool:
    """ERC-165: whether the contract says it supports `interface_id`."""
    args = bytes.fromhex(interface_id.removeprefix("0x")).ljust(32, b"\0")
    answer = chain_call(
        w3, address, selector_of("supportsInterface(bytes4)") + args.hex()
    )
    return answer.get("result", "0x")[-1:] == "1"


def _interfaces(w3: Web3, address: str, chain_id: int) -> tuple[bool, list[str]]:
    """Return (verified, signatures) for one address, without following proxies.

    An address is known only on the chains its contract is deployed on: the
    same address elsewhere may hold anything.
    """
    known = KNOWN_CONTRACTS.get(address.lower())
    if known is not None and (known.chains is None or chain_id in known.chains):
        return True, list(known.signatures)
    signatures: list[str] = []
    if _supports(w3, address, "0xd9b67a26"):
        signatures += ERC1155_SIGNATURES
    elif _supports(w3, address, "0x80ac58cd"):
        signatures += ERC721_SIGNATURES
    elif _answers(w3, address, "decimals()"):
        signatures += ERC20_SIGNATURES
    return False, signatures


def get_abi(w3: Web3, address: str) -> dict:
    """Return what Connect can say about a contract's ABI.

    `verified` speaks for the queried address alone. A proxy's EIP-1967 slot
    is storage the contract writes itself, so whatever it points at is
    reported as `implementation_verified`, never as the contract's own.
    """
    address = to_checksum_address(address)
    chain_id = int(w3.eth.chain_id)
    verified, signatures = _interfaces(w3, address, chain_id)
    report: dict = {
        "address": address,
        "verified": verified,
        "abi": [_abi_entry(s) for s in dict.fromkeys(signatures)],
    }
    slot = int.from_bytes(
        bytes(w3.eth.get_storage_at(address, IMPLEMENTATION_SLOT)), "big"
    )
    if slot:
        implementation = to_checksum_address("0x" + hex(slot)[2:].rjust(40, "0")[-40:])
        impl_verified, impl_signatures = _interfaces(w3, implementation, chain_id)
        report["implementation"] = implementation
        report["implementation_verified"] = impl_verified
        report["implementation_abi"] = [
            _abi_entry(s) for s in dict.fromkeys(impl_signatures)
        ]
    if not report["abi"] and not report.get("implementation_abi"):
        report["note"] = (
            "no ABI Connect ships matches this contract; decode its calls with "
            "decode_calldata or read it with chain_call"
        )
    return report


def decode_calldata(data: str) -> dict:
    """Decode calldata against the signatures Connect ships."""
    raw = (data or "0x").removeprefix("0x")
    selector = "0x" + raw[:8]
    if len(raw) < 8:
        return {"selector": selector, "error": "calldata shorter than a selector"}
    candidates = SELECTORS.get(selector)
    if not candidates:
        return {"selector": selector, "error": "unknown selector"}
    try:
        args_raw = bytes.fromhex(raw[8:])
    except ValueError:
        return {"selector": selector, "error": "calldata is not hex"}
    for signature in candidates:
        args = _decode_args(signature, args_raw)
        if args is not None:
            return {"selector": selector, "signature": signature, "args": args}
    return {
        "selector": selector,
        "signature": candidates[0],
        "error": "the arguments do not decode as this signature",
    }


def _decode_args(signature: str, args_raw: bytes) -> list | None:
    """Decode arguments as `signature` takes them, or None if they do not fit."""
    types = _split_types(signature.partition("(")[2][:-1])
    try:
        decoded = abi_decode(types, args_raw)
    except DecodingError:  # the bytes do not fit; a bad signature still raises
        return None
    return _jsonable(decoded)


def _jsonable(value: t.Any) -> t.Any:
    """Turn decoded ABI values into JSON: ints as strings, bytes as hex."""
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    return value
