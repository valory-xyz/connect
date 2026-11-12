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

"""Read-only chain tools: call a contract, find its ABI, decode calldata (T5).

Nothing here signs or spends. `get_abi` resolves only what Connect ships: a
few well-known contracts by address, and the standard interfaces a contract
answers to (ERC-20 by its `decimals()`, ERC-721/1155 by `supportsInterface`).
It follows the EIP-1967 implementation slot, as the reference gate does, and
makes no block-explorer call; `verified` says whether the ABI came from a
contract Connect knows by address rather than from an interface it answers to.
"""

import typing as t

from eth_abi import decode as abi_decode
from eth_utils import keccak, to_checksum_address
from web3 import Web3

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

KNOWN_CONTRACTS: dict[str, tuple[str, tuple[str, ...]]] = {
    # the same address on every chain these are deployed to
    "0xca11bde05977b3631167028862be2a173976ca11": ("Multicall3", OTHER_SIGNATURES[1:2]),
    "0x000000000022d473030f116ddee9f6b43ac78ba3": ("Permit2", OTHER_SIGNATURES[4:5]),
}

COMMON_SIGNATURES = (
    ERC20_SIGNATURES
    + ERC721_SIGNATURES
    + ERC1155_SIGNATURES
    + WETH_SIGNATURES
    + OTHER_SIGNATURES
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
    """Run an eth_call; return {result} or {reverted, reason}."""
    try:
        raw = w3.eth.call(
            {"to": to_checksum_address(to), "data": t.cast(t.Any, data or "0x")},
            block_identifier=t.cast(t.Any, block),
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        return {"reverted": True, "reason": str(e)}
    return {"result": "0x" + bytes(raw).hex()}


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


def _interfaces(w3: Web3, address: str) -> tuple[bool, list[str]]:
    """Return (verified, signatures) for one address, without following proxies."""
    known = KNOWN_CONTRACTS.get(address.lower())
    if known is not None:
        return True, list(known[1])
    signatures: list[str] = []
    if _supports(w3, address, "0xd9b67a26"):
        signatures += ERC1155_SIGNATURES
    elif _supports(w3, address, "0x80ac58cd"):
        signatures += ERC721_SIGNATURES
    elif _answers(w3, address, "decimals()"):
        signatures += ERC20_SIGNATURES
    return False, signatures


def get_abi(w3: Web3, address: str) -> dict:
    """Return what Connect can say about a contract's ABI."""
    address = to_checksum_address(address)
    verified, signatures = _interfaces(w3, address)
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
        impl_verified, impl_signatures = _interfaces(w3, implementation)
        report["implementation"] = implementation
        report["implementation_abi"] = [
            _abi_entry(s) for s in dict.fromkeys(impl_signatures)
        ]
        report["verified"] = verified or impl_verified
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
    args_raw = bytes.fromhex(raw[8:])
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
        return _jsonable(abi_decode(types, args_raw))
    except Exception:  # pylint: disable=broad-exception-caught
        return None


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
