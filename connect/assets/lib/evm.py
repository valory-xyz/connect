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

"""Chain access and primitives: the signer's web3, calls, decimals, ERC-20."""

import sys
import typing as t
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3

_PEARL_SCRIPTS = (
    Path(__file__).resolve().parents[1] / "skills" / "pearl-connect" / "scripts"
)
if str(_PEARL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PEARL_SCRIPTS))
try:
    from signer_client import (  # noqa: E402  pylint: disable=wrong-import-position
        connect,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - install-shape guard
    raise ImportError(
        "connect-stocktokens needs the sibling pearl-connect skill; expected "
        f"signer_client.py under {_PEARL_SCRIPTS}"
    ) from exc


class Call(t.TypedDict):
    """One call the safe makes, as the signer expects it."""

    to: str
    data: str
    what: str


class SwapError(RuntimeError):
    """A trade could not be quoted, built or verified."""


def selector(signature: str) -> bytes:
    """First four bytes of the keccak hash of a function signature."""
    return keccak(text=signature)[:4]


SEL_BALANCE_OF = selector("balanceOf(address)")
SEL_DECIMALS = selector("decimals()")
SEL_ERC20_APPROVE = selector("approve(address,uint256)")


def check_fields(kind: str, checks: dict[str, tuple[t.Any, t.Any]]) -> None:
    """Raise unless every decoded field is the one that was planned.

    Raises:
        SwapError: on the first field that disagrees.
    """
    for field, (got, want) in checks.items():
        if got != want:
            raise SwapError(f"{kind} {field} is {got!r}, expected {want!r}")


def call_int(w3: Web3, to: str, data: bytes) -> int:
    """One eth_call whose single return word is read as an unsigned integer.

    Raises:
        SwapError: when the call returns nothing; "the node said nothing" and
            "the contract said zero" are different answers.
    """
    raw = bytes(w3.eth.call({"to": to_checksum_address(to), "data": data}))
    if len(raw) < 32:
        raise SwapError(
            f"{to} returned {len(raw)} bytes, expected at least 32; it may not "
            f"be a contract here"
        )
    return int.from_bytes(raw[:32], "big")


def call_address(w3: Web3, to: str, data: bytes) -> t.Optional[str]:
    """One eth_call returning an address, or None when it answers the zero one."""
    value = call_int(w3, to, data)
    return to_checksum_address(f"0x{value:040x}") if value else None


def token_decimals(w3: Web3, token: str) -> int:
    """Decimals read from the token, never assumed.

    Raises:
        SwapError: when the token reports implausible decimals.
    """
    decimals = call_int(w3, token, SEL_DECIMALS)
    if not 0 < decimals <= 36:
        raise SwapError(f"{token} reports implausible decimals: {decimals}")
    return decimals


def balance_of(w3: Web3, token: str, holder: str, decimals: int) -> float:
    """Read a holder's token balance in whole units."""
    data = SEL_BALANCE_OF + abi_encode(["address"], [to_checksum_address(holder)])
    return call_int(w3, token, data) / 10**decimals


def erc20_approval_call(token: str, spender: str, amount: int, label: str) -> Call:
    """Exact-amount ERC-20 approval, as a call the safe can make."""
    data = SEL_ERC20_APPROVE + abi_encode(
        ["address", "uint256"], [to_checksum_address(spender), amount]
    )
    return {"to": token, "data": "0x" + data.hex(), "what": label}


__all__ = [
    "Call",
    "SwapError",
    "check_fields",
    "balance_of",
    "call_address",
    "call_int",
    "connect",
    "erc20_approval_call",
    "selector",
    "token_decimals",
]
