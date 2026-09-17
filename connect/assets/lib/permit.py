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

"""Permit2 allowances the safe grants by signature instead of by transaction.

A safe's ERC-1271 handler does not verify a signature over the Permit2 digest
itself: the owner signs ``SafeMessage(abi.encode(permit2Digest))`` under the
safe's own domain. Sign the raw digest and Permit2 rejects it.
"""

import typing as t

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from evm import Call, SwapError, check_fields, selector
from web3 import Web3

EIP712_DOMAIN_TYPEHASH = keccak(
    text="EIP712Domain(string name,uint256 chainId,address verifyingContract)"
)
PERMIT_DETAILS_TYPE = (
    "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
)
PERMIT_DETAILS_TYPEHASH = keccak(text=PERMIT_DETAILS_TYPE)
PERMIT_SINGLE_TYPEHASH = keccak(
    text=(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)"
        + PERMIT_DETAILS_TYPE
    )
)
SAFE_MESSAGE_TYPEHASH = keccak(text="SafeMessage(bytes message)")
PERMIT2_DOMAIN_NAME = "Permit2"
PERMIT_SINGLE_ABI = "((address,uint160,uint48,uint48),address,uint256)"
PLACEHOLDER_SIGNATURE = bytes(65)

SEL_ALLOWANCE = selector("allowance(address,address,address)")
SEL_DOMAIN_SEPARATOR = selector("domainSeparator()")
SEL_APPROVE = selector("approve(address,address,uint160,uint48)")


class PermitDetails(t.NamedTuple):
    """One token's Permit2 allowance for one spender."""

    token: str
    amount: int
    expiration: int
    nonce: int


def permit2_domain_separator(chain_id: int, permit2: str) -> bytes:
    """Permit2's EIP-712 domain separator, which carries no version field."""
    return keccak(
        abi_encode(
            ["bytes32", "bytes32", "uint256", "address"],
            [
                EIP712_DOMAIN_TYPEHASH,
                keccak(text=PERMIT2_DOMAIN_NAME),
                chain_id,
                to_checksum_address(permit2),
            ],
        )
    )


def permit_single_digest(
    chain_id: int,
    permit2: str,
    details: PermitDetails,
    spender: str,
    sig_deadline: int,
) -> bytes:
    """EIP-712 digest of a PermitSingle, as Permit2 itself computes it."""
    details_hash = keccak(
        abi_encode(
            ["bytes32", "address", "uint160", "uint48", "uint48"],
            [
                PERMIT_DETAILS_TYPEHASH,
                to_checksum_address(details.token),
                details.amount,
                details.expiration,
                details.nonce,
            ],
        )
    )
    struct_hash = keccak(
        abi_encode(
            ["bytes32", "bytes32", "address", "uint256"],
            [
                PERMIT_SINGLE_TYPEHASH,
                details_hash,
                to_checksum_address(spender),
                sig_deadline,
            ],
        )
    )
    return keccak(
        b"\x19\x01" + permit2_domain_separator(chain_id, permit2) + struct_hash
    )


def safe_message_digest(domain_separator: bytes, digest: bytes) -> bytes:
    """Derive what a safe owner must actually sign for the safe to accept a digest."""
    message_hash = keccak(
        abi_encode(
            ["bytes32", "bytes32"],
            [SAFE_MESSAGE_TYPEHASH, keccak(abi_encode(["bytes32"], [digest]))],
        )
    )
    return keccak(b"\x19\x01" + domain_separator + message_hash)


def permit_input(
    details: PermitDetails, spender: str, sig_deadline: int, signature: bytes
) -> bytes:
    """Universal Router input for the PERMIT2_PERMIT action."""
    return abi_encode(
        [PERMIT_SINGLE_ABI, "bytes"],
        [
            (
                (
                    to_checksum_address(details.token),
                    details.amount,
                    details.expiration,
                    details.nonce,
                ),
                to_checksum_address(spender),
                sig_deadline,
            ),
            signature,
        ],
    )


def allowance_call(owner: str, token: str, spender: str) -> bytes:
    """Calldata for Permit2's allowance(owner, token, spender) view."""
    return SEL_ALLOWANCE + abi_encode(
        ["address", "address", "address"],
        [
            to_checksum_address(owner),
            to_checksum_address(token),
            to_checksum_address(spender),
        ],
    )


def decode_allowance(raw: bytes) -> tuple[int, int, int]:
    """Amount, expiration and nonce from a Permit2 allowance() return.

    Raises:
        SwapError: on a short read, rather than signing a guessed nonce.
    """
    if len(raw) < 96:
        raise SwapError(
            f"Permit2 allowance() returned {len(raw)} bytes, expected 96; "
            f"refusing to sign a permit with a guessed nonce"
        )
    return (
        int.from_bytes(raw[0:32], "big"),
        int.from_bytes(raw[32:64], "big"),
        int.from_bytes(raw[64:96], "big"),
    )


def approval_call(
    permit2: str, token: str, spender: str, amount: int, expiry: int
) -> Call:
    """On-chain Permit2 allowance, for callers that cannot sign a digest."""
    data = SEL_APPROVE + abi_encode(
        ["address", "address", "uint160", "uint48"],
        [to_checksum_address(token), to_checksum_address(spender), amount, expiry],
    )
    return {"to": permit2, "data": "0x" + data.hex(), "what": "approve router"}


def signed_action(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    w3: Web3,
    chain_id: int,
    signer: t.Any,
    owner: str,
    token: str,
    amount: int,
    permit2: str,
    spender: str,
    expiry: int,
    placeholder: bool = False,
) -> bytes:
    """Build a Permit2 allowance the router carries itself, signed by the owner safe.

    ``expiry`` bounds both the allowance and the window the signature may be
    submitted in, so the caller sets them from the same budget it gives the
    swap's own deadline: an allowance that lapses first would revert a swap
    the router would still have accepted.

    Raises:
        SwapError: when the owner is not a safe, or the signer refuses.
    """
    raw = bytes(
        w3.eth.call({"to": permit2, "data": allowance_call(owner, token, spender)})
    )
    _, _, nonce = decode_allowance(raw)
    details = PermitDetails(token=token, amount=amount, expiration=expiry, nonce=nonce)
    sig_deadline = expiry
    digest = permit_single_digest(chain_id, permit2, details, spender, sig_deadline)
    domain_separator = bytes(w3.eth.call({"to": owner, "data": SEL_DOMAIN_SEPARATOR}))
    if len(domain_separator) != 32:
        raise SwapError(
            f"{owner} did not answer domainSeparator(); it is not a safe this "
            f"skill can sign a permit for - rerun with --separate-approvals"
        )
    if placeholder:
        return permit_input(details, spender, sig_deadline, PLACEHOLDER_SIGNATURE)
    try:
        signature = signer.sign_digest(safe_message_digest(domain_separator, digest))
    except Exception as exc:  # pylint: disable=broad-except
        raise SwapError(
            f"the signer refused the permit signature ({exc}); try with "
            f"--separate-approvals to approve in its own transaction instead"
        ) from exc
    return permit_input(details, spender, sig_deadline, bytes.fromhex(signature[2:]))


def decode_action(action: bytes) -> tuple[PermitDetails, str, int]:
    """Read a PERMIT2_PERMIT router input back into its fields."""
    single, _signature = abi_decode([PERMIT_SINGLE_ABI, "bytes"], action)
    (token, amount, expiration, nonce), spender, sig_deadline = single
    return (
        PermitDetails(
            token=to_checksum_address(token),
            amount=amount,
            expiration=expiration,
            nonce=nonce,
        ),
        to_checksum_address(spender),
        sig_deadline,
    )


def verify_action(
    action: bytes, token: str, spender: str, amount: int, expiry: int
) -> None:
    """Check the allowance we signed is the one we meant to grant.

    Raises:
        SwapError: when any field disagrees with what was planned.
    """
    details, signed_spender, sig_deadline = decode_action(action)
    checks: dict[str, tuple[t.Any, t.Any]] = {
        "token": (details.token, to_checksum_address(token)),
        "spender": (signed_spender, to_checksum_address(spender)),
        "amount": (details.amount, amount),
        "expiration": (details.expiration, expiry),
        "sig_deadline": (sig_deadline, expiry),
    }
    check_fields("permit", checks)
