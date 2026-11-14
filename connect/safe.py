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

"""The service safe: the one place that knows what an execTransaction looks like.

The agent asks for an inner call — a target, a value, some calldata — and the
server wraps it. Nothing else needs the shape: the guard decodes with the same
spec that this encodes with, so the writer and the reader of these bytes cannot
drift apart.

The safe has threshold 1 and the agent EOA is its only owner, so no signature
is collected off-chain. Safe accepts a *pre-validated* signature — r = the
owner's address, s = 0, v = 1 — precisely when the caller is that owner, which
the outer transaction guarantees: msg.sender IS the agent EOA. That is also why
no safe nonce appears anywhere here. Nothing is signed over it, so nobody has
to predict it; the Safe reads and increments its own.
"""

from dataclasses import dataclass

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from web3 import Web3

# Safe v1.x execTransaction(address,uint256,bytes,uint8,uint256,uint256,
#                           uint256,address,address,bytes)
EXEC_TRANSACTION_SELECTOR = "6a761202"
EXEC_TRANSACTION_TYPES = [
    "address",  # to
    "uint256",  # value
    "bytes",  # data
    "uint8",  # operation (0 = CALL, 1 = DELEGATECALL)
    "uint256",  # safeTxGas
    "uint256",  # baseGas
    "uint256",  # gasPrice
    "address",  # gasToken
    "address",  # refundReceiver
    "bytes",  # signatures
]
OPERATION_CALL = 0
ZERO_ADDRESS = "0x" + "00" * 20

APPROVE_SELECTOR = "095ea7b3"  # approve(address,uint256)
# Safe.approveHash(bytes32): an owner pre-approves a safe transaction by hash,
# which anyone may then execute with no further signature
APPROVE_HASH_SELECTOR = "d4d9bdcd"
DEPOSIT_SELECTOR = "b6b55f25"  # deposit(uint256) — mech BalanceTracker top-up

# EIP-712 typehashes of the Safe v1.3.0+ SafeMessage wrapping (unchanged in
# v1.4.1): the domain the CompatibilityFallbackHandler rehashes a bare digest
# into before ERC-1271 owner-signature checking.
SAFE_DOMAIN_TYPEHASH = Web3.keccak(
    text="EIP712Domain(uint256 chainId,address verifyingContract)"
)
SAFE_MESSAGE_TYPEHASH = Web3.keccak(text="SafeMessage(bytes message)")


def safe_message_hash(safe_address: str, chain_id: int, digest: bytes) -> bytes:
    r"""Return the hash Safe.isValidSignature checks owner signatures against.

    The v1.3.0+ ``CompatibilityFallbackHandler`` rehashes a bare 32-byte
    digest into an EIP-712 ``SafeMessage`` under the *safe's own* domain::

        keccak256("\x19\x01"
            ‖ keccak256(abi.encode(SAFE_DOMAIN_TYPEHASH, chainId, safe))
            ‖ keccak256(abi.encode(SAFE_MESSAGE_TYPEHASH, keccak256(digest))))

    Agent-mode off-chain mech requests are ERC-1271-verified against this
    wrap (mech-client's ``Signer.sign_safe_message`` contract), so both the
    signature and the guard's digest allowance must name the same bytes —
    one implementation here keeps the writer and the reader from drifting.

    Exactly 32 bytes are required: the inner ``keccak256(digest)`` shortcut
    matches the handler's ``keccak256(abi.encode(bytes32))`` only at that
    length, so anything else would silently produce a hash the safe never
    accepts.
    """
    if len(digest) != 32:
        raise ValueError(f"digest must be exactly 32 bytes, got {len(digest)}")
    domain_separator = Web3.keccak(
        abi_encode(
            ["bytes32", "uint256", "address"],
            [SAFE_DOMAIN_TYPEHASH, chain_id, safe_address],
        )
    )
    struct_hash = Web3.keccak(
        abi_encode(
            ["bytes32", "bytes32"],
            [SAFE_MESSAGE_TYPEHASH, Web3.keccak(digest)],
        )
    )
    return bytes(Web3.keccak(b"\x19\x01" + domain_separator + struct_hash))


def prevalidated_signature(owner: str) -> bytes:
    """Return the 65-byte signature Safe accepts from an owner calling directly.

    v = 1 tells Safe to skip ecrecover and require that r (read as an address)
    is an owner and is the caller. It authorizes nothing on its own and cannot
    be replayed by anyone else: it is valid only because the outer
    transaction's msg.sender is that owner.
    """
    return b"".join(
        (
            bytes(12) + _hex_to_bytes(owner),  # r: the owner, left-padded
            bytes(32),  # s: unused
            bytes([1]),  # v: pre-validated
        )
    )


def calldata_hex(data: str | None) -> str:
    """Return calldata as bare lowercase hex, its `0x`/`0X` prefix removed.

    The one reading of a calldata string every selector check shares: a
    signer reads `0X...` as the same bytes as `0x...`, so a check that
    strips only the lowercase prefix would miss the selector it guards.
    """
    raw = data or ""
    return (raw[2:] if raw[:2].lower() == "0x" else raw).lower()


def _hex_to_bytes(value: str) -> bytes:
    """Read 0x-hex (or bare hex) as bytes."""
    return bytes.fromhex(calldata_hex(value))


def exec_transaction(target: str, value: int, data: str, owner: str) -> str:
    """Return execTransaction calldata carrying one CALL out of the safe.

    `target` is the address the safe calls. The fields the guard refuses to see
    set are simply never set here.
    """
    args = abi_encode(
        EXEC_TRANSACTION_TYPES,
        (
            target,
            value,
            _hex_to_bytes(data or "0x"),
            OPERATION_CALL,
            0,  # safeTxGas: the safe forwards what it was given
            0,  # baseGas
            0,  # gasPrice: no refund
            ZERO_ADDRESS,  # gasToken
            ZERO_ADDRESS,  # refundReceiver
            prevalidated_signature(owner),
        ),
    )
    return "0x" + EXEC_TRANSACTION_SELECTOR + args.hex()


def decode_approve(data: str) -> str | None:
    """Return the spender of an ERC-20 `approve(address,uint256)`, else None.

    None means the calldata is not a decodable approve.
    """
    calldata = calldata_hex(data)
    if not calldata.startswith(APPROVE_SELECTOR):
        return None
    try:
        spender, _ = abi_decode(["address", "uint256"], bytes.fromhex(calldata[8:]))
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return str(spender)


def decode_deposit(data: str) -> int | None:
    """Return the amount of a BalanceTracker `deposit(uint256)`, else None.

    None means the calldata is not a decodable deposit — the guard treats
    that as "not the transaction the allowance covers", never as zero.
    """
    calldata = calldata_hex(data)
    if not calldata.startswith(DEPOSIT_SELECTOR):
        return None
    try:
        (amount,) = abi_decode(["uint256"], bytes.fromhex(calldata[8:]))
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return int(amount)


@dataclass(frozen=True)
class SafeExec:
    """An execTransaction, decoded: the call the safe makes and its refund fields.

    The one decoder of these bytes: the guard judges them and the intent gate
    simulates the call inside, so the two cannot read them differently.
    """

    to: str
    value: int
    data: str
    operation: int
    gas_price: int
    gas_token: str
    refund_receiver: str

    @classmethod
    def decode(cls, data: str) -> "SafeExec":
        """Decode execTransaction calldata; ValueError when it will not read."""
        calldata = calldata_hex(data)
        if not calldata.startswith(EXEC_TRANSACTION_SELECTOR):
            raise ValueError("not execTransaction calldata")
        try:
            decoded = tuple(
                abi_decode(EXEC_TRANSACTION_TYPES, bytes.fromhex(calldata[8:]))
            )
        except Exception as e:
            raise ValueError(f"could not decode execTransaction calldata: {e}") from e
        return cls(
            to=str(decoded[0]),
            value=int(decoded[1]),
            data="0x" + bytes(decoded[2]).hex(),
            operation=int(decoded[3]),
            gas_price=int(decoded[6]),
            gas_token=str(decoded[7]),
            refund_receiver=str(decoded[8]),
        )

    @property
    def pays_refund(self) -> bool:
        """Whether the safe would also pay a gas refund, outside the call itself."""
        return (
            self.gas_price != 0
            or self.gas_token.lower() != ZERO_ADDRESS
            or self.refund_receiver.lower() != ZERO_ADDRESS
        )


def is_exec_transaction(data: str) -> bool:
    """Whether calldata calls execTransaction."""
    return calldata_hex(data).startswith(EXEC_TRANSACTION_SELECTOR)
