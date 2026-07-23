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

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

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


def _hex_to_bytes(value: str) -> bytes:
    """Read 0x-hex (or bare hex) as bytes."""
    return bytes.fromhex(value.removeprefix("0x"))


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
    calldata = (data or "").removeprefix("0x").lower()
    if not calldata.startswith(APPROVE_SELECTOR):
        return None
    try:
        spender, _ = abi_decode(["address", "uint256"], bytes.fromhex(calldata[8:]))
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return str(spender)
