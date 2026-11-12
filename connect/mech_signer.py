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

"""mech-client's ``Signer`` protocol over Connect's guarded signer.

Split out of ``mech.py``, which was at pylint's 1000-line limit; ``from
connect.mech import MechSigner`` still resolves.
"""

from connect.safe import safe_message_hash
from connect.signer import SERVER_BUILT, Signer


class MechSigner:
    """mech-client ``Signer`` protocol adapter over our guarded Signer.

    No special privileges: every transaction goes through Signer.send() and
    every digest through Signer.sign_digest(), both guardrail-checked.
    """

    def __init__(self, signer: Signer, chain: str) -> None:
        """Initialize."""
        self._signer = signer
        self._chain = chain

    @property
    def address(self) -> str:
        """The agent EOA address."""
        return self._signer.address

    def send_transaction(self, unsigned_tx: dict) -> str:
        """Fill, sign and broadcast the transaction via the choke point."""
        data = unsigned_tx.get("data") or "0x"
        if isinstance(data, (bytes, bytearray)):
            data = "0x" + bytes(data).hex()
        return self._signer.send(
            chain=self._chain,
            to=unsigned_tx["to"],
            value=int(unsigned_tx.get("value") or 0),
            data=data,
            gas=unsigned_tx.get("gas"),
            # the mech flow builds these itself, bounded by max_payment and,
            # while restricted, by its single-use allowances
            intent=SERVER_BUILT,
        )

    def sign_message(self, message: bytes) -> bytes:
        """Sign a raw digest via the choke point (guardrail-checked)."""
        signature = self._signer.sign_digest(bytes(message))
        return bytes.fromhex(signature.removeprefix("0x"))

    def sign_safe_message(
        self, safe_address: str, chain_id: int, message: bytes
    ) -> bytes:
        """Sign the Safe-wrapped hash of a digest (ERC-1271 owner signature).

        Agent-mode off-chain requests are verified with
        ``Safe.isValidSignature``, so mech-client hands the request id here
        to be wrapped and signed (``Signer.sign_safe_message`` contract).
        The wrap is computed by the same safe_message_hash the mech flow
        registered its allowance with, and the signature still goes through
        Signer.sign_digest — same choke point, same guardrail.
        """
        wrapped = safe_message_hash(safe_address, chain_id, bytes(message))
        signature = self._signer.sign_digest(wrapped)
        return bytes.fromhex(signature.removeprefix("0x"))
