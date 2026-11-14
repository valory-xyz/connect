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

"""The failures a send reports, in Connect's own words.

Split out of connect/signer.py for pylint's line limit; `from connect.signer
import SignerError` still resolves.
"""

from web3.exceptions import ContractLogicError, Web3RPCError


class SignerError(Exception):
    """Signing or broadcast failure."""


class SendUnknown(SignerError):
    """A broadcast the RPC never answered: it may have landed, as `tx_hash`.

    The hash is the signed bytes', known before the broadcast, so the request
    id it was sent under keeps it (`held`): a retry raises this again rather
    than signing a second transaction at the next nonce.
    """

    def __init__(self, tx_hash: str, held: bool) -> None:
        """Initialize."""
        super().__init__(tx_hash, held)
        self.tx_hash = tx_hash
        self.held = held

    def __str__(self) -> str:
        """Return the error a caller reads."""
        return _send_unknown_words(self.tx_hash, held=self.held)


# What a caller is told of a failure that is not one of Connect's refusals:
# Connect's own words, never the library's, which may name the RPC URL and its
# key (urllib3 writes "with url: /v2/<key>"); the cause goes to the log.
SEND_FAILED = (
    "send failed: the RPC could not take the transaction (the cause is in "
    "Connect's log)"
)
# the broadcast itself failed with no answer from the RPC: it may have landed
SEND_UNKNOWN = "send failed while broadcasting: the transaction may have been sent"


def _send_unknown_words(tx_hash: str, *, held: bool) -> str:
    """Return SEND_UNKNOWN for `tx_hash`; only a `held` request id promises a replay."""
    said = f"{SEND_UNKNOWN} as {tx_hash} (the cause is in Connect's log); "
    if held:
        return said + (
            "its request_id stays held with that hash, so a retry under it "
            "sends nothing and answers this again; read the hash's receipt "
            "(transaction_status) before sending under a new id"
        )
    return said + (
        "read the hash's receipt (transaction_status) or the account's nonce "
        "before sending again"
    )


def send_failure(error: Exception, *, broadcasting: bool) -> str:
    """Return what a caller is told of a failed send.

    A revert in gas estimation is the contract's own answer, so its reason
    stays (the shipped client reads it as reverted before signing). A
    broadcast that failed without the RPC's answer (a timeout, a dropped
    connection) is SEND_UNKNOWN; anything else is SEND_FAILED.
    """
    if isinstance(error, ContractLogicError):
        reason = str(error.message or "execution reverted")
        if "execution reverted" not in reason:
            reason = f"execution reverted: {reason}"
        return f"send failed: {reason}"
    if broadcasting and not isinstance(error, (Web3RPCError, ValueError)):
        return SEND_UNKNOWN
    return SEND_FAILED
