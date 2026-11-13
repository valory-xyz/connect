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

"""How a sent transaction settled: the receipt wait both send surfaces share.

The MCP send tools and the HTTP send routes are sibling adapters over the
signer; neither imports the other, so what they both answer lives here.
"""

import typing as t

from hexbytes import HexBytes
from web3.exceptions import TimeExhausted

from connect.signer import Signer

RECEIPT_POLL_SECONDS = 2
MAX_RECEIPT_TIMEOUT = 300


def settled(
    signer: Signer,
    chain: str,
    tx_hash: str,
    wait_for_receipt: bool,
    timeout: int,
) -> dict:
    """Return the hash, and how it settled if the caller waited.

    When the caller waits, a top-level `status` says which of pending / mined /
    reverted it is, so a reverted execTransaction is not read as success from a
    receipt whose 0/1 is buried a level down. And once the transaction is
    broadcast the hash is never dropped: a post-send RPC error is reported as
    still-pending, not as a failure that would invite a double-spending resend.
    """
    if not wait_for_receipt:
        return {"tx_hash": tx_hash}
    try:
        receipt = signer.w3(chain).eth.wait_for_transaction_receipt(
            HexBytes(tx_hash),
            timeout=min(timeout, MAX_RECEIPT_TIMEOUT),
            poll_latency=RECEIPT_POLL_SECONDS,
        )
        # inside the try on purpose: reading the receipt must not drop the hash
        # either, so a malformed one is reported pending, not raised
        return mined_result(tx_hash, receipt)
    except TimeExhausted:
        return {"tx_hash": tx_hash, "status": "pending"}
    except Exception as e:  # pylint: disable=broad-exception-caught
        # the send already happened; a receipt-read hiccup must not lose the hash
        return {"tx_hash": tx_hash, "status": "pending", "receipt_error": str(e)}


def mined_result(tx_hash: str, receipt: t.Mapping[str, t.Any]) -> dict:
    """Return a settled receipt with `mined`/`reverted` lifted to a top-level status.

    Every tool that hands back a mined receipt goes through here, so a caller
    reads one field to tell success from a revert — the 0/1 is never left buried
    in the receipt for one tool while another surfaces it.
    """
    info = _receipt_to_dict(receipt)
    return {
        "tx_hash": tx_hash,
        "status": "mined" if info["status"] == 1 else "reverted",
        "receipt": info,
    }


def _receipt_to_dict(receipt: t.Mapping[str, t.Any]) -> dict:
    return {
        "status": receipt["status"],
        "block_number": receipt["blockNumber"],
        "gas_used": receipt["gasUsed"],
        "logs": len(receipt["logs"]),
    }
