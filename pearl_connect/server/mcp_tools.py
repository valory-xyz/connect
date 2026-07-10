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

"""MCP tools for the Claude Code session — thin adapters over the signer/wallet.

Tool handlers execute on the server's event loop (the MCP SDK calls sync
tools inline), so every blocking body is pushed to a worker thread via
asyncio.to_thread: slow RPC calls and receipt waits must not stall the loop
that also serves the Pearl endpoints.
"""

import asyncio
import typing as t

from hexbytes import HexBytes
from mcp.server.fastmcp import FastMCP
from web3.exceptions import TimeExhausted, TransactionNotFound

from pearl_connect import wallet
from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig
from pearl_connect.signer import Signer

RECEIPT_POLL_SECONDS = 2
MAX_RECEIPT_TIMEOUT = 300


def build_mcp(  # pylint: disable=unused-argument
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
) -> FastMCP:
    """Build mcp."""
    mcp = FastMCP(
        name="pearl-connect",
        instructions=(
            "Signing service for this Pearl agent. The agent EOA and per-chain "
            "service safes are shown by wallet_info. Every on-chain action is an "
            "EOA transaction sent via send_transaction; safe transactions are "
            "composed as execTransaction calls with the pre-validated signature "
            "(see the pearl-connect skill)."
        ),
        stateless_http=True,
        streamable_http_path="/",
    )

    @mcp.tool()
    async def wallet_info() -> dict:
        """Agent EOA, per-chain service safes, RPC URLs and balances."""
        return await asyncio.to_thread(wallet.wallet_overview, config, signer)

    @mcp.tool()
    async def send_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        to: str,
        value: int = 0,
        data: str = "0x",
        *,
        request_id: str | None = None,
        wait_for_receipt: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Sign and broadcast a transaction from the agent EOA on the given chain.

        Returns {tx_hash}; with wait_for_receipt, also the receipt if it mines
        within `timeout` seconds, else {tx_hash, status: "pending"}.

        When retrying a send whose outcome you are unsure about, pass the same
        request_id as the original attempt: the signer will return the original
        tx_hash instead of broadcasting a duplicate transaction.
        """
        if value < 0:
            raise ValueError("value must be a non-negative amount in wei")

        def _run() -> dict:
            tx_hash = signer.send(
                chain=chain, to=to, value=value, data=data, request_id=request_id
            )
            if not wait_for_receipt:
                return {"tx_hash": tx_hash}
            w3 = signer.w3(chain)
            try:
                receipt = w3.eth.wait_for_transaction_receipt(
                    HexBytes(tx_hash),
                    timeout=min(timeout, MAX_RECEIPT_TIMEOUT),
                    poll_latency=RECEIPT_POLL_SECONDS,
                )
            except TimeExhausted:
                return {"tx_hash": tx_hash, "status": "pending"}
            return {"tx_hash": tx_hash, "receipt": _receipt_to_dict(receipt)}

        return await asyncio.to_thread(_run)

    @mcp.tool()
    async def transaction_status(chain: str, tx_hash: str) -> dict:
        """Receipt for a transaction if mined, else {status: "pending"}.

        A malformed hash or a failing RPC raises instead of reporting
        "pending" — a hash that can never resolve must not be polled forever.
        """
        try:
            valid = len(bytes.fromhex(tx_hash.removeprefix("0x"))) == 32
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("tx_hash must be a 0x-prefixed 32-byte hex string")

        def _run() -> dict:
            w3 = signer.w3(chain)
            try:
                receipt = w3.eth.get_transaction_receipt(HexBytes(tx_hash))
            except TransactionNotFound:
                return {"tx_hash": tx_hash, "status": "pending"}
            return {"tx_hash": tx_hash, "receipt": _receipt_to_dict(receipt)}

        return await asyncio.to_thread(_run)

    @mcp.tool()
    async def sign_message(digest: str) -> dict:
        """Sign a raw 32-byte digest (0x-hex), unprefixed — for off-chain mech requests."""
        try:
            raw = bytes.fromhex(digest.removeprefix("0x"))
        except ValueError as e:
            raise ValueError(f"digest must be a 0x-hex string: {e}") from e
        return {"signature": await asyncio.to_thread(signer.sign_digest, raw)}

    return mcp


def _receipt_to_dict(receipt: t.Mapping[str, t.Any]) -> dict:
    return {
        "status": receipt["status"],
        "block_number": receipt["blockNumber"],
        "gas_used": receipt["gasUsed"],
        "logs": len(receipt["logs"]),
    }
