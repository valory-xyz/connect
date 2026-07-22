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

from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import DEFAULT_MAX_PAYMENT, MechService
from connect.settings import SettingsStore
from connect.signer import Signer

RECEIPT_POLL_SECONDS = 2
MAX_RECEIPT_TIMEOUT = 300


def build_mcp(  # pylint: disable=unused-argument, too-many-arguments
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    guard: Guard,
    mech: MechService,
    settings_store: SettingsStore,
) -> FastMCP:
    """Build mcp."""
    mcp = FastMCP(
        name="connect",
        instructions=(
            "Signing service for this Pearl agent: it holds the key, you name "
            "the actions. Act on-chain with safe_transaction; a guardrail may "
            "refuse, and every refusal names the rule it violated."
        ),
        stateless_http=True,
        streamable_http_path="/",
    )

    @mcp.tool()
    async def wallet_info() -> dict:
        """Agent EOA, guard mode, and per-chain safes and balances.

        Act only on `actionable_chains` (safe + gas, usually one); the rest
        give a `not_actionable_because`.
        """

        def _run() -> dict:
            overview = wallet.wallet_overview(config, signer)
            overview["mode"] = guard.mode()
            return overview

        return await asyncio.to_thread(_run)

    @mcp.tool()
    async def safe_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        target: str,
        value: int = 0,
        data: str = "0x",
        *,
        request_id: str | None = None,
        wait_for_receipt: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Make the service safe call `target` — the normal way to act on-chain.

        The safe is the agent's on-chain identity: approvals, swaps, stakes,
        claims and transfers are all calls it makes. `target`, `value` and
        `data` are that call — most carry no value at all; any they do carry
        leaves the safe, not the EOA. The server composes the safe's transaction
        around it. Prefer this over send_transaction, whose `to` is the EOA's
        own outer recipient — a different account with different funds.

        Returns {tx_hash}; with wait_for_receipt, also a top-level `status`
        (mined / reverted / pending) and the receipt. Retrying with the same
        request_id returns the original tx_hash rather than acting twice.
        """
        return await _dispatch(
            signer.send_via_safe,
            signer,
            chain=chain,
            address=target,
            value=value,
            data=data,
            request_id=request_id,
            wait_for_receipt=wait_for_receipt,
            timeout=timeout,
        )

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
        """Sign and broadcast a transaction from the agent EOA — the rarer path.

        `to` is the EOA's own outer recipient, not a call the safe makes; the
        EOA's funds are for gas. For spending or acting on-chain, use
        safe_transaction instead. In restricted mode this can reach nothing but
        the safe.

        Returns {tx_hash}; with wait_for_receipt, also a top-level `status`
        (mined / reverted / pending) and the receipt. Retrying with the same
        request_id returns the original tx_hash instead of a duplicate.
        """
        return await _dispatch(
            signer.send,
            signer,
            chain=chain,
            address=to,
            value=value,
            data=data,
            request_id=request_id,
            wait_for_receipt=wait_for_receipt,
            timeout=timeout,
        )

    @mcp.tool()
    async def transaction_status(chain: str, tx_hash: str) -> dict:
        """Settlement of a transaction: mined / reverted / pending.

        The same top-level `status` the send tools return, so a tx polled here
        after a send is read the same way — a revert is not mistaken for success.
        A malformed hash or a failing RPC raises instead of reporting "pending":
        a hash that can never resolve must not be polled forever.
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
            return _mined_result(tx_hash, receipt)

        return await asyncio.to_thread(_run)

    @mcp.tool()
    async def sign_message(digest: str) -> dict:
        """Sign a raw 32-byte digest (0x-hex), unprefixed — for off-chain mech requests.

        Unavailable in restricted mode (the guardrail cannot inspect what a
        digest commits to).
        """
        try:
            raw = bytes.fromhex(digest.removeprefix("0x"))
        except ValueError as e:
            raise ValueError(f"digest must be a 0x-hex string: {e}") from e
        return {"signature": await asyncio.to_thread(signer.sign_digest, raw)}

    @mcp.tool()
    async def mech_request(  # pylint: disable=too-many-arguments
        prompt: str,
        tool: str,
        chain: str | None = None,
        *,
        legacy_on_chain: bool = False,
        priority_mech: str | None = None,
        auto_deposit: bool = True,
        timeout: float = 300,
        max_payment: int = DEFAULT_MAX_PAYMENT,
    ) -> dict:
        """Send a request to an Olas mech (AI service) and wait for its delivery.

        By default the request goes off-chain (prepaid balance, no transaction;
        needs unrestricted mode) — but only mechs whose operator published an
        endpoint can serve it, and few do, so check `offchain_capable` with
        mech_tools first. With legacy_on_chain=true it is sent on-chain
        through the mech marketplace via the service safe — this works in
        restricted mode because the mech contracts are whitelisted by default.
        chain defaults to a configured chain that has a service safe, since the
        safe is what pays. auto_deposit tops up the prepaid balance from the
        safe when the mech answers 402 (insufficient balance) and retries once.
        A request is refused if the mech's per-request price exceeds max_payment
        (wei, default 0.1 of the native unit) — raise it explicitly to accept a
        more expensive mech.
        """
        # mech-client manages its own event loops (asyncio.run + sync gql):
        # it must run in a worker thread, never on the server loop
        return await asyncio.to_thread(
            mech.request,
            prompt,
            tool,
            chain=chain,
            legacy_on_chain=legacy_on_chain,
            priority_mech=priority_mech,
            auto_deposit=auto_deposit,
            timeout=timeout,
            max_payment=max_payment,
        )

    @mcp.tool()
    async def mech_tools(
        chain: str | None = None,
        priority_mech: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """Discover Olas mechs and the tools they serve, for use with mech_request.

        Without priority_mech: a page of live marketplace mechs (most
        deliveries first; `total` reports how many exist — page with
        limit/offset). With priority_mech: that mech's payment type, service
        id and available tool names — pass one as mech_request's `tool`
        argument (limit/offset are ignored then) — plus `offchain_capable`,
        which says whether the default off-chain flow can reach it at all; when
        it is false, `offchain_note` gives the reason and mech_request needs
        legacy_on_chain=true. chain defaults to a configured chain with a safe.
        """
        # same as mech_request: the sync gql subgraph client refuses to run
        # on an already-running loop
        return await asyncio.to_thread(
            mech.tools,
            chain=chain,
            priority_mech=priority_mech,
            limit=limit,
            offset=offset,
        )

    @mcp.tool()
    async def settings() -> dict:
        """Read the enforced settings in their canonical shape.

        The "protected" object is the guardrail state. Read-only: changes
        go through the operator's agent UI, never through this MCP surface.
        """
        return await asyncio.to_thread(lambda: settings_store.load().to_dict())

    return mcp


async def _dispatch(  # pylint: disable=too-many-arguments
    method: t.Callable[..., str],
    signer: Signer,
    *,
    chain: str,
    address: str,
    value: int,
    data: str,
    request_id: str | None,
    wait_for_receipt: bool,
    timeout: int,
) -> dict:
    """Validate, run one signer method off the event loop, and settle it.

    The two send tools differ only in which signer method acts and what its
    address means (EOA recipient vs. the safe's call target); everything else —
    the value guard, the worker-thread offload, the settle — is shared here.
    """
    if value < 0:
        raise ValueError("value must be a non-negative amount in wei")

    def _run() -> dict:
        tx_hash = method(chain, address, value=value, data=data, request_id=request_id)
        return _settled(signer, chain, tx_hash, wait_for_receipt, timeout)

    return await asyncio.to_thread(_run)


def _settled(
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
        return _mined_result(tx_hash, receipt)
    except TimeExhausted:
        return {"tx_hash": tx_hash, "status": "pending"}
    except Exception as e:  # pylint: disable=broad-exception-caught
        # the send already happened; a receipt-read hiccup must not lose the hash
        return {"tx_hash": tx_hash, "status": "pending", "receipt_error": str(e)}


def _mined_result(tx_hash: str, receipt: t.Mapping[str, t.Any]) -> dict:
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
