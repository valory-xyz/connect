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

from connect import settings as settings_config
from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import DEFAULT_MAX_PAYMENT, DEFAULT_RESULT_TIMEOUT, MechService
from connect.settings import SettingsStore
from connect.signer import Signer

RECEIPT_POLL_SECONDS = 2
MAX_RECEIPT_TIMEOUT = 300


def build_mcp(  # pylint: disable=unused-argument, too-many-arguments, too-many-locals
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    guard: Guard,
    mech: MechService,
    settings_store: SettingsStore,
) -> FastMCP:
    """Build mcp."""
    # Read once per build: tool registration happens here while wallet_info's
    # mode key is added per call, and one snapshot keeps the MCP surface
    # internally consistent (a registered `settings` tool always comes with
    # the wallet_info mode key). GET /wallet reads the flag per request —
    # the constant only changes with a rebuild, so the surfaces cannot
    # actually diverge in a running process.
    expose_mode = settings_config.EXPOSE_MODE_TO_AGENT
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
        """Agent EOA and per-chain safes and balances.

        Act only on `actionable_chains`; the rest say `not_actionable_because`.
        """

        def _run() -> dict:
            overview = wallet.wallet_overview(config, signer)
            if expose_mode:
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

        `target`/`value`/`data` are the call the safe makes; any value carried
        leaves the safe, not the EOA. Returns {tx_hash}, plus a top-level
        `status` (mined / reverted / pending) and the receipt when
        wait_for_receipt. Reusing a request_id replays the original tx_hash
        instead of spending twice.
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

        `to` is the EOA's own recipient, not a call the safe makes, and the
        EOA's funds are for gas: to spend or act on-chain use safe_transaction.
        Returns and request_id semantics are safe_transaction's.
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
    async def preflight_transaction(
        chain: str,
        target: str,
        value: int = 0,
        data: str = "0x",
        *,
        via_safe: bool = True,
    ) -> dict:
        """Ask whether a call would be permitted, before you build on it.

        Takes what safe_transaction takes (or send_transaction's, with
        via_safe=false) and answers {allowed}, plus the same `reason` the real
        call would have refused with. Nothing is signed, broadcast or paid for.
        `allowed` means the guardrail permits these bytes — not that the call
        will succeed on-chain, which only sending finds out.
        """
        reason = await asyncio.to_thread(
            signer.refusal_reason,
            chain,
            target,
            value=value,
            data=data,
            via_safe=via_safe,
        )
        if reason is None:
            return {"allowed": True}
        return {"allowed": False, "reason": reason}

    @mcp.tool()
    async def transaction_status(chain: str, tx_hash: str) -> dict:
        """Settlement of a transaction: mined / reverted / pending.

        A malformed hash or a failing RPC raises rather than reporting
        "pending": a hash that can never resolve must not be polled forever.
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
        """Sign a raw 32-byte digest (0x-hex), unprefixed.

        The off-chain mech flow does not use this tool: it signs its own
        SafeMessage-wrapped request-id digest internally, through a
        server-only allowance that no MCP tool reaches.
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
        request_id: str | None = None,
    ) -> dict:
        """Send a request to an Olas mech (AI service) and wait for its delivery.

        The safe pays, so `chain` defaults to a configured chain that has one.
        Off-chain by default: few mechs can serve that, so check
        `offchain_capable` with mech_tools first; legacy_on_chain=true goes
        through the marketplace instead.
        Refused before paying if the mech's price exceeds max_payment
        (base units of the mech's payment asset).
        On timeout the ids come back as `pending_request_ids` for mech_result.
        `request_id` is an id you invent before sending (not one of the
        `request_ids` that come back): repeating it never sends again — it
        resumes that request and returns its report marked `replayed`. Choose
        one whenever you would not want to pay twice to find out what
        happened; a request that failed after payment refuses replay and says
        so, since only you can decide to risk a second payment.
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
            request_id=request_id,
        )

    @mcp.tool()
    async def mech_result(
        request_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT
    ) -> dict:
        """Check whether a mech has since answered a request whose wait timed out.

        Poll the ids from `pending_request_ids`. Already paid for, so this
        resumes the watch and never resends. Returns {delivered, result}; a
        restart of this server clears what can be polled.
        """
        return await asyncio.to_thread(mech.result, request_id, timeout=timeout)

    @mcp.tool()
    async def mech_tools(
        chain: str | None = None,
        priority_mech: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """Discover Olas mechs and the tools they serve, for use with mech_request.

        Without priority_mech: a page of live mechs, most deliveries first
        (`total` says how many exist). With it: that mech's payment type,
        service id, tool names for mech_request's `tool`, and
        `offchain_capable` — false means only legacy_on_chain=true reaches it,
        and `offchain_note` says why.
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

    if expose_mode:

        @mcp.tool()
        async def settings() -> dict:
            """Read the enforced settings in their canonical shape.

            "protected" is the guardrail state. Read-only: changes go through
            the operator's agent UI, never this surface.
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
