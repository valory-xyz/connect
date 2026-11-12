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
from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from web3.exceptions import TimeExhausted, TransactionNotFound

from connect import chain_read
from connect import intent as intent_module
from connect import settings as settings_config
from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import DEFAULT_RESULT_TIMEOUT, MechService
from connect.server.auth import VALUE_CAPPED
from connect.server.strict import make_tools_strict
from connect.settings import SettingsStore
from connect.signer import Signer

RECEIPT_POLL_SECONDS = 2
# tools that read and never sign, broadcast or pay: harnesses may run them
# without asking the operator
READ_ONLY = ToolAnnotations(readOnlyHint=True)
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

    @mcp.tool(annotations=READ_ONLY)
    async def wallet_info() -> dict:
        """Agent EOA and per-chain safes and native token balances.

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
        intent: dict | None = None,
        ctx: Context | None = None,
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
        `intent` is required whenever the call moves value (spends or sends
        anything of the safe's, or grants an approval): {spend: {token: max},
        receive_min: {token: min}, recipients: [eoa, ...], approvals: [{token,
        spender, amount}]}, tokens as lower-case addresses or "native", amounts
        in base units. The call is simulated before it is signed and refused,
        naming the rule, if it would do more than the intent allows.
        """
        return await _dispatch(
            signer.send_via_safe,
            signer,
            chain=chain,
            address=target,
            value=value,
            data=data,
            intent=_for_token(ctx, intent),
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
        intent: dict | None = None,
        ctx: Context | None = None,
        request_id: str | None = None,
        wait_for_receipt: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Sign and broadcast a transaction from the agent EOA — the rarer path.

        `to` is the EOA's own recipient, not a call the safe makes, and the
        EOA's funds are for gas: to spend or act on-chain use safe_transaction.
        Returns, request_id and `intent` semantics are safe_transaction's.
        """
        return await _dispatch(
            signer.send,
            signer,
            chain=chain,
            address=to,
            value=value,
            data=data,
            intent=_for_token(ctx, intent),
            request_id=request_id,
            wait_for_receipt=wait_for_receipt,
            timeout=timeout,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def preflight_transaction(
        chain: str,
        target: str,
        value: int = 0,
        data: str = "0x",
        *,
        via_safe: bool = True,
        intent: dict | None = None,
        ctx: Context | None = None,
    ) -> dict:
        """Ask whether a call would be permitted, before you build on it.

        Takes what safe_transaction takes (or send_transaction's, with
        via_safe=false) and answers {allowed}, plus the same `reason` the real
        call would have refused with. Nothing is signed, broadcast or paid for.
        `allowed` means the guardrail and the intent gate permit these bytes
        at head — with the `intent` you give, as the real call would be
        checked; any `problems` name the gate's rules.
        """
        reason, problems = await asyncio.to_thread(
            signer.check,
            chain,
            target,
            value=value,
            data=data,
            via_safe=via_safe,
            intent=_for_token(ctx, intent),
        )
        if reason is None:
            return {"allowed": True}
        result: dict = {"allowed": False, "reason": reason}
        if problems:
            result["problems"] = problems
        return result

    @mcp.tool(annotations=READ_ONLY)
    async def simulate_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        target: str,
        value: int = 0,
        data: str = "0x",
        *,
        via_safe: bool = True,
        intent: dict | None = None,
        ctx: Context | None = None,
    ) -> dict:
        """Simulate a call at head and say what it does to the safe's assets.

        Returns the asset diff — `native` and `tokens` deltas (each token with
        its `symbol`, display only), `recipients`
        (each with `contract`), `approvals`, ERC-721/1155 `positions`,
        `called` (the target plus every contract that emitted a log; one
        called without emitting is not listed), `revert`, `gas_used` — with
        `fits_intent` (null without an intent) and the `problems` the send
        would be refused for. Nothing is signed. via_safe=false simulates
        send_transaction's call from the EOA.
        """
        return await asyncio.to_thread(
            signer.simulate,
            chain,
            target,
            value=value,
            data=data,
            via_safe=via_safe,
            intent=_for_token(ctx, intent),
        )

    @mcp.tool(annotations=READ_ONLY)
    async def chain_call(chain: str, to: str, data: str, block: str = "latest") -> dict:
        """Read a contract with eth_call: {result} or {reverted, reason}."""
        return await asyncio.to_thread(
            chain_read.chain_call, signer.w3(chain), to, data, block
        )

    @mcp.tool(annotations=READ_ONLY)
    async def get_abi(chain: str, address: str) -> dict:
        """Report what Connect can say about a contract's ABI, following EIP-1967.

        Only ABIs Connect ships: well-known contracts by address (`verified`)
        and the standard interfaces a contract answers to; no explorer lookup.
        """
        return await asyncio.to_thread(chain_read.get_abi, signer.w3(chain), address)

    @mcp.tool(annotations=READ_ONLY)
    async def decode_calldata(chain: str, data: str) -> dict:
        """Decode calldata against the signatures Connect ships.

        Returns {selector, signature, args}, or {selector, error} for a
        selector Connect does not know. `chain` is accepted for symmetry with
        the other read tools; decoding needs no RPC.
        """
        return chain_read.decode_calldata(data)

    @mcp.tool(annotations=READ_ONLY)
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
        max_payment: int | None = None,
        request_id: str | None = None,
        request_context: dict | None = None,
    ) -> dict:
        """Send a request to an Olas mech (AI service) and wait for its delivery.

        The safe pays, so `chain` defaults to a configured chain that has one.
        Off-chain by default: few mechs can serve that, so check
        `offchain_capable` with mech_tools first; legacy_on_chain=true goes
        through the marketplace instead.
        Off-chain the report also carries mech-client's `operator`,
        `delivery`, `payment` and `benchmarks`, decided before paying.
        Refused before paying if the mech's price exceeds max_payment
        (base units of the mech's payment asset, default 0.1 of that asset;
        mech_tools reports the asset as payment_token).
        On timeout the ids come back as `pending_request_ids` for mech_result.
        `request_id` is an id you invent before sending (not one of the
        `request_ids` that come back): repeating it never sends again — it
        resumes that request and returns its report marked `replayed`. Choose
        one whenever you would not want to pay twice to find out what
        happened; a request that failed after payment refuses replay and says
        so, since only you can decide to risk a second payment.
        `request_context` is an optional dict handed to the tool alongside the
        prompt. The trader sends `market_id`, `type`, `description`,
        `market_prob`, `market_close_at`, `market_liquidity_usd`, `amm_fee`
        and `market_spread`, dropping any it has no value for; each is
        optional and ignored by a tool that does not read it. It reaches the
        mech, and legacy_on_chain=true also publishes it to IPFS for good —
        put nothing private in it.
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
            request_context=request_context,
        )

    @mcp.tool(annotations=READ_ONLY)
    async def mech_result(
        request_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT
    ) -> dict:
        """Check whether a mech has since answered a request whose wait timed out.

        Poll the ids from `pending_request_ids`. Already paid for, so this
        resumes the watch and never resends. Returns {delivered, result}; a
        restart of this server clears what can be polled.
        """
        return await asyncio.to_thread(mech.result, request_id, timeout=timeout)

    @mcp.tool(annotations=READ_ONLY)
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
        and `offchain_note` says why. The report also carries mech-client's
        `operator`, `delivery`, `payment` and `benchmarks`.
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

        @mcp.tool(annotations=READ_ONLY)
        async def settings() -> dict:
            """Read the enforced settings in their canonical shape.

            "protected" is the guardrail state. Read-only: changes go through
            the operator's agent UI, never this surface.
            """
            return await asyncio.to_thread(lambda: settings_store.load().to_dict())

    # a parameter a tool does not take is refused by name, never dropped
    make_tools_strict(mcp, activity)
    return mcp


def _for_token(ctx: Context | None, intent: dict | None) -> t.Any:
    """Return the intent the gate holds this call to, for the calling token.

    The MCP mount marks a value-capped token's request; its intent is then
    `intent.Capped`, so the gate refuses any position the call moves out.
    """
    try:
        request = ctx.request_context.request if ctx is not None else None
    except ValueError:  # no request: called in-process, not through the mount
        request = None
    state = getattr(request, "state", None)
    if getattr(state, VALUE_CAPPED, False):
        return intent_module.Capped(intent)
    return intent


async def _dispatch(  # pylint: disable=too-many-arguments
    method: t.Callable[..., str],
    signer: Signer,
    *,
    chain: str,
    address: str,
    value: int,
    data: str,
    intent: t.Any,
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
        tx_hash = method(
            chain,
            address,
            value=value,
            data=data,
            request_id=request_id,
            intent=intent,
        )
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
