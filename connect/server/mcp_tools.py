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
import logging
import typing as t

from hexbytes import HexBytes
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BeforeValidator, ConfigDict, Field, with_config
from typing_extensions import TypedDict
from web3.exceptions import TransactionNotFound

from connect import chain_read
from connect import settings as settings_config
from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard, GuardError
from connect.idempotency import InFlightError
from connect.intent import AgentIntent, parse_amount, parse_tool_amount
from connect.mech import DEFAULT_RESULT_TIMEOUT, MechError, MechService
from connect.mech_allowances import TopUpBudget
from connect.server.auth import (
    GrantRefused,
    GrantStore,
    is_replay,
    request_token,
)
from connect.server.receipts import mined_result, not_found, settled
from connect.server.strict import make_tools_strict
from connect.settings import SettingsStore
from connect.signer import Signer, SignerError
from connect.signer_errors import logged_cause
from connect.switches import PRODUCTION, Switches
from connect.texts import SERVER_INFO, TOOL_DESCRIPTIONS, UNKNOWN_TOOL

# tools that read and never sign, broadcast or pay: harnesses may run them
# without asking the operator
READ_ONLY = ToolAnnotations(readOnlyHint=True)


def _amount_text(value: t.Any) -> str:
    """Read a base-unit amount as `intent.parse_tool_amount` reads it, as a string.

    :raises ValueError: naming the rule, `bad-value`, for anything else.
    """
    try:
        return str(parse_tool_amount(value))
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"rule 'bad-value': {e}; pass a decimal or 0x-hex string of base "
            f"units (got {value!r})"
        ) from e


# a base-unit amount on the tool surface: declared a string, so a client
# that cannot hold the number exactly can still pass it exactly
Amount = t.Annotated[
    str,
    BeforeValidator(_amount_text),
    Field(description="base units, as a decimal or 0x-hex string"),
]


def _cap_text(value: t.Any) -> str:
    """Read a base-unit cap as `intent.parse_amount` reads it, as a string.

    A cap bounds a price that is checked exactly and is never itself spent,
    so a JSON integer of any size is taken.

    :raises ValueError: naming the rule, `bad-value`, for anything else.
    """
    try:
        return str(parse_amount(value))
    except (TypeError, ValueError) as e:
        raise ValueError(
            f"rule 'bad-value': {e}; pass a whole number of base units, as an "
            f"integer or a decimal or 0x-hex string (got {value!r})"
        ) from e


# a base-unit cap on the tool surface: a string or any whole JSON integer
Cap = t.Annotated[
    str,
    BeforeValidator(_cap_text),
    Field(description="base units, as an integer or a decimal or 0x-hex string"),
]


# Extra keys are kept for `intent.parse_intent`, the one judge of an intent's
# shape, which refuses them by name; these types only declare the amounts.
@with_config(ConfigDict(extra="allow"))
class ToolApproval(TypedDict, total=False):
    """One approval an intent allows the call to grant."""

    token: str
    spender: str
    amount: Amount


@with_config(ConfigDict(extra="allow"))
class ToolIntent(TypedDict, total=False):
    """What a call may do; tokens are addresses or "native", amounts `Amount`s."""

    spend: dict[str, Amount] | None
    receive_min: dict[str, Amount] | None
    recipients: list[str] | None
    approvals: list[ToolApproval] | None


# the tools whose `target` may be passed as `to`, as the reference accepts it
TOOLS_TAKING_TO_FOR_TARGET = frozenset(
    {"safe_transaction", "preflight_transaction", "simulate_transaction"}
)

# errors whose text Connect wrote for the caller; any other is a library's or
# a bug's, which may carry an RPC URL and key, so it is logged, not forwarded
CALLER_ERRORS: tuple[type[Exception], ...] = (
    ValueError,
    SignerError,
    GuardError,
    GrantRefused,
    MechError,
    InFlightError,
)
TOOL_FAILED = "{tool} failed (the cause is in Connect's log)"

logger = logging.getLogger("agent")


def with_aliases(tool: str, arguments: dict[str, t.Any]) -> dict[str, t.Any]:
    """Return a tool's arguments with `to` read as `target` where it aliases it.

    `target` wins when both are given, as in the reference.
    """
    if tool not in TOOLS_TAKING_TO_FOR_TARGET or "to" not in arguments:
        return arguments
    aliased = {k: v for k, v in arguments.items() if k != "to"}
    aliased.setdefault("target", arguments["to"])
    return aliased


class ConnectMCP(FastMCP):
    """FastMCP with the reference's call boundary.

    A tool's error reaches the agent as the text the refusing code wrote:
    FastMCP prepends `Error executing tool <name>: ` to every raised error,
    which would hide the markers the bench's broker reads.
    """

    def __init__(self, **settings: t.Any) -> None:
        """Build the server, reporting the reference's serverInfo version."""
        super().__init__(**settings)
        # FastMCP takes no version; unset, the MCP SDK reports its own
        self._mcp_server.version = SERVER_INFO["version"]

    async def call_tool(self, name: str, arguments: dict[str, t.Any]) -> t.Any:
        """Call a tool, raising its own error text with no transport prefix."""
        if self._tool_manager.get_tool(name) is None:
            raise ToolError(UNKNOWN_TOOL(name))
        try:
            return await super().call_tool(name, with_aliases(name, arguments))
        except ToolError as e:
            cause = e.__cause__ or e
            if isinstance(cause, (ToolError, *CALLER_ERRORS)):
                raise ToolError(str(cause)) from cause
            logger.error("tool %s failed: %s", name, logged_cause(cause))
            raise ToolError(TOOL_FAILED.format(tool=name)) from cause


def build_mcp(  # pylint: disable=unused-argument, too-many-arguments, too-many-locals
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    guard: Guard,
    mech: MechService,
    settings_store: SettingsStore,
    grants: GrantStore,
    switches: Switches = PRODUCTION,
) -> FastMCP:
    """Build mcp."""
    # Read once per build: tool registration happens here while wallet_info's
    # mode key is added per call, and one snapshot keeps the MCP surface
    # internally consistent (a registered `settings` tool always comes with
    # the wallet_info mode key). GET /wallet reads the flag per request —
    # the constant only changes with a rebuild, so the surfaces cannot
    # actually diverge in a running process.
    expose_mode = settings_config.EXPOSE_MODE_TO_AGENT
    # no instructions at initialize: the reference sends none
    mcp = ConnectMCP(
        name=SERVER_INFO["name"], stateless_http=True, streamable_http_path="/"
    )

    @mcp.tool(description=TOOL_DESCRIPTIONS["wallet_info"], annotations=READ_ONLY)
    async def wallet_info() -> dict:
        """Report the EOA, the safes and their balances."""

        def _run() -> dict:
            overview = wallet.wallet_overview(config, signer)
            if expose_mode:
                overview["mode"] = guard.mode()
            return overview

        return await asyncio.to_thread(_run)

    @mcp.tool(description=TOOL_DESCRIPTIONS["safe_transaction"])
    async def safe_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        target: str,
        value: Amount = "0",
        data: str = "0x",
        *,
        intent: ToolIntent | None = None,
        ctx: Context | None = None,
        request_id: str | None = None,
        wait_for_receipt: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Have the service safe make one call."""
        return await _dispatch(
            signer.send_via_safe,
            signer,
            chain=chain,
            address=target,
            value=value,
            data=data,
            intent=_for_token(grants, ctx, intent),
            request_id=request_id,
            replay_only=is_replay(_ctx_request(ctx), "safe_transaction", request_id),
            wait_for_receipt=wait_for_receipt,
            timeout=timeout,
        )

    @mcp.tool(description=TOOL_DESCRIPTIONS["send_transaction"])
    async def send_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        to: str,
        value: Amount = "0",
        data: str = "0x",
        *,
        intent: ToolIntent | None = None,
        ctx: Context | None = None,
        request_id: str | None = None,
        wait_for_receipt: bool = False,
        timeout: int = 60,
    ) -> dict:
        """Send one transaction from the agent EOA."""
        return await _dispatch(
            signer.send,
            signer,
            chain=chain,
            address=to,
            value=value,
            data=data,
            intent=_for_token(grants, ctx, intent),
            request_id=request_id,
            replay_only=is_replay(_ctx_request(ctx), "send_transaction", request_id),
            wait_for_receipt=wait_for_receipt,
            timeout=timeout,
        )

    @mcp.tool(
        description=TOOL_DESCRIPTIONS["preflight_transaction"], annotations=READ_ONLY
    )
    async def preflight_transaction(
        chain: str,
        target: str,
        value: Amount = "0",
        data: str = "0x",
        *,
        via_safe: bool = True,
        ctx: Context | None = None,
    ) -> dict:
        """Answer the guardrail's verdict on a call; nothing is simulated."""
        refused = _token_refusal(
            grants,
            ctx,
            "safe_transaction" if via_safe else "send_transaction",
            {"chain": chain, "value": value, "intent": None},
        )
        if refused is not None:  # audited as the gate's own dry runs are
            activity.record(
                "checked",
                chain=chain,
                allowed=False,
                reason=refused,
                probed_target=target,
                probed_value=str(value),
                via_safe=via_safe,
            )
            return {"permitted": False, "rule": refused}
        reason, _ = await asyncio.to_thread(
            signer.check,
            chain,
            target,
            value=parse_amount(value),
            data=data,
            via_safe=via_safe,
            gate=False,
        )
        if reason is None:
            return {"permitted": True}
        return {"permitted": False, "rule": reason}

    @mcp.tool(
        description=TOOL_DESCRIPTIONS["simulate_transaction"], annotations=READ_ONLY
    )
    async def simulate_transaction(  # pylint: disable=too-many-arguments
        chain: str,
        target: str,
        value: Amount = "0",
        data: str = "0x",
        *,
        via_safe: bool = True,
        intent: ToolIntent | None = None,
        ctx: Context | None = None,
    ) -> dict:
        """Simulate a call and report its asset diff."""
        return await asyncio.to_thread(
            signer.simulate,
            chain,
            target,
            value=parse_amount(value),
            data=data,
            via_safe=via_safe,
            intent=_for_token(grants, ctx, intent),
        )

    @mcp.tool(description=TOOL_DESCRIPTIONS["chain_call"], annotations=READ_ONLY)
    async def chain_call(chain: str, to: str, data: str, block: str = "latest") -> dict:
        """Read a contract with eth_call."""
        return await asyncio.to_thread(
            chain_read.chain_call, signer.w3(chain), to, data, block
        )

    @mcp.tool(description=TOOL_DESCRIPTIONS["get_abi"], annotations=READ_ONLY)
    async def get_abi(chain: str, address: str) -> dict:
        """Report the ABI Connect ships for a contract."""
        return await asyncio.to_thread(chain_read.get_abi, signer.w3(chain), address)

    @mcp.tool(description=TOOL_DESCRIPTIONS["decode_calldata"], annotations=READ_ONLY)
    async def decode_calldata(chain: str, data: str) -> dict:
        """Decode calldata against the signatures Connect ships."""
        return chain_read.decode_calldata(data)

    @mcp.tool(
        description=TOOL_DESCRIPTIONS["transaction_status"], annotations=READ_ONLY
    )
    async def transaction_status(chain: str, tx_hash: str) -> dict:
        """Report how a transaction settled."""
        try:
            valid = len(bytes.fromhex(tx_hash.removeprefix("0x"))) == 32
        except ValueError:
            valid = False
        if not valid:  # a hash that can never resolve is simply not found
            return not_found(tx_hash)

        def _run() -> dict:
            w3 = signer.w3(chain)
            try:
                receipt = w3.eth.get_transaction_receipt(HexBytes(tx_hash))
            except TransactionNotFound:  # unknown, or not mined yet
                return not_found(tx_hash)
            return mined_result(tx_hash, receipt)

        return await asyncio.to_thread(_run)

    @mcp.tool(description=TOOL_DESCRIPTIONS["sign_message"])
    async def sign_message(digest: str) -> dict:
        """Sign a raw 32-byte digest with the agent EOA."""
        try:
            raw = bytes.fromhex(digest.removeprefix("0x"))
        except ValueError as e:
            raise ValueError(f"digest must be a 0x-hex string: {e}") from e
        return {"signature": await asyncio.to_thread(signer.sign_digest, raw)}

    @mcp.tool(description=TOOL_DESCRIPTIONS["mech_request"])
    async def mech_request(  # pylint: disable=too-many-arguments
        prompt: str,
        tool: str,
        chain: str | None = None,
        *,
        legacy_on_chain: bool = False,
        priority_mech: str | None = None,
        auto_deposit: bool = True,
        timeout: float = 300,
        max_payment: Cap | None = None,
        request_id: str | None = None,
        request_context: dict | None = None,
        ctx: Context | None = None,
    ) -> dict:
        """Send a mech request and wait for its delivery."""
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
            max_payment=None if max_payment is None else parse_amount(max_payment),
            request_id=request_id,
            request_context=request_context,
            top_up_budget=_top_up_budget(grants, ctx),
        )

    @mcp.tool(description=TOOL_DESCRIPTIONS["mech_result"], annotations=READ_ONLY)
    async def mech_result(
        request_id: str, timeout: float = DEFAULT_RESULT_TIMEOUT
    ) -> dict:
        """Resume the watch on a request whose wait timed out."""
        return await asyncio.to_thread(mech.result, request_id, timeout=timeout)

    @mcp.tool(description=TOOL_DESCRIPTIONS["mech_tools"], annotations=READ_ONLY)
    async def mech_tools(
        chain: str | None = None,
        priority_mech: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict:
        """List mechs, or one mech's tools and terms."""
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

    if switches.strict_parameters:
        # a parameter a tool does not take is refused by name, never dropped
        make_tools_strict(mcp, activity)
    return mcp


def _ctx_request(ctx: Context | None) -> t.Any:
    """Return the HTTP request behind this tool call, None when called in-process."""
    try:
        return ctx.request_context.request if ctx is not None else None
    except ValueError:  # no request: called in-process, not through the mount
        return None


def _ctx_token(ctx: Context | None) -> str | None:
    """Return the bearer token the MCP mount stamped on this tool's request."""
    return request_token(_ctx_request(ctx))


def _for_token(
    grants: GrantStore, ctx: Context | None, intent: ToolIntent | None
) -> AgentIntent:
    """Return the intent the gate holds this call to, for the calling token.

    The MCP mount stamps the token on the request; `GrantStore.intent_for`
    decides, and treats a call that reached a tool without one as capped.
    """
    return grants.intent_for(_ctx_token(ctx), None if intent is None else dict(intent))


def _top_up_budget(grants: GrantStore, ctx: Context | None) -> TopUpBudget | None:
    """Return the session budget a mech request's top-up draws on, for its token.

    None for a call with no token: it never reached the mount, which
    authorizes every real call.
    """
    token = _ctx_token(ctx)
    if token is None:
        return None

    def draw(amount: int) -> str | None:
        try:
            grants.draw_mech_top_up(token, amount)
        except GrantRefused as e:
            return e.message
        return None

    return draw


def _token_refusal(
    grants: GrantStore, ctx: Context | None, action: str, arguments: dict
) -> str | None:
    """Return the refusal the token's grant gives `action`, drawing on nothing.

    A dry run of the check the mount makes before the real call, so a
    preflight answers with the cap the send would be refused under. A call
    with no token never reached the mount, which authorizes every real call.
    """
    token = _ctx_token(ctx)
    if token is None:
        return None
    try:
        grants.authorize(token, action, arguments, draw=False)
    except GrantRefused as e:
        return e.message
    return None


async def _dispatch(  # pylint: disable=too-many-arguments
    method: t.Callable[..., str],
    signer: Signer,
    *,
    chain: str,
    address: str,
    value: str | int,
    data: str,
    intent: AgentIntent,
    request_id: str | None,
    replay_only: bool,
    wait_for_receipt: bool,
    timeout: int,
) -> dict:
    """Validate, run one signer method off the event loop, and settle it.

    The two send tools differ only in which signer method acts and what its
    address means (EOA recipient vs. the safe's call target); everything else —
    the value guard, the worker-thread offload, the settle — is shared here.
    """
    try:
        amount = parse_amount(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"value must be a non-negative amount in wei: {e}") from e

    def _run() -> dict:
        tx_hash = method(
            chain,
            address,
            value=amount,
            data=data,
            request_id=request_id,
            intent=intent,
            replay_only=replay_only,
        )
        return settled(signer, chain, tx_hash, wait_for_receipt, timeout)

    return await asyncio.to_thread(_run)
