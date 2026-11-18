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
import functools
import logging
import typing as t

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BeforeValidator, ConfigDict, Field, ValidationError, with_config
from pydantic.json_schema import SkipJsonSchema
from typing_extensions import TypedDict

from connect import chain_read
from connect import settings as settings_config
from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard, GuardError
from connect.idempotency import InFlightError
from connect.input_errors import InputError, check_arguments, checked_hex
from connect.intent import AgentIntent, parse_amount, parse_tool_amount
from connect.mech import DEFAULT_RESULT_TIMEOUT, MechError, MechService
from connect.mech_allowances import TopUpBudget
from connect.safe import OPERATION_CALL, Operation
from connect.server.auth import (
    GrantRefused,
    GrantStore,
    is_replay,
    request_token,
)
from connect.server.receipts import settled, settlement
from connect.server.strict import (
    AuditedRefusal,
    make_tools_strict,
    unknown_parameter_errors,
)
from connect.settings import SettingsStore
from connect.signer import Signer, SignerError
from connect.signer_errors import logged_cause
from connect.texts import (
    AMOUNT_DESCRIPTION,
    AMOUNT_REFUSED,
    CAP_DESCRIPTION,
    CAP_REFUSED,
    CHAIN_REQUIRED,
    GET_ABI_DESCRIPTION,
    INVALID_REQUEST,
    REQUEST_CONTEXT_NOTE,
    SERVER_INFO,
    TOOL_DESCRIPTIONS,
    TRANSACTION_STATUS_DESCRIPTION,
    UNKNOWN_TOOL,
    VALUE_REFUSED,
    tool_failed,
)

# tools that read and never sign, broadcast or pay: harnesses may run them
# without asking the operator
READ_ONLY = ToolAnnotations(readOnlyHint=True)


def _amount_text(value: t.Any) -> str:
    """Read a base-unit amount as `intent.parse_tool_amount` reads it, as a string.

    :raises ValueError: naming the rule, `bad-value`, for anything else.
    """
    try:
        return str(parse_tool_amount(value))
    except (TypeError, ValueError) as e:  # Connect's words: no value, no int()'s
        raise ValueError(AMOUNT_REFUSED) from e


# a base-unit amount on the tool surface: declared a string, so a client
# that cannot hold the number exactly can still pass it exactly
Amount = t.Annotated[
    str,
    BeforeValidator(_amount_text),
    Field(description=AMOUNT_DESCRIPTION),
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
        raise ValueError(CAP_REFUSED) from e


# a base-unit cap on the tool surface: a string or any whole JSON integer
Cap = t.Annotated[
    str,
    BeforeValidator(_cap_text),
    Field(description=CAP_DESCRIPTION),
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


RequestContext = t.Annotated[dict | None, Field(description=REQUEST_CONTEXT_NOTE)]


# the tools whose `target` may be passed as `to`, as the reference accepts it
TOOLS_TAKING_TO_FOR_TARGET = frozenset(
    {"safe_transaction", "preflight_transaction", "simulate_transaction"}
)

# errors whose text Connect wrote for the caller; any other is a library's or
# a bug's, which may carry an RPC URL and key, so it is logged, not forwarded
CALLER_ERRORS: tuple[type[Exception], ...] = (
    InputError,
    SignerError,
    GuardError,
    GrantRefused,
    MechError,
    InFlightError,
)


logger = logging.getLogger("agent")


def with_aliases(tool: str, arguments: dict[str, t.Any]) -> dict[str, t.Any]:
    """Return a tool's arguments with `to` read as `target` where it aliases it.

    A non-empty `target` wins when both are given: the reference reads
    `a.get("target") or a.get("to")`.
    """
    if tool not in TOOLS_TAKING_TO_FOR_TARGET or "to" not in arguments:
        return arguments
    aliased = {k: v for k, v in arguments.items() if k != "to"}
    if not aliased.get("target"):
        aliased["target"] = arguments["to"]
    return aliased


def argument_problems(error: ValidationError) -> str:
    """Say what was wrong with each argument, never echoing the value sent."""
    return "; ".join(
        (
            ".".join(str(part) for part in issue["loc"]) + ": " + issue["msg"]
            if issue["loc"]
            else issue["msg"]
        )
        for issue in error.errors()
    )


class ConnectMCP(FastMCP):
    """FastMCP with the reference's call boundary.

    A refusal Connect wrote reaches the agent verbatim, any other error as
    `tool_failed`; FastMCP's `Error executing tool <name>: ` prefix would hide
    the markers the bench's broker reads.
    """

    def __init__(self, **settings: t.Any) -> None:
        """Build the server, reporting the reference's serverInfo version."""
        super().__init__(**settings)
        # FastMCP takes no version; unset, the MCP SDK reports its own
        self._mcp_server.version = SERVER_INFO["version"]

    def tool_names(self) -> frozenset[str]:
        """Return the names of the registered tools."""
        return frozenset(tool.name for tool in self._tool_manager.list_tools())

    def check_call(self, name: str, arguments: dict[str, t.Any]) -> dict[str, t.Any]:
        """Refuse a registered tool's malformed arguments; return them aliased.

        The one input check: every address and hex argument as sent, then the
        tool's own model (amounts, types, strictness). The MCP mount runs it
        before authorizing, so a refused call never draws on a budget and
        reads the same over the transport as in process.

        :raises ToolError: the refusal, in the words the agent reads.
        """
        tool = self._tool_manager.get_tool(name)
        if tool is None:
            raise ToolError(UNKNOWN_TOOL(name))
        try:  # the arguments' check is Connect's; one inside a tool body is not
            check_arguments(arguments)
            arguments = with_aliases(name, arguments)
            metadata = tool.fn_metadata
            metadata.arg_model.model_validate(metadata.pre_parse_json(arguments))
            # the model refuses a missing required field; an empty one is none too
            empty = [
                f"{field}: Field required"
                for field in tool.parameters.get("required", [])
                if arguments.get(field) == ""
            ]
            if empty:
                raise InputError(INVALID_REQUEST("ValidationError", "; ".join(empty)))
        except InputError as e:
            raise ToolError(str(e)) from e
        except ValidationError as e:
            audited = bool(unknown_parameter_errors(e.errors()))
            refusal = AuditedRefusal if audited else ToolError
            raise refusal(
                INVALID_REQUEST(type(e).__name__, argument_problems(e))
            ) from e
        except Exception as e:  # e.g. a JSON intent nested past the stack
            logger.error("tool %s failed: %s", name, logged_cause(e))
            raise ToolError(tool_failed(name)) from e
        return arguments

    async def call_tool(self, name: str, arguments: dict[str, t.Any]) -> t.Any:
        """Call a tool, raising its own error text with no transport prefix."""
        arguments = self.check_call(name, arguments)
        try:
            return await super().call_tool(name, arguments)
        except ToolError as e:
            cause = e.__cause__ or e
            if isinstance(cause, (ToolError, *CALLER_ERRORS)):
                raise ToolError(str(cause)) from cause
            logger.error("tool %s failed: %s", name, logged_cause(cause))
            raise ToolError(tool_failed(name)) from cause


def build_mcp(  # pylint: disable=unused-argument, too-many-arguments, too-many-locals
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    guard: Guard,
    mech: MechService,
    settings_store: SettingsStore,
    grants: GrantStore,
) -> ConnectMCP:
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
    async def wallet_info(chain: str | None = None) -> dict:
        """Report the EOA, the safes and their balances; `chain` is ignored."""
        del chain

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
        operation: SkipJsonSchema[Operation] = OPERATION_CALL,
    ) -> dict:
        """Have the service safe make one call."""
        return await _dispatch(
            functools.partial(signer.send_via_safe, operation=operation),
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
        """Answer whether the token and the guardrail permit a call; nothing is simulated."""
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
            run_intent_gate=False,
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

    @mcp.tool(description=GET_ABI_DESCRIPTION, annotations=READ_ONLY)
    async def get_abi(address: str, chain: str | None = None) -> dict:
        """Report the ABI Connect ships for a contract, on `chain` or the instance's."""
        on = chain or config.instance_chain
        if on is None:
            raise InputError(CHAIN_REQUIRED)
        return await asyncio.to_thread(chain_read.get_abi, signer.w3(on), address)

    @mcp.tool(description=TOOL_DESCRIPTIONS["decode_calldata"], annotations=READ_ONLY)
    async def decode_calldata(
        data: str, address: str | None = None, chain: str | None = None
    ) -> dict:
        """Decode calldata against the signatures Connect ships; `chain` is ignored.

        `address` is ignored too, once the boundary has checked its shape.
        """
        del address, chain
        return chain_read.decode_calldata(data)

    @mcp.tool(description=TRANSACTION_STATUS_DESCRIPTION, annotations=READ_ONLY)
    async def transaction_status(chain: str, tx_hash: str) -> dict:
        """Report how a transaction settled."""
        return await asyncio.to_thread(lambda: settlement(signer.w3(chain), tx_hash))

    @mcp.tool(description=TOOL_DESCRIPTIONS["sign_message"])
    async def sign_message(digest: str) -> dict:
        """Sign a raw 32-byte digest with the agent EOA."""
        raw = bytes.fromhex(checked_hex("digest", digest)[2:])
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
        request_context: RequestContext = None,
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

    if signer.switches.strict_parameters:
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
        raise InputError(VALUE_REFUSED) from e

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
