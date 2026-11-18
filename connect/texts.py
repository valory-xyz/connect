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


"""Every agent-visible text whose wording is part of Connect's contract.

Most of the wording is OnchainBench's reference implementation's, verbatim,
so an agent reads the same text on the bench and in Pearl; the guardrail
rules and gate details Connect adds, its amount refusals and the descriptions
it keeps are its own, in the same form. The module is public:
the bench imports it, so a rename here fails the bench's suite instead of
drifting. Names the bench imports keep their reference spelling, upper-case
formatters included.

Not every text is emitted by Connect yet. `WEI_DESCRIPTION`, `MINED_PREFIX`,
`MINED_REVERT`, `INTENT_UNKNOWN_TOKEN`, `LOST_RESPONSE`, `SIGNER_REFUSED`,
`UNAUTHORIZED_BODY`, `ABI_UNVERIFIED`,
`UNKNOWN_SELECTOR` and the `MECH_*` texts are the reference's wording for
behaviour still to be matched; until each is wired, Connect answers those
cases in its own words.
"""

# pylint: disable=invalid-name

import typing as t
from types import MappingProxyType

WEI_DESCRIPTION = (
    "an integer amount in base units (wei), as a decimal string such as "
    '"9000000000000000000"'
)

# read-only: an importer must not change what the server publishes
SERVER_INFO: t.Mapping[str, str] = MappingProxyType(
    {"name": "connect", "version": "0.1.0"}
)

TOOL_DESCRIPTIONS: t.Mapping[str, str] = MappingProxyType(
    {
        "wallet_info": (
            "Agent EOA and per-chain safes, balances, known tokens and the chain's "
            "read-only RPC URL. Start every on-chain task here; act only on "
            "`actionable_chains`."
        ),
        "safe_transaction": (
            "Make the service safe call `target`, the normal way to act on-chain. "
            "`target`/`value`/`data` are the call the safe makes; any value carried "
            "leaves the safe, not the EOA. Reusing a request_id replays the original "
            "result instead of spending twice. Connect simulates the call first and "
            "refuses it if it reverts; pass `intent` (spend, receive_min, recipients, "
            "approvals) to also have the asset diff checked against what you mean."
        ),
        "send_transaction": (
            "Sign and broadcast a transaction from the agent EOA, the rarer path. "
            "`to` is the EOA's own recipient, not a call the safe makes, and the "
            "EOA's funds are for gas: to spend or act on-chain use safe_transaction. "
            "request_id semantics are safe_transaction's."
        ),
        "preflight_transaction": (
            "Ask whether a safe call would be permitted, before you build on it: "
            "answers {permitted}, plus the `rule` the real call would have been "
            "refused with. Nothing is signed, broadcast or paid for, and nothing is "
            "simulated: `permitted` means the guardrail permits these bytes, not "
            "that the call will succeed on-chain."
        ),
        "simulate_transaction": (
            "Simulate a safe call against the chain's current state and return the "
            "asset diff: native and token balance changes of the safe, recipients, "
            "approvals granted, contracts called, revert reason, gas. With `intent`, "
            "also says whether the diff fits it. Nothing is sent."
        ),
        "chain_call": (
            "eth_call against the chain (read a contract). `data` is ABI-encoded "
            "calldata; returns the raw result."
        ),
        "get_abi": (
            "The verified ABI of a contract, from a local cache of verified sources "
            "(Sourcify/Blockscout). For a proxy, also the implementation and its "
            "ABI. Unverified contracts return an error."
        ),
        "decode_calldata": (
            "Decode calldata (or a function selector) using the target's ABI if "
            "known, else a local signature list."
        ),
        "transaction_status": (
            "Settlement of a transaction hash you already hold: success, reverted or "
            "not_found."
        ),
        "sign_message": (
            "Sign a raw 32-byte digest (0x-hex) with the agent EOA, unprefixed."
        ),
        "mech_tools": (
            "Discover Olas mechs and the tools they serve, for use with mech_request. "
            "Without priority_mech: the live mechs. With it: that mech's tool names "
            "for mech_request's `tool`, its price (`max_delivery_rate`, base units "
            "of `payment_token`), payment_token and whose terms apply."
        ),
        "mech_request": (
            "Send a request to an Olas mech (AI service) and wait for its delivery. "
            "The safe pays: off-chain by default, from the prepaid balance, topped "
            "up from the safe with auto_deposit. Refused before paying if the mech's "
            "price exceeds max_payment (base units of the mech's payment asset). "
            "`request_id` is an id you invent before sending: repeating it never "
            "pays again."
        ),
        "mech_result": (
            "Check whether a mech has since answered a request whose wait timed out "
            "(an id from `pending_request_ids`). Already paid for, so this resumes "
            "the watch and never resends."
        ),
    }
)

# What the broker reads: a refusal that begins with the guardrail prefix or
# ends with the not-sent suffix was not sent; one beginning MINED_PREFIX was.
GUARDRAIL_PREFIX = "guardrail: rule "
NOT_SENT_SUFFIX = ". Nothing was sent."
MINED_PREFIX = "transaction 0x"


# every guardrail rule id: the reference's three (the floor and the whitelist)
# and Connect's own, which are the same under every `Switches` position
GuardRule = t.Literal[
    "no-delegatecall",
    "no-self-call",
    "whitelist",
    "raw-digest",
    "outer-value",
    "refund",
    "undecodable-exec-transaction",
    "marketplace",
    "no-safe",
    "safe-only",
    "exec-transaction-only",
    "payment-token-approve",
]
GUARD_RULES: tuple[GuardRule, ...] = t.get_args(GuardRule)


# a guardrail refusal built by `guard_refusal`, the only text `GuardError`
# takes, so a refusal without a typed rule id fails the type check
GuardText = t.NewType("GuardText", str)


def guard_refusal(rule: GuardRule, detail: str) -> GuardText:
    """Return a guardrail refusal, in the reference's form."""
    return GuardText(f"{GUARDRAIL_PREFIX}'{rule}': {detail}")


# the clause every operator-changeable refusal ends with
ASK_OPERATOR = "ask the operator to change them via the agent UI if it is required"

GUARD_NO_DELEGATECALL = guard_refusal(
    "no-delegatecall", "the safe may not delegatecall; the guardrail never allows it"
)
GUARD_NO_SELF_CALL = guard_refusal(
    "no-self-call",
    "the safe may not call itself (owner, module and guard changes are made that "
    "way); the guardrail never allows it",
)


def guard_not_allowed(target: str, chain: str) -> GuardText:
    """Return the whitelist refusal for a call to `target` on `chain`."""
    return guard_refusal(
        "whitelist",
        "the operator's guardrail settings do not allow the safe to call "
        f"{target} on {chain}; {ASK_OPERATOR}",
    )


# Connect's own guardrail rules (see `GuardRule`)
GUARD_RAW_DIGEST = guard_refusal(
    "raw-digest",
    "raw digest signing is disabled by the operator's guardrail settings; "
    f"{ASK_OPERATOR}",
)
GUARD_OUTER_VALUE = guard_refusal(
    "outer-value",
    "the guardrail forbids native value on the outer transaction of an "
    "execTransaction call",
)
GUARD_REFUND = guard_refusal(
    "refund",
    "the guardrail requires execTransaction refund fields to be zero "
    "(gasPrice=0, gasToken=0x0, refundReceiver=0x0): a gas refund would pay "
    "out of the safe past the allowed targets",
)


EXEC_UNDECODABLE = "could not decode execTransaction calldata"
NOT_EXEC_TRANSACTION = "not execTransaction calldata"
GUARD_UNDECODABLE = guard_refusal("undecodable-exec-transaction", EXEC_UNDECODABLE)


def guard_marketplace(marketplace: str, chain: str) -> GuardText:
    """Return the refusal of a call to a mech marketplace Connect did not compose."""
    return guard_refusal(
        "marketplace",
        f"the mech marketplace {marketplace} on {chain} takes only the requests "
        "Connect composes; send a mech request with mech_request",
    )


def guard_no_safe(chain: str) -> GuardText:
    """Return the refusal of a transaction on a chain with no service safe."""
    return guard_refusal(
        "no-safe",
        "the operator's guardrail settings allow no transactions on chain "
        f"'{chain}' (no service safe is configured there)",
    )


def guard_safe_only(safe: str, to: str) -> GuardText:
    """Return the refusal of a transaction that does not target the service safe."""
    return guard_refusal(
        "safe-only",
        "the operator's guardrail settings only allow transactions targeting the "
        f"service safe {safe}, not {to}",
    )


def guard_exec_transaction_only(selector: str, got: str) -> GuardText:
    """Return the refusal of a call to the safe that is not execTransaction."""
    return guard_refusal(
        "exec-transaction-only",
        "the guardrail requires calls to the safe to be execTransaction "
        f"(selector 0x{selector}), got 0x{got}",
    )


def guard_payment_token_approve(tracker: str, token: str) -> GuardText:
    """Return the refusal of a payment-token call other than approving the tracker."""
    return guard_refusal(
        "payment-token-approve",
        f"the guardrail only allows approve(spender={tracker}) on the payment "
        f"token {token}",
    )


# get_abi answers in Connect's own way until it matches the reference's
# (unverified sources an error), so it publishes Connect's own description
GET_ABI_DESCRIPTION = (
    "Report what Connect can say about a contract's ABI, following EIP-1967. "
    "Only ABIs Connect ships: well-known contracts by address on the chains they "
    "are deployed to (`verified`, for the queried address alone; a proxy's "
    "implementation has its own `implementation_verified`) and the standard "
    "interfaces a contract answers to; no explorer lookup."
)

# transaction_status answers pending too (a transaction the node holds unmined),
# which the reference's description does not name, so it publishes Connect's own
TRANSACTION_STATUS_DESCRIPTION = (
    "Settlement of a transaction hash you already hold: success (mined, with its "
    "block), reverted, pending (sent but not yet mined) or not_found."
)

# Pearl keeps this warning on the field, beside the reference's tool text
REQUEST_CONTEXT_NOTE = (
    "optional dict handed to the tool alongside the prompt; it reaches the mech, "
    "and legacy_on_chain=true also publishes it to IPFS for good: put nothing "
    "private in it"
)


def GATE_PROBLEM(rule: str, detail: str) -> str:
    """Return one intent-gate problem, as the gate's refusal joins them."""
    return f"intent gate: rule '{rule}' ({detail})"


def gate_overspend(symbol: str, spends: int, allows: int) -> str:
    """Return the `overspend` problem's detail."""
    return f"{symbol}: spends {spends}, intent allows {allows}"


def gate_receive_min(symbol: str, receives: int, needs: int) -> str:
    """Return the `receive-min` problem's detail."""
    return f"{symbol}: receives {receives}, intent needs {needs}"


def gate_undeclared_recipient(address: str) -> str:
    """Return the `undeclared-recipient` problem's detail."""
    return address


def gate_undeclared_approval(symbol: str, spender: str, amount: object) -> str:
    """Return the `undeclared-approval` problem's detail."""
    return f"{symbol} to {spender}, {amount}"


def gate_token_cap_positions(where: str) -> str:
    """Return the `token-cap-positions` problem's detail: Connect's own rule."""
    return f"moves {where} out, and a value-capped token may not move positions"


def INTENT_UNKNOWN_TOKEN(key: str) -> str:
    """Return the refusal of an intent token key that names no known token."""
    return f"intent: unknown token '{key}' (use an address)"


def MINED_REVERT(tx_hash: str, reason: object) -> str:
    """Return the error a mined, reverted send raises."""
    return f"transaction {tx_hash} reverted: {reason}"


LOST_RESPONSE = "the response was lost; the request may or may not have taken effect"

SIGNER_REFUSED = (
    "signer: the signing service refused to sign (operator hold; try again later)"
)


def UNKNOWN_TOOL(tool: str) -> str:
    """Return the error for a call to a tool Connect does not serve."""
    return f"unknown tool {tool}"


UNAUTHORIZED_BODY: t.Mapping[str, str] = MappingProxyType({"detail": "unauthorized"})


def INVALID_REQUEST(type_name: str, message: str) -> str:
    """Return the error for malformed input on a tool call."""
    return f"invalid request: {type_name}: {message}"


def ADDRESS_INVALID(field: str, value: object) -> str:
    """Return the refusal of an address argument that is not 0x + 40 hex digits."""
    return f"{field} must be a 0x address (40 hex digits), got {str(value)[:60]!r}"


def HEX_INVALID(field: str, value: object) -> str:
    """Return the refusal of a hex argument that is not whole-byte hex."""
    return f"{field} must be hex (0x and whole bytes), got {str(value)[:60]!r}"


# Connect's own refusal of a base-unit amount it cannot read exactly: it names
# the rule and the form to send, never the value sent
AMOUNT_REFUSED = (
    "rule 'bad-value': pass a decimal or 0x-hex string of base units, or a JSON "
    "integer below 2^53"
)
CAP_REFUSED = (
    "rule 'bad-value': pass a whole number of base units, as an integer or a "
    "decimal or 0x-hex string"
)

# Connect's own field descriptions of those amounts
AMOUNT_DESCRIPTION = "base units, as a decimal or 0x-hex string"
CAP_DESCRIPTION = "base units, as an integer or a decimal or 0x-hex string"

# Connect's own refusals of a send's value and of a body the MCP mount cannot serve
VALUE_REFUSED = "value must be a non-negative amount in wei"
BATCH_REFUSED = "batch requests are not supported: send one message per request"
BODY_TOO_DEEP = "parse error: the request nests too deeply"


def tool_failed(tool: str) -> str:
    """Return what the caller reads for an error Connect did not word for it."""
    return f"{tool} failed (the cause is in Connect's log)"


def block_invalid(tags: t.Iterable[str], block: str) -> str:
    """Return the refusal of a `chain_call` block that is no tag and no number."""
    return f"block must be one of {', '.join(tags)} or a number, got {block[:60]!r}"


def block_negative(number: int) -> str:
    """Return the refusal of a negative block number on `chain_call`."""
    return f"block must be >= 0, got {number}"


def AMOUNT_INEXACT(value: object) -> str:
    """Return the refusal of an amount a JSON number cannot carry exactly.

    The value is truncated as `ADDRESS_INVALID` truncates it, so no refusal
    echoes a long value whole.
    """
    return (
        f"amount {str(value)[:60]!r} is not an exact integer: send large amounts "
        "as a decimal string"
    )


def ABI_UNVERIFIED(address: str, chain: str) -> str:
    """Return the error for an address with no verified source."""
    return (
        f"no verified source for {address} on {chain}; read its bytecode or "
        "decode selectors"
    )


def UNKNOWN_SELECTOR(selector: str) -> str:
    """Return the error for calldata whose selector no table holds."""
    return f"unknown selector {selector}"


MECH_OUTAGE = "mech marketplace unavailable (HTTP 503); try again later"


def MECH_OVER_CAP(price: int, cap: int) -> str:
    """Return the refusal of a mech whose price exceeds the caller's max_payment."""
    return f"refused before payment: mech price {price} exceeds max_payment {cap}"


MECH_NO_PREPAID = "insufficient prepaid balance and auto_deposit is off"


def MECH_DEPOSIT_FAILED(asset: str) -> str:
    """Return the refusal of a top-up the safe cannot cover, naming the payment asset."""
    return f"auto_deposit failed: the safe holds too little {asset}"


def MECH_UNKNOWN(address: str) -> str:
    """Return the error for a mech address Connect does not know."""
    return f"unknown mech {address}"


MECH_NO_PENDING = "no pending request with that id"
