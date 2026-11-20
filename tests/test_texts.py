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


"""Every contract text equals OnchainBench's reference value, verbatim."""

import ast
import typing as t
from pathlib import Path

import pytest

from connect import texts

ADDR = "0x" + "ab" * 20
SAFE_ADDR = "0x" + "5a" * 20
OTHER_ADDR = "0x" + "07" * 20

# (constant, reference value): the reference's literals, copied from
# onchainbench 40b9430 (fork_connect.py, mock_connect/server.py,
# interim/intent_gate.py, connect/policy.py)
CONSTANTS = [
    (
        texts.WEI_DESCRIPTION,
        "an integer amount in base units (wei), as a decimal string such as "
        '"9000000000000000000"',
    ),
    (texts.SERVER_INFO, {"name": "connect", "version": "0.1.0"}),
    (texts.GUARDRAIL_PREFIX, "guardrail: rule "),
    (texts.NOT_SENT_SUFFIX, ". Nothing was sent."),
    (texts.MINED_PREFIX, "transaction 0x"),
    (
        texts.GUARD_NO_DELEGATECALL,
        "guardrail: rule 'no-delegatecall': the safe may not delegatecall; "
        "the guardrail never allows it",
    ),
    (
        texts.GUARD_NO_SELF_CALL,
        "guardrail: rule 'no-self-call': the safe may not call itself (owner, "
        "module and guard changes are made that way); the guardrail never "
        "allows it",
    ),
    (
        texts.LOST_RESPONSE,
        "the response was lost; the request may or may not have taken effect",
    ),
    (
        texts.SIGNER_REFUSED,
        "signer: the signing service refused to sign (operator hold; try again "
        "later)",
    ),
    (texts.UNAUTHORIZED_BODY, {"detail": "unauthorized"}),
    (texts.MECH_OUTAGE, "mech marketplace unavailable (HTTP 503); try again later"),
    (texts.MECH_NO_PREPAID, "insufficient prepaid balance and auto_deposit is off"),
    (texts.MECH_NO_PENDING, "no pending request with that id"),
]

FORMATTED = [
    (
        texts.guard_not_allowed(ADDR, "gnosis"),
        "guardrail: rule 'whitelist': the operator's guardrail settings do not "
        f"allow the safe to call {ADDR} on gnosis; ask the operator to change "
        "them via the agent UI if it is required",
    ),
    (texts.GATE_PROBLEM("reverts", "boom"), "intent gate: rule 'reverts' (boom)"),
    (texts.gate_overspend("USDC", 5, 3), "USDC: spends 5, intent allows 3"),
    (texts.gate_receive_min("WETH", 1, 2), "WETH: receives 1, intent needs 2"),
    (texts.gate_undeclared_recipient(ADDR), ADDR),
    (texts.gate_undeclared_approval("USDC", ADDR, "all"), f"USDC to {ADDR}, all"),
    (texts.INTENT_UNKNOWN_TOKEN("FOO"), "intent: unknown token 'FOO' (use an address)"),
    (
        texts.MINED_REVERT("0x12", "out of gas"),
        "transaction 0x12 reverted: out of gas",
    ),
    (texts.UNKNOWN_TOOL("nope"), "unknown tool nope"),
    (
        texts.INVALID_REQUEST("ValueError", "bad"),
        "invalid request: ValueError: bad",
    ),
    (
        texts.ADDRESS_INVALID("target", "0x12"),
        "target must be a 0x address (40 hex digits), got '0x12'",
    ),
    (
        texts.HEX_INVALID("data", "0xz"),
        "data must be hex (0x and whole bytes), got '0xz'",
    ),
    (
        texts.AMOUNT_INEXACT(9e18),
        "amount '9e+18' is not an exact integer: send large amounts as a decimal "
        "string",
    ),
    (
        texts.ABI_UNVERIFIED(ADDR, "base"),
        f"no verified source for {ADDR} on base; read its bytecode or decode "
        "selectors",
    ),
    (texts.UNKNOWN_SELECTOR("0xdeadbeef"), "unknown selector 0xdeadbeef"),
    (
        texts.MECH_OVER_CAP(10, 5),
        "refused before payment: mech price 10 exceeds max_payment 5",
    ),
    (
        texts.MECH_DEPOSIT_FAILED("USDC"),
        "auto_deposit failed: the safe holds too little USDC",
    ),
    (texts.MECH_UNKNOWN(ADDR), f"unknown mech {ADDR}"),
]


# the reference's TOOLS table, onchainbench 40b9430 fork_connect.py, verbatim
REFERENCE_DESCRIPTIONS = {
    "wallet_info": (
        "Agent EOA and per-chain safes, balances, known tokens and the chain's "
        "read-only RPC URL. Start every on-chain task here; act only on "
        "`actionable_chains`."
    ),
    "safe_transaction": (
        "Make the service safe call `target`, the normal way to act on-chain. "
        "`target`/`value`/`data` are the call the safe makes; any value carried"
        " leaves the safe, not the EOA. Reusing a request_id replays the "
        "original result instead of spending twice. Connect simulates the call "
        "first and refuses it if it reverts; pass `intent` (spend, receive_min,"
        " recipients, approvals) to also have the asset diff checked against "
        "what you mean."
    ),
    "send_transaction": (
        "Sign and broadcast a transaction from the agent EOA, the rarer path. "
        "`to` is the EOA's own recipient, not a call the safe makes, and the "
        "EOA's funds are for gas: to spend or act on-chain use "
        "safe_transaction. request_id semantics are safe_transaction's."
    ),
    "preflight_transaction": (
        "Ask whether a safe call would be permitted, before you build on it: "
        "answers {permitted}, plus the `rule` the real call would have been "
        "refused with. Nothing is signed, broadcast or paid for, and nothing is"
        " simulated: `permitted` means the guardrail permits these bytes, not "
        "that the call will succeed on-chain."
    ),
    "simulate_transaction": (
        "Simulate a safe call against the chain's current state and return the "
        "asset diff: native and token balance changes of the safe, recipients, "
        "approvals granted, contracts called, revert reason, gas. With "
        "`intent`, also says whether the diff fits it. Nothing is sent."
    ),
    "chain_call": (
        "eth_call against the chain (read a contract). `data` is ABI-encoded "
        "calldata; returns the raw result."
    ),
    "get_abi": (
        "The verified ABI of a contract, from a local cache of verified sources"
        " (Sourcify/Blockscout). For a proxy, also the implementation and its "
        "ABI. Unverified contracts return an error."
    ),
    "decode_calldata": (
        "Decode calldata (or a function selector) using the target's ABI if "
        "known, else a local signature list."
    ),
    "transaction_status": (
        "Settlement of a transaction hash you already hold: success, reverted "
        "or not_found."
    ),
    "sign_message": (
        "Sign a raw 32-byte digest (0x-hex) with the agent EOA, unprefixed."
    ),
    "mech_tools": (
        "Discover Olas mechs and the tools they serve, for use with "
        "mech_request. Without priority_mech: the live mechs. With it: that "
        "mech's tool names for mech_request's `tool`, its price "
        "(`max_delivery_rate`, base units of `payment_token`), payment_token "
        "and whose terms apply."
    ),
    "mech_request": (
        "Send a request to an Olas mech (AI service) and wait for its delivery."
        " The safe pays: off-chain by default, from the prepaid balance, topped"
        " up from the safe with auto_deposit. Refused before paying if the "
        "mech's price exceeds max_payment (base units of the mech's payment "
        "asset). `request_id` is an id you invent before sending: repeating it "
        "never pays again."
    ),
    "mech_result": (
        "Check whether a mech has since answered a request whose wait timed out"
        " (an id from `pending_request_ids`). Already paid for, so this resumes"
        " the watch and never resends."
    ),
}


def test_every_tool_description_is_the_reference_s_literal() -> None:
    """Each published description equals the reference's, word for word."""
    assert texts.TOOL_DESCRIPTIONS == REFERENCE_DESCRIPTIONS


# Connect's own guardrail rules, held in every position (not the reference's)
CONNECT_GUARD = [
    (
        texts.GUARD_RAW_DIGEST,
        "guardrail: rule 'raw-digest': raw digest signing is disabled by the "
        "operator's guardrail settings; ask the operator to change them via the "
        "agent UI if it is required",
    ),
    (
        texts.GUARD_OUTER_VALUE,
        "guardrail: rule 'outer-value': the guardrail forbids native value on the "
        "outer transaction of an execTransaction call",
    ),
    (
        texts.GUARD_UNDECODABLE,
        "guardrail: rule 'undecodable-exec-transaction': could not decode "
        "execTransaction calldata",
    ),
    (
        texts.guard_marketplace(ADDR, "gnosis"),
        f"guardrail: rule 'marketplace': the mech marketplace {ADDR} on gnosis "
        "takes only the requests Connect composes; send a mech request with "
        "mech_request",
    ),
    (
        texts.guard_no_safe("base"),
        "guardrail: rule 'no-safe': the operator's guardrail settings allow no "
        "transactions on chain 'base' (no service safe is configured there)",
    ),
    (
        texts.GUARD_REFUND,
        "guardrail: rule 'refund': the guardrail requires execTransaction refund "
        "fields to be zero (gasPrice=0, gasToken=0x0, refundReceiver=0x0): a gas "
        "refund would pay out of the safe past the allowed targets",
    ),
    (
        texts.guard_safe_only(SAFE_ADDR, OTHER_ADDR),
        "guardrail: rule 'safe-only': the operator's guardrail settings only allow "
        f"transactions targeting the service safe {SAFE_ADDR}, not {OTHER_ADDR}",
    ),
    (
        texts.guard_exec_transaction_only("6a761202", "12345678"),
        "guardrail: rule 'exec-transaction-only': the guardrail requires calls to "
        "the safe to be execTransaction (selector 0x6a761202), got 0x12345678",
    ),
    (
        texts.guard_payment_token_approve(SAFE_ADDR, OTHER_ADDR),
        "guardrail: rule 'payment-token-approve': the guardrail only allows "
        f"approve(spender={SAFE_ADDR}) on the payment token {OTHER_ADDR}",
    ),
]


# Connect's own texts outside the guardrail, pinned word for word
CONNECT_OWN = [
    (
        texts.AMOUNT_REFUSED,
        "rule 'bad-value': pass a decimal or 0x-hex string of base units, or a "
        "JSON integer below 2^53",
    ),
    (
        texts.CAP_REFUSED,
        "rule 'bad-value': pass a whole number of base units, as an integer or a "
        "decimal or 0x-hex string",
    ),
    (texts.VALUE_REFUSED, "value must be a non-negative amount in wei"),
    (texts.BODY_TOO_DEEP, "parse error: the request nests too deeply"),
    (texts.CHAIN_REQUIRED, "chain is required: this instance runs on no single chain"),
    (
        texts.BATCH_REFUSED,
        "batch requests are not supported: send one message per request",
    ),
    (
        texts.tool_failed("safe_transaction"),
        "safe_transaction failed (the cause is in Connect's log)",
    ),
    (texts.block_negative(-1), "block must be >= 0, got -1"),
    (
        texts.block_invalid(("latest", "pending"), "soon"),
        "block must be one of latest, pending or a number, got 'soon'",
    ),
    (
        texts.gate_token_cap_positions(f"{ADDR} #7"),
        f"moves {ADDR} #7 out, and a value-capped token may not move positions",
    ),
]


@pytest.mark.parametrize(("constant", "expected"), CONNECT_OWN)
def test_connect_s_own_texts(constant: str, expected: str) -> None:
    """Connect's own texts keep their words: agents and the bench read them."""
    assert constant == expected


@pytest.mark.parametrize(("constant", "expected"), CONNECT_GUARD)
def test_connect_s_own_guardrail_texts(constant: str, expected: str) -> None:
    """Connect's own rules keep their words: agents on the bench read them."""
    assert constant == expected


@pytest.mark.parametrize(("constant", "reference"), CONSTANTS + FORMATTED)
def test_text_equals_the_reference(constant: t.Any, reference: t.Any) -> None:
    """Each contract text is the reference's, character for character."""
    assert constant == reference


def test_a_malformed_value_is_quoted_truncated_to_sixty_characters() -> None:
    """The reference cuts the echoed value at 60 characters before quoting it.

    The inexact amount and a block are cut the same way.
    """
    long = "0x" + "z" * 100
    assert texts.ADDRESS_INVALID("to", long).endswith(repr(long[:60]))
    assert texts.HEX_INVALID("data", long).endswith(repr(long[:60]))
    assert texts.AMOUNT_INEXACT(10**70).startswith(f"amount {str(10**70)[:60]!r} ")
    assert texts.block_invalid(("latest",), "b" * 61).endswith(repr("b" * 60))


def test_the_guardrail_texts_carry_the_prefix_the_broker_reads() -> None:
    """Every guardrail refusal begins with the prefix the broker classifies."""
    for text in (
        texts.GUARD_NO_DELEGATECALL,
        texts.GUARD_NO_SELF_CALL,
        texts.guard_not_allowed(ADDR, "gnosis"),
    ):
        assert text.startswith(texts.GUARDRAIL_PREFIX)


# modules that must not restate a contract text inline
def _readers() -> list[str]:
    """Return every module of `connect` outside its assets, but `texts` itself.

    Every one, not only those that import `texts`: an inline copy is most
    likely in a module that never imported the constant.
    """
    package = Path(texts.__file__).parent
    return sorted(
        path.relative_to(package).as_posix()
        for path in package.rglob("*.py")
        if path.name != "texts.py" and "assets" not in path.parts
    )


READERS = _readers()


def test_the_readers_are_found() -> None:
    """The scan sees every module, those that read a text among them."""
    assert {
        "guard.py",
        "intent.py",
        "safe.py",
        "signer.py",
        "chain_read.py",
        "input_errors.py",
        "server/auth.py",
        "server/mcp_tools.py",
        "mech.py",
        "server/signer_routes.py",
    } <= set(READERS)


def _string_constants() -> dict[str, str]:
    """Return every plain string constant of the texts module, by name."""
    return {
        name: value
        for name, value in vars(texts).items()
        if name.isupper() and isinstance(value, str)
    }


@pytest.mark.parametrize("module", READERS)
def test_no_reader_restates_a_text_inline(module: str) -> None:
    """A text lives only in the texts module: no literal in a reader repeats one."""
    source = Path(texts.__file__).parent / module
    literals = {
        node.value
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    restated = {n for n, v in _string_constants().items() if v in literals}
    assert not restated, (module, sorted(restated))
