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

import typing as t

import pytest

from connect import texts

ADDR = "0x" + "ab" * 20

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
        "amount 9e+18 is not an exact integer: send large amounts as a decimal "
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


@pytest.mark.parametrize(("constant", "reference"), CONSTANTS + FORMATTED)
def test_text_equals_the_reference(constant: t.Any, reference: t.Any) -> None:
    """Each contract text is the reference's, character for character."""
    assert constant == reference


def test_a_malformed_value_is_quoted_truncated_to_sixty_characters() -> None:
    """The reference cuts the echoed value at 60 characters before quoting it."""
    long = "0x" + "z" * 100
    assert texts.ADDRESS_INVALID("to", long).endswith(repr(long[:60]))
    assert texts.HEX_INVALID("data", long).endswith(repr(long[:60]))


def test_the_thirteen_tools_are_described() -> None:
    """The description table names exactly the reference's 13 tools."""
    assert set(texts.TOOL_DESCRIPTIONS) == {
        "wallet_info",
        "safe_transaction",
        "send_transaction",
        "preflight_transaction",
        "simulate_transaction",
        "chain_call",
        "get_abi",
        "decode_calldata",
        "transaction_status",
        "sign_message",
        "mech_tools",
        "mech_request",
        "mech_result",
    }


def test_the_guardrail_texts_carry_the_prefix_the_broker_reads() -> None:
    """Every guardrail refusal begins with the prefix the broker classifies."""
    for text in (
        texts.GUARD_NO_DELEGATECALL,
        texts.GUARD_NO_SELF_CALL,
        texts.guard_not_allowed(ADDR, "gnosis"),
    ):
        assert text.startswith(texts.GUARDRAIL_PREFIX)
