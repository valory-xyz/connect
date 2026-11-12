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

"""Tests for the intent gate (OPE-2035 T5)."""

import typing as t

import pytest

from connect import intent

from tests.conftest import native_transfer_log

SAFE = "0x" + "22" * 20
EOA = "0x" + "aa" * 20
CONTRACT = "0x" + "cc" * 20
TOKEN = "0x" + "70" * 20
SPENDER = "0x" + "5e" * 20
CELO_FACE = "0x471ece3750da237f93b8e339c536989b8978a438"


def _topic(address: str) -> str:
    return "0x" + address.lower().removeprefix("0x").rjust(64, "0")


def _word(value: int) -> str:
    return hex(value)[2:].rjust(64, "0")


def transfer(token: str, src: str, dst: str, amount: int) -> dict:
    """Return an ERC-20 Transfer log."""
    return {
        "address": token,
        "topics": [intent.TRANSFER, _topic(src), _topic(dst)],
        "data": "0x" + _word(amount),
    }


def approval(token: str, owner: str, spender: str, amount: int) -> dict:
    """Return an ERC-20 Approval log."""
    return {
        "address": token,
        "topics": [intent.APPROVAL, _topic(owner), _topic(spender)],
        "data": "0x" + _word(amount),
    }


def rpc_with(
    logs: list[dict], status: str = "0x1", error: dict | None = None
) -> intent.Rpc:
    """Return an rpc callable answering eth_simulateV1 with these logs."""

    def rpc(method: str, params: list) -> t.Any:
        assert method == "eth_simulateV1"
        call: dict = {"status": status, "gasUsed": "0x10", "logs": logs}
        if error is not None:
            call["error"] = error
        return [{"calls": [call]}]

    return rpc


def simulate(logs: list[dict], **kwargs: t.Any) -> intent.AssetDiff:
    """Simulate a call from SAFE whose result carries `logs`."""
    contracts = kwargs.pop("contracts", {CONTRACT})
    return intent.simulate(
        rpc_with(logs, **kwargs),
        sender=SAFE,
        to=CONTRACT,
        value=0,
        data="0x",
        get_code=lambda a: b"\x01" if a in contracts else b"",
    )


def test_native_and_token_spend_are_netted_per_asset() -> None:
    """The diff is what left and arrived at the sender, per asset."""
    diff = simulate(
        [
            native_transfer_log(SAFE, CONTRACT, 100),
            native_transfer_log(CONTRACT, SAFE, 30),
            transfer(TOKEN, SAFE, CONTRACT, 40),
            transfer(TOKEN, CONTRACT, SAFE, 15),
        ]
    )
    assert diff["ok"] is True
    assert diff["native"] == "-70"
    assert diff["tokens"] == {TOKEN: {"delta": "-25"}}
    assert diff["recipients"] == [{"address": CONTRACT, "contract": True}]
    assert diff["called"] == [CONTRACT, TOKEN]
    assert diff["gas_used"] == 16


def test_celo_native_face_is_not_counted_twice() -> None:
    """Celo's CELO logs its own Transfer for the same coins as the synthetic one."""
    diff = simulate(
        [
            native_transfer_log(SAFE, EOA, 7),
            transfer(CELO_FACE, SAFE, EOA, 7),
            transfer(CELO_FACE, SAFE, EOA, 3),  # a face-only move still counts
        ]
    )
    assert diff["native"] == "-10"
    assert diff["tokens"] == {}


def test_weth_and_nft_moves_and_approvals() -> None:
    """Deposit/Withdrawal, ERC-721, ERC-1155 single/batch, and both approval kinds."""
    batch_data = (
        "0x"
        + _word(64)
        + _word(160)
        + _word(2)
        + _word(1)
        + _word(2)
        + _word(2)
        + _word(5)
        + _word(6)
    )
    logs = [
        {
            "address": TOKEN,
            "topics": [intent.DEPOSIT, _topic(SAFE)],
            "data": "0x" + _word(9),
        },
        {
            "address": TOKEN,
            "topics": [intent.WITHDRAWAL, _topic(SAFE)],
            "data": "0x" + _word(4),
        },
        {
            "address": CONTRACT,
            "topics": [intent.TRANSFER, _topic(SAFE), _topic(EOA), "0x" + _word(42)],
            "data": "0x",
        },
        {
            "address": CONTRACT,
            "topics": [intent.TRANSFER, _topic(EOA), _topic(SAFE), "0x" + _word(43)],
            "data": "0x",
        },
        {
            "address": TOKEN,
            "topics": [intent.TRANSFER_SINGLE, _topic(SAFE), _topic(SAFE), _topic(EOA)],
            "data": "0x" + _word(1) + _word(3),
        },
        {
            "address": TOKEN,
            "topics": [intent.TRANSFER_BATCH, _topic(SAFE), _topic(EOA), _topic(SAFE)],
            "data": batch_data,
        },
        approval(TOKEN, SAFE, SPENDER, 0),
        {
            "address": CONTRACT,
            "topics": [intent.APPROVAL_FOR_ALL, _topic(SAFE), _topic(SPENDER)],
            "data": "0x" + _word(0),
        },
        approval(TOKEN, EOA, SPENDER, 5),  # someone else's approval
        {"address": TOKEN, "topics": [], "data": "0x"},  # anonymous log
    ]
    diff = simulate(logs)
    assert diff["tokens"] == {TOKEN: {"delta": "5"}}
    assert diff["positions"] == [
        {"token": TOKEN, "id": "1", "delta": "2"},
        {"token": TOKEN, "id": "2", "delta": "6"},
        {"token": CONTRACT, "id": "42", "delta": "-1"},
        {"token": CONTRACT, "id": "43", "delta": "1"},
    ]
    assert diff["approvals"] == [
        {"token": TOKEN, "spender": SPENDER, "amount": "0", "infinite": False},
        {"token": CONTRACT, "spender": SPENDER, "amount": "all", "infinite": True},
    ]
    assert diff["recipients"] == [{"address": EOA, "contract": False}]


def test_revert_reason_is_decoded() -> None:
    """An Error(string) revert is read out; otherwise the RPC message or the raw data."""
    text = b"too little received"
    data = "0x08c379a0" + _word(32) + _word(len(text)) + text.hex().ljust(64, "0")
    assert simulate([], status="0x0", error={"data": data})["revert"] == (
        "too little received"
    )
    assert simulate([], status="0x0", error={"message": "out of gas"})["revert"] == (
        "out of gas"
    )
    assert simulate([], status="0x0")["revert"] == "reverted"
    assert simulate([], status="0x0", error={"data": "0xdeadbeef"})["revert"] == (
        "0xdeadbeef"
    )
    bad = "0x08c379a0" + _word(32) + "zz" * 32 + "00" * 32
    assert (
        simulate([], status="0x0", error={"data": bad, "message": "m"})["revert"] == "m"
    )


def test_unexpected_answer_is_simulation_unavailable() -> None:
    """An answer without the call result cannot be trusted as a simulation."""
    with pytest.raises(intent.SimulationUnavailable):
        intent.simulate(
            lambda m, p: [],
            sender=SAFE,
            to=CONTRACT,
            value=0,
            data="0x",
            get_code=lambda a: b"",
        )


def _diff(**overrides: t.Any) -> intent.AssetDiff:
    base = intent.AssetDiff(
        ok=True,
        revert=None,
        native="0",
        tokens={},
        recipients=[],
        approvals=[],
        positions=[],
        called=[CONTRACT],
        gas_used=0,
    )
    base.update(overrides)  # type: ignore[typeddict-item]
    return base


def rules(problems: list[intent.Problem]) -> list[str]:
    """Return the rule names, in order."""
    return [p["rule"] for p in problems]


def test_value_moving_needs_an_intent() -> None:
    """Any spend, NFT out or non-zero approval without an intent is refused."""
    assert rules(intent.check_intent(_diff(native="-1"), None)) == ["missing-intent"]
    assert rules(intent.check_intent(_diff(tokens={TOKEN: {"delta": "-1"}}), None)) == [
        "missing-intent"
    ]
    assert rules(
        intent.check_intent(
            _diff(positions=[{"token": TOKEN, "id": "1", "delta": "-1"}]), None
        )
    ) == ["missing-intent"]
    assert rules(
        intent.check_intent(
            _diff(approvals=[{"token": TOKEN, "spender": SPENDER, "amount": "1"}]),
            None,
        )
    ) == ["missing-intent"]
    # a claim moves nothing of the sender's, so it needs none
    assert intent.check_intent(_diff(tokens={TOKEN: {"delta": "3"}}), None) == []


def test_reverts_is_refused_even_with_an_intent() -> None:
    """A call that reverts is never signed."""
    assert rules(intent.check_intent(_diff(ok=False, revert="no"), {})) == ["reverts"]


def test_spend_receive_recipient_and_approval_rules() -> None:
    """Each mismatch names its own rule; a covered call passes."""
    diff = _diff(
        native="-5",
        tokens={TOKEN: {"delta": "2"}},
        recipients=[
            {"address": EOA, "contract": False},
            {"address": CONTRACT, "contract": True},
        ],
        approvals=[
            {"token": TOKEN, "spender": SPENDER, "amount": "10"},
            {"token": TOKEN, "spender": SPENDER, "amount": "0"},
            {"token": CONTRACT, "spender": SPENDER, "amount": "all"},
        ],
    )
    assert rules(
        intent.check_intent(diff, {"spend": {"native": 4}, "receive_min": {TOKEN: 3}})
    ) == [
        "overspend",
        "receive-min",
        "undeclared-recipient",
        "undeclared-approval",
        "undeclared-approval",
    ]
    covered: intent.Intent = {
        "spend": {"native": 5},
        "receive_min": {TOKEN: 2},
        "recipients": [EOA],
        "approvals": [
            {"token": TOKEN, "spender": SPENDER, "amount": 10},
            {"token": CONTRACT, "spender": SPENDER, "amount": intent.MAX_UINT256},
        ],
    }
    assert intent.check_intent(diff, covered) == []


def test_parse_intent_normalises_and_refuses_bad_shapes() -> None:
    """Addresses lower-case, amounts ints; anything malformed is bad-intent."""
    parsed, problems = intent.parse_intent(
        {
            "spend": {"NATIVE": "0x10", TOKEN.upper().replace("0X", "0x"): 5},
            "recipients": [EOA.upper().replace("0X", "0x")],
            "approvals": [{"token": TOKEN, "spender": SPENDER, "amount": 1}],
        }
    )
    assert problems == []
    assert parsed == {
        "spend": {"native": 16, TOKEN: 5},
        "receive_min": {},
        "recipients": [EOA],
        "approvals": [{"token": TOKEN, "spender": SPENDER, "amount": 1}],
    }
    assert intent.parse_intent(None) == (None, [])
    for bad in (
        "spend 5",
        {"spend": {"native": -1}},
        {"spend": {"native": True}},
        {"spend": [1]},
        {"recipients": ["0x12"]},
        {"approvals": ["x"]},
        {"approvals": [{"token": TOKEN}]},
        {"limit": 1},
    ):
        _, problems = intent.parse_intent(bad)
        assert rules(problems) == ["bad-intent"], bad


def test_refusal_message_names_every_rule() -> None:
    """The refusal a session reads lists each rule and why."""
    message = intent.refusal_message(
        [
            intent.Problem(rule="overspend", detail="a"),
            intent.Problem(rule="reverts", detail="b"),
        ]
    )
    assert message == (
        "refused by the intent gate: rule 'overspend': a; rule 'reverts': b"
    )
