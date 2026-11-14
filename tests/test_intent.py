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

"""Tests for the intent gate."""

import typing as t

import pytest

from connect import intent

from tests.conftest import canary_result, native_transfer_log

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
    logs: list[dict],
    status: str = "0x1",
    error: dict | None = None,
    traced: bool = True,
) -> intent.Rpc:
    """Return an rpc callable answering eth_simulateV1 with these logs."""

    def rpc(method: str, params: list) -> t.Any:
        if method == "eth_call":  # symbol(): an ABI string for TOKEN, else none
            if params[0]["to"] == TOKEN:
                return "0x" + _word(32) + _word(4) + b"USDC".hex().ljust(64, "0")
            return "0x"
        assert method == "eth_simulateV1"
        call: dict = {"status": status, "gasUsed": "0x10", "logs": logs}
        if error is not None:
            call["error"] = error
        canary = params[0]["blockStateCalls"][0]["calls"][1]
        return [{"calls": [call, canary_result(canary, traced)]}]

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
    assert diff["tokens"] == {TOKEN: {"symbol": "USDC", "delta": "-25"}}
    assert diff["recipients"] == [{"address": CONTRACT, "contract": True}]
    assert diff["called"] == [CONTRACT, TOKEN]
    assert diff["gas_used"] == 16


def test_celo_native_moves_from_both_sources_are_summed() -> None:
    """A plain CELO send logs only the synthetic Transfer, a CELO.transfer only its own.

    Shapes as Celo's RPC answers eth_simulateV1 (checked against
    celo-rpc.publicnode.com): the two never report one move, so both count,
    and the face's logs are never also counted as an ERC-20.
    """
    diff = simulate(
        [
            native_transfer_log(SAFE, EOA, 7),
            transfer(CELO_FACE, SAFE, EOA, 3),
        ]
    )
    assert diff["native"] == "-10"
    assert diff["tokens"] == {}


def test_an_approval_by_the_celo_face_is_an_approval() -> None:
    """Only the face's Transfer is native: CELO.approve is still checked."""
    diff = simulate([approval(CELO_FACE, SAFE, SPENDER, intent.MAX_UINT256)])
    assert diff["approvals"] == [
        {
            "token": CELO_FACE,
            "spender": SPENDER,
            "amount": str(intent.MAX_UINT256),
            "infinite": True,
        }
    ]
    assert rules(intent.check_intent(diff, None)) == ["missing-intent"]
    assert rules(intent.check_intent(diff, intent.parse_intent({})[0])) == [
        "undeclared-approval"
    ]


def test_a_spend_naming_the_celo_face_is_a_native_spend() -> None:
    """Face moves are booked under native, so an intent naming the face is too."""
    parsed, problems = intent.parse_intent(
        {"spend": {CELO_FACE.upper().replace("0X", "0x"): 3}}
    )
    assert problems == []
    assert parsed is not None
    assert parsed["spend"] == {"native": 3}
    diff = simulate([transfer(CELO_FACE, SAFE, CONTRACT, 3)])
    assert rules(intent.check_intent(diff, parsed)) == []
    _, twice = intent.parse_intent({"spend": {"native": 1, CELO_FACE: 2}})
    assert rules(twice) == ["bad-intent"]
    assert "twice" in twice[0]["detail"]


def test_polygons_own_log_transfer_is_not_counted() -> None:
    """Polygon's 0x...1010 emits LogTransfer, a different event, beside the synthetic one."""
    log_transfer = {
        "address": "0x0000000000000000000000000000000000001010",
        "topics": [
            "0xe6497e3e18d9b3f9d0b14a1ea4b4b8e8cc8b25ae2c7e4e1b5f4d8b1e5b6b7c8d",
            "0x" + "00" * 32,
            _topic(SAFE),
            _topic(EOA),
        ],
        "data": "0x" + _word(5) + _word(0) + _word(0),
    }
    diff = simulate([native_transfer_log(SAFE, EOA, 5), log_transfer])
    assert diff["native"] == "-5"
    assert diff["tokens"] == {}


def test_burns_and_self_transfers_are_not_recipients() -> None:
    """A burn to the zero address and a transfer to oneself name no recipient."""
    diff = simulate(
        [
            transfer(TOKEN, SAFE, "0x" + "00" * 20, 4),
            transfer(TOKEN, SAFE, SAFE, 1),
        ]
    )
    assert diff["recipients"] == []
    assert intent.check_intent(diff, {"spend": {TOKEN: 4}}) == []


def test_an_nft_approval_is_value_moving_and_checked() -> None:
    """ERC-721 Approval has every field indexed; it is a grant like any other."""

    def nft_approval(spender: str) -> dict:
        return {
            "address": CONTRACT,
            "topics": [intent.APPROVAL, _topic(SAFE), _topic(spender), "0x" + _word(9)],
            "data": "0x",
        }

    diff = simulate([nft_approval(SPENDER)])
    assert diff["approvals"] == [
        {
            "token": CONTRACT,
            "spender": SPENDER,
            "amount": "1",
            "infinite": False,
            "id": "9",
        }
    ]
    assert rules(intent.check_intent(diff, None)) == ["missing-intent"]
    assert rules(intent.check_intent(diff, {})) == ["undeclared-approval"]
    cleared = simulate([nft_approval("0x" + "00" * 20)])
    assert intent.check_intent(cleared, None) == []  # approving nobody clears it


def test_a_malformed_batch_is_simulation_unavailable() -> None:
    """A TransferBatch whose arrays outrun its data cannot make the gate loop."""
    huge = {
        "address": TOKEN,
        "topics": [intent.TRANSFER_BATCH, _topic(SAFE), _topic(SAFE), _topic(EOA)],
        "data": "0x" + _word(64) + _word(96) + hex(2**200)[2:].rjust(64, "0"),
    }
    with pytest.raises(intent.SimulationUnavailable, match="TransferBatch"):
        simulate([huge])
    # equal counts, so only the bounds checks stand between the gate and a loop
    one_word = dict(huge, data="0x" + _word(64) + _word(64) + _word(2**200))
    # the ids fit; only the amounts array runs past the data
    short = "0x" + _word(64) + _word(160) + _word(2) + _word(1) + _word(2)
    amounts_overrun = dict(huge, data=short + _word(2) + _word(5))
    # the amounts fit; only the ids array runs past the data
    ids_at_end = "0x" + _word(160) + _word(64) + _word(2) + _word(5) + _word(6)
    ids_overrun = dict(huge, data=ids_at_end + _word(2) + _word(1))
    for malformed in (one_word, amounts_overrun, ids_overrun):
        with pytest.raises(intent.SimulationUnavailable, match="TransferBatch"):
            simulate([malformed])
    with pytest.raises(intent.SimulationUnavailable, match="unreadable"):
        intent.simulate(
            lambda m, p: [
                {
                    "calls": [
                        {"status": "0x1", "gasUsed": "zz", "logs": []},
                        canary_result(p[0]["blockStateCalls"][0]["calls"][1]),
                    ]
                }
            ],
            sender=SAFE,
            to=CONTRACT,
            value=0,
            data="0x",
            get_code=lambda a: b"",
        )


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
    assert diff["tokens"] == {TOKEN: {"symbol": "USDC", "delta": "5"}}
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


ZERO = "0x" + "00" * 20


def _wrap_log(kind: str, holder: str, amount: int) -> dict:
    """Return a WETH Deposit or Withdrawal log."""
    return {
        "address": TOKEN,
        "topics": [kind, _topic(holder)],
        "data": "0x" + _word(amount),
    }


@pytest.mark.parametrize(
    ("logs", "delta"),
    [
        ([transfer(TOKEN, ZERO, SAFE, 9), _wrap_log(intent.DEPOSIT, SAFE, 9)], "9"),
        ([_wrap_log(intent.DEPOSIT, SAFE, 9), transfer(TOKEN, ZERO, SAFE, 9)], "9"),
        ([transfer(TOKEN, SAFE, ZERO, 4), _wrap_log(intent.WITHDRAWAL, SAFE, 4)], "-4"),
        # a mint to, or a burn from, another address says nothing of the safe's
        ([transfer(TOKEN, ZERO, EOA, 9), _wrap_log(intent.DEPOSIT, SAFE, 9)], "9"),
        ([transfer(TOKEN, EOA, ZERO, 4), _wrap_log(intent.WITHDRAWAL, SAFE, 4)], "-4"),
    ],
)
def test_a_wrap_logging_transfer_and_deposit_counts_once(
    logs: list[dict], delta: str
) -> None:
    """Solmate/OpenZeppelin WETH log a mint or burn Transfer beside Deposit/Withdrawal."""
    assert simulate(logs)["tokens"] == {TOKEN: {"symbol": "USDC", "delta": delta}}


@pytest.mark.parametrize(
    ("code", "contract"),
    [
        (intent.EIP7702_DELEGATION_PREFIX + b"\x11" * 20, False),
        (intent.EIP7702_DELEGATION_PREFIX + b"\x11" * 21, True),
        (b"\xef\x01\x01" + b"\x11" * 20, True),
    ],
)
def test_an_eip7702_delegated_eoa_is_not_a_contract(
    code: bytes, contract: bool
) -> None:
    """A delegated EOA's key still moves what it holds: its recipient is declared."""
    diff = intent.simulate(
        rpc_with([transfer(TOKEN, SAFE, EOA, 5)]),
        sender=SAFE,
        to=TOKEN,
        value=0,
        data="0x",
        get_code=lambda a: code,
    )
    assert diff["recipients"] == [{"address": EOA, "contract": contract}]
    rules = [p["rule"] for p in intent.check_intent(diff, {"recipients": []})]
    assert ("undeclared-recipient" in rules) is not contract


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
    assert simulate([], status="0x0", error="execution reverted")["revert"] == (
        "execution reverted"
    )
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


def test_a_token_the_spend_does_not_name_may_not_be_spent_at_all() -> None:
    """An unlisted ERC-20 has a budget of 0, never an unlimited one."""
    native_only: intent.Intent = {"spend": {"native": 10}}
    out = _diff(tokens={TOKEN: {"delta": "-1"}})
    assert rules(intent.check_intent(out, native_only)) == ["overspend"]
    assert rules(intent.check_intent(out, {"spend": {TOKEN: 0}})) == ["overspend"]
    assert intent.check_intent(out, {"spend": {TOKEN: 1}}) == []


@pytest.mark.parametrize(
    ("answer", "symbol"),
    [
        ("0x" + b"MKR".hex().ljust(64, "0"), "MKR"),  # bytes32, as early tokens
        ("0x" + _word(32) + _word(80) + ("41" * 80).ljust(192, "0"), "A" * 32),
        ("0x", ""),
        ("0x1234", ""),
        ("not hex", ""),
        (intent.SimulationUnavailable("down"), ""),
    ],
)
def test_a_token_symbol_is_read_for_the_report_only(answer: t.Any, symbol: str) -> None:
    """symbol() is display only: any odd or failed answer reads as ""."""

    def rpc(method: str, params: list) -> t.Any:
        assert (method, params) == (
            "eth_call",
            [{"to": TOKEN, "data": intent.SYMBOL_SELECTOR}, "latest"],
        )
        if isinstance(answer, Exception):
            raise answer
        return answer

    assert intent._symbol(rpc, TOKEN) == symbol  # pylint: disable=protected-access


@pytest.mark.parametrize("raw", [0.9, 1.0, True])
def test_an_amount_is_never_truncated(raw: t.Any) -> None:
    """A float minimum of 0.9 must not become 0: floats and bools are refused."""
    _, problems = intent.parse_intent({"receive_min": {TOKEN: raw}})
    assert rules(problems) == ["bad-intent"]
    assert "whole number" in problems[0]["detail"]


def _with_allowance(logs: list[dict], allowance: int | None) -> intent.Rpc:
    """Answer the simulation with `logs`, and allowance() with `allowance`."""
    simulated = rpc_with(logs)

    def rpc(method: str, params: list) -> t.Any:
        if method == "eth_call" and params[0]["data"].startswith(
            intent.ALLOWANCE_SELECTOR
        ):
            assert params[0]["data"][10:74] == SAFE[2:].rjust(64, "0")
            assert params[0]["data"][74:] == SPENDER[2:].rjust(64, "0")
            if allowance is None:
                raise intent.SimulationUnavailable("down")
            return "0x" + _word(allowance)
        return simulated(method, params)

    return rpc


@pytest.mark.parametrize(
    ("allowance", "kept"), [(1000, False), (600, False), (599, True), (None, True)]
)
def test_an_approval_that_only_spends_an_allowance_down_is_no_grant(
    allowance: int | None, kept: bool
) -> None:
    """An OpenZeppelin 4.x transferFrom emits Approval(holder, spender, left)."""
    logs = [
        transfer(TOKEN, SAFE, CONTRACT, 400),
        approval(TOKEN, SAFE, SPENDER, 600),
    ]
    diff = intent.simulate(
        _with_allowance(logs, allowance),
        sender=SAFE,
        to=CONTRACT,
        value=0,
        data="0x",
        get_code=lambda a: b"\x01",
    )
    assert bool(diff["approvals"]) is kept
    spend_only: intent.Intent = {"spend": {TOKEN: 400}}
    expected = ["undeclared-approval"] if kept else []
    assert rules(intent.check_intent(diff, spend_only)) == expected


@pytest.mark.parametrize("value", [0, 5])
def test_any_call_on_an_rpc_that_ignores_trace_transfers_fails_closed(
    value: int,
) -> None:
    """A zero-value call can move native internally: the canary must be traced."""
    logs = [native_transfer_log(SAFE, EOA, value)] if value else []
    with pytest.raises(intent.SimulationUnavailable, match="traceTransfers"):
        intent.simulate(
            rpc_with(logs, traced=False),
            sender=SAFE,
            to=EOA,
            value=value,
            data="0x",
            get_code=lambda a: b"",
        )


def test_the_trace_canary_rides_beside_the_call_and_is_not_in_its_diff() -> None:
    """One request: the canary is funded by an override and never reaches the diff."""
    seen: list[dict] = []
    inner = rpc_with([])

    def rpc(method: str, params: list) -> t.Any:
        if method == "eth_simulateV1":
            seen.append(params[0])
        return inner(method, params)

    diff = intent.simulate(
        rpc, sender=SAFE, to=EOA, value=0, data="0x", get_code=lambda a: b""
    )
    (block,) = seen[0]["blockStateCalls"]
    assert block["calls"][1]["from"] == intent.TRACE_CANARY_FROM
    assert intent.TRACE_CANARY_FROM in block["stateOverrides"]
    assert diff["native"] == "0"
    assert diff["called"] == [EOA]
    assert diff["recipients"] == []


def test_an_answer_without_the_canary_is_simulation_unavailable() -> None:
    """An RPC that drops the second call cannot vouch for traceTransfers."""
    with pytest.raises(intent.SimulationUnavailable, match="unexpected"):
        intent.simulate(
            lambda m, p: [{"calls": [{"status": "0x1", "logs": []}]}],
            sender=SAFE,
            to=EOA,
            value=0,
            data="0x",
            get_code=lambda a: b"",
        )


def test_a_value_send_the_rpc_did_not_trace_fails_closed() -> None:
    """With no native Transfer log, a value send would look like it moves nothing."""
    for logs in ([], [native_transfer_log(SAFE, EOA, 3)]):
        with pytest.raises(intent.SimulationUnavailable, match="traceTransfers"):
            intent.simulate(
                rpc_with(logs),
                sender=SAFE,
                to=EOA,
                value=5,
                data="0x",
                get_code=lambda a: b"",
            )
    traced = intent.simulate(
        rpc_with([native_transfer_log(SAFE, EOA, 5)]),
        sender=SAFE,
        to=EOA,
        value=5,
        data="0x",
        get_code=lambda a: b"",
    )
    assert traced["native"] == "-5"
    reverted = intent.simulate(  # a revert moves nothing, traced or not
        rpc_with([], status="0x0"),
        sender=SAFE,
        to=EOA,
        value=5,
        data="0x",
        get_code=lambda a: b"",
    )
    assert reverted["ok"] is False


@pytest.mark.parametrize("event", [intent.PERMIT2_APPROVAL, intent.PERMIT2_PERMIT])
def test_a_permit2_grant_is_an_approval_the_intent_must_declare(event: str) -> None:
    """Permit2 lets its spender move the token: approve() and permit() both grant."""
    log = {
        "address": intent.PERMIT2,
        "topics": [event, _topic(SAFE), _topic(TOKEN), _topic(SPENDER)],
        "data": "0x" + _word(intent.MAX_UINT160) + _word(99),
    }
    diff = simulate([log])
    assert diff["approvals"] == [
        {
            "token": TOKEN,
            "spender": SPENDER,
            "amount": str(intent.MAX_UINT160),
            "infinite": True,
            "via": "permit2",
        }
    ]
    assert rules(intent.check_intent(diff, None)) == ["missing-intent"]
    assert rules(intent.check_intent(diff, {})) == ["undeclared-approval"]
    declared = {
        "approvals": [
            {"token": TOKEN, "spender": SPENDER, "amount": intent.MAX_UINT160}
        ]
    }
    assert intent.check_intent(diff, intent.parse_intent(declared)[0]) == []
    elsewhere = simulate([{**log, "address": TOKEN}])  # not Permit2: not its grant
    assert elsewhere["approvals"] == []
    for_another = simulate(
        [{**log, "topics": [event, _topic(EOA), *log["topics"][2:]]}]
    )
    assert for_another["approvals"] == []


@pytest.mark.parametrize(
    "answer",
    [
        [{"calls": [None]}],
        [{"calls": ["0x01"]}],
        [{"calls": [{"status": "0x1", "logs": 5}]}],
    ],
)
def test_a_malformed_simulation_answer_is_simulation_unavailable(
    answer: t.Any,
) -> None:
    """Any shape the RPC answers that is not a call result is a named refusal."""
    with pytest.raises(intent.SimulationUnavailable, match="unexpected"):
        intent.simulate(
            lambda method, params: answer,
            sender=SAFE,
            to=CONTRACT,
            value=0,
            data="0x",
            get_code=lambda a: b"",
        )


def test_receive_min_holds_when_nothing_arrives() -> None:
    """A token that never arrives is absent from the diff: still short of its minimum."""
    problems = intent.check_intent(
        _diff(native="-5"), {"spend": {"native": 5}, "receive_min": {TOKEN: 1}}
    )
    assert rules(problems) == ["receive-min"]


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


def test_an_approval_is_covered_only_by_the_same_token_spender_and_enough() -> None:
    """One unit short, a different spender, a different token: each is refused."""
    diff = _diff(approvals=[{"token": TOKEN, "spender": SPENDER, "amount": "10"}])
    all_diff = _diff(approvals=[{"token": TOKEN, "spender": SPENDER, "amount": "all"}])
    for granted in (
        {"token": TOKEN, "spender": SPENDER, "amount": 9},
        {"token": TOKEN, "spender": EOA, "amount": 10},
        {"token": CONTRACT, "spender": SPENDER, "amount": 10},
    ):
        assert rules(
            intent.check_intent(diff, t.cast(intent.Intent, {"approvals": [granted]}))
        ) == ["undeclared-approval"]
    below_max = {"token": TOKEN, "spender": SPENDER, "amount": intent.MAX_UINT256 - 1}
    assert rules(
        intent.check_intent(all_diff, t.cast(intent.Intent, {"approvals": [below_max]}))
    ) == ["undeclared-approval"]
