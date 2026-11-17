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

"""The intent gate at the signing choke point, and the read tools."""

import json
import logging
import re
import typing as t
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from mcp.server.fastmcp import FastMCP
from web3 import Web3
from web3.exceptions import Web3RPCError

from connect import chain_read
from connect import intent as intent_module
from connect import signer as signer_module
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.signer import SERVER_BUILT, Signer, SignerError
from connect.signer_errors import (
    SEND_FAILED,
    SEND_UNKNOWN,
    SendUnknown,
    cause_of,
    logged_cause,
)
from connect.switches import PRODUCTION, TEST_INTERFACE

from tests.conftest import FakeW3, audit_entries, on_fake_chain, pay

SAFE = "0x" + "22" * 20
EOA = "0x" + "aa" * 20
TOKEN = "0x" + "70" * 20
SPENDER = "0x" + "5e" * 20
TOKEN_CALL = "0x" + "12" * 4
TOKEN_TOKEN = "unit-test-token"  # nosec B105


def _rules(problems: list[str]) -> list[str]:
    """Return the rule ids of a simulation's problem strings, in order."""
    rules = []
    for problem in problems:
        match = re.fullmatch(r"intent gate: rule '([^']+)' \(.*\)", problem, re.S)
        assert match is not None, problem
        rules.append(match[1])
    return rules


def _transfer_log(sender: str, to: str, amount: int) -> dict:
    return {
        "address": TOKEN,
        "topics": [
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
            "0x" + sender[2:].rjust(64, "0"),
            "0x" + to[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(amount)[2:].rjust(64, "0"),
    }


def _position_out_log(holder: str = SAFE) -> dict:
    """Return an ERC-1155 TransferSingle moving one position out of `holder`."""
    return {
        "address": TOKEN,
        "topics": [
            intent_module.TRANSFER_SINGLE,
            "0x" + holder[2:].rjust(64, "0"),
            "0x" + holder[2:].rjust(64, "0"),
            "0x" + EOA[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(7)[2:].rjust(64, "0") + hex(1)[2:].rjust(64, "0"),
    }


def _approval_log(amount: int, owner: str = SAFE) -> dict:
    return {
        "address": TOKEN,
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x" + owner[2:].rjust(64, "0"),
            "0x" + SPENDER[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(amount)[2:].rjust(64, "0"),
    }


@pytest.fixture
def tools(
    test_signer: Signer, guard: Guard, make_mcp: t.Callable[..., FastMCP]
) -> dict[str, t.Callable]:
    """Return the registered MCP tool functions keyed by name."""
    test_signer.set_guard(guard)
    mcp = make_mcp()
    manager = mcp._tool_manager  # pylint: disable=protected-access
    return {tool.name: tool.fn for tool in manager.list_tools()}


class TestSignerGate:
    """The gate sits after the guard on every agent-originated send."""

    def test_a_send_with_no_intent_may_spend_its_own_value(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Strict policy: a no-intent send that does only what it says goes through."""
        test_signer.send_via_safe("testchain", EOA, value=5)
        assert len(fake_w3.eth.sent) == 1

    def test_a_no_intent_approval_is_refused_and_audited(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """Strict policy: no intent declares no approvals, so granting one is refused."""
        fake_w3.provider.logs = [_approval_log(10)]
        with pytest.raises(SignerError, match="rule 'undeclared-approval'"):
            test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
        assert not fake_w3.eth.sent
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["rule"] == "undeclared-approval"
        assert entry["to"] == TOKEN

    def test_a_no_intent_send_is_held_to_its_own_value_and_target(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Strict policy: a spend beyond the value or another recipient is refused."""
        extra = {
            "address": "0x" + "ee" * 20,  # the synthetic native-transfer log
            "topics": [
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                "0x" + SAFE[2:].rjust(64, "0"),
                "0x" + SPENDER[2:].rjust(64, "0"),
            ],
            "data": "0x" + hex(3)[2:].rjust(64, "0"),
        }
        fake_w3.provider.logs = [extra]
        with pytest.raises(SignerError) as refused:
            test_signer.send_via_safe("testchain", EOA, value=5)
        assert "rule 'overspend' (native: spends 8, intent allows 5)" in str(
            refused.value
        )
        assert f"rule 'undeclared-recipient' ({SPENDER})" in str(refused.value)
        assert not fake_w3.eth.sent

    @pytest.mark.parametrize("strict", [True, False])
    def test_a_no_intent_token_spend_is_refused_only_under_strict(  # pylint: disable=too-many-arguments
        self,
        account: LocalAccount,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
        strict: bool,
    ) -> None:
        """S1's pair: strict names the implied limit; simulate-only sends it."""
        signer = on_fake_chain(
            Signer(
                account,
                app_config,
                activity,
                switches=PRODUCTION if strict else TEST_INTERFACE,
            ),
            fake_w3,
        )
        fake_w3.eth.contracts.add(SPENDER)  # paid to a contract: no recipient rule
        fake_w3.provider.logs = [_transfer_log(SAFE, SPENDER, 4)]
        if strict:
            with pytest.raises(SignerError) as refused:
                signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
            assert str(refused.value) == (
                f"intent gate: rule 'overspend' ({TOKEN}: spends 4, intent allows 0)"
                ". Nothing was sent."
            )
            assert not fake_w3.eth.sent
        else:
            signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
            assert len(fake_w3.eth.sent) == 1

    def test_a_capped_token_moves_no_position_in_either_position(
        self,
        account: LocalAccount,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
    ) -> None:
        """Under simulate-only a capped token's no-intent call still keeps positions."""
        signer = on_fake_chain(
            Signer(account, app_config, activity, switches=TEST_INTERFACE), fake_w3
        )
        fake_w3.provider.logs = [_position_out_log()]
        with pytest.raises(SignerError, match="rule 'token-cap-positions'"):
            signer.send_via_safe(
                "testchain", TOKEN, data=TOKEN_CALL, intent=intent_module.Capped(None)
            )
        assert not fake_w3.eth.sent

    def test_the_simulate_only_policy_refuses_only_a_revert(
        self,
        account: LocalAccount,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
    ) -> None:
        """The bench's policy: an undeclared approval mines, a revert is refused."""
        signer = on_fake_chain(
            Signer(account, app_config, activity, switches=TEST_INTERFACE), fake_w3
        )
        fake_w3.provider.logs = [_approval_log(10)]
        signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
        assert len(fake_w3.eth.sent) == 1
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = {"message": "execution reverted"}
        with pytest.raises(SignerError, match=r"rule 'reverts' \(execution reverted\)"):
            signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
        assert len(fake_w3.eth.sent) == 1

    def test_the_safe_path_simulates_the_safes_own_call(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """The simulation is of the call the safe makes, as the safe."""
        test_signer.send_via_safe("testchain", EOA, value=5, intent=pay(EOA, 5))
        (call,) = fake_w3.provider.simulated
        assert call["from"] == SAFE
        assert call["to"] == EOA
        assert call["value"] == "0x5"
        assert len(fake_w3.eth.sent) == 1

    def test_the_eoa_path_simulates_from_the_eoa(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """send() checks the EOA's own call."""
        test_signer.send("testchain", EOA, value=3, intent=pay(EOA, 3))
        assert fake_w3.provider.simulated[0]["from"] == test_signer.address

    @pytest.mark.parametrize("via_safe", [True, False])
    def test_one_call_gets_the_same_verdict_whatever_its_hex_prefix_case(
        self, test_signer: Signer, fake_w3: FakeW3, via_safe: bool
    ) -> None:
        """The simulation carries the bytes the guard read, whatever the prefix."""
        spellings = (TOKEN_CALL, "0X" + TOKEN_CALL[2:])
        verdicts = [
            test_signer.simulate("testchain", TOKEN, data=data, via_safe=via_safe)
            for data in spellings
        ]
        assert verdicts[0] == verdicts[1]
        assert verdicts[0]["problems"] == []
        send = test_signer.send_via_safe if via_safe else test_signer.send
        for data in spellings:
            send("testchain", TOKEN, data=data)
        assert len(fake_w3.eth.sent) == 2
        assert {call["data"] for call in fake_w3.provider.simulated} == {TOKEN_CALL}

    def test_overspend_and_undeclared_recipient_are_refused(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """An intent that allows less than the call does is a refusal, by rule."""
        with pytest.raises(SignerError, match="'overspend'.*'undeclared-recipient'"):
            test_signer.send_via_safe(
                "testchain", EOA, value=5, intent={"spend": {"native": 4}}
            )
        assert not fake_w3.eth.sent

    def test_undeclared_approval_is_refused(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """An approval the intent does not cover is refused."""
        fake_w3.provider.logs = [_approval_log(10)]
        with pytest.raises(SignerError, match="'undeclared-approval'"):
            test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL, intent={})
        test_signer.send_via_safe(
            "testchain",
            TOKEN,
            data=TOKEN_CALL,
            intent={"approvals": [{"token": TOKEN, "spender": SPENDER, "amount": 10}]},
        )
        assert len(fake_w3.eth.sent) == 1

    def test_a_call_that_moves_nothing_needs_no_intent(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A claim or a stake read-back is not value-moving."""
        test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
        assert len(fake_w3.eth.sent) == 1

    def test_a_revert_is_refused(self, test_signer: Signer, fake_w3: FakeW3) -> None:
        """A call that would revert is not signed."""
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = {"message": "execution reverted"}
        with pytest.raises(SignerError, match="'reverts'"):
            test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)

    def test_a_revert_reported_as_a_bare_string_is_refused_and_audited(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """Some RPCs answer the call's error as a string, not an object."""
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = "execution reverted"
        with pytest.raises(
            SignerError,
            match=r"^intent gate: rule 'reverts' \(execution reverted\)\. Nothing was sent\.$",
        ):
            test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL)
        assert not fake_w3.eth.sent
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["rule"] == "reverts"

    @pytest.mark.parametrize("via_safe", [True, False])
    @pytest.mark.parametrize(
        "data", ["0xzz", "0xa9059cbb 00", "0xa9059cbb\n00", "0xabc", " 0x00"]
    )
    def test_calldata_that_is_not_hex_is_refused_before_the_rpc(
        self,
        test_signer: Signer,
        fake_w3: FakeW3,
        store_path: t.Any,
        via_safe: bool,
        data: str,
    ) -> None:
        """A caller's typo is refused as one, not as an RPC that cannot simulate."""
        send = test_signer.send_via_safe if via_safe else test_signer.send
        with pytest.raises(SignerError, match=r"rule 'bad-calldata' \(cannot decode"):
            send("testchain", TOKEN, data=data)
        assert fake_w3.provider.simulated == []
        assert not fake_w3.eth.sent
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["rule"] == "bad-calldata"
        reason, problems = test_signer.check(
            "testchain", TOKEN, data=data, via_safe=via_safe
        )
        assert "'bad-calldata'" in str(reason)
        assert problems[0]["rule"] == "bad-calldata"
        simulated = test_signer.simulate(
            "testchain", TOKEN, data=data, via_safe=via_safe
        )
        assert _rules(simulated["problems"])[0] == "bad-calldata"
        assert fake_w3.provider.simulated == []

    def test_an_unavailable_simulation_is_logged(
        self,
        test_signer: Signer,
        fake_w3: FakeW3,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Every send on the chain is refused, so log.txt must say why."""
        fake_w3.provider.unavailable = True
        with caplog.at_level("WARNING", logger="agent"), pytest.raises(SignerError):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
        (record,) = [r for r in caplog.records if "cannot simulate" in r.message]
        assert "SimulationUnavailable: " in record.message  # and why
        assert record.levelname == "ERROR"
        assert EOA in record.message  # which call it could not simulate

    @pytest.mark.parametrize("via_safe", [True, False])
    def test_a_replay_only_send_without_an_id_is_refused(
        self, test_signer: Signer, fake_w3: FakeW3, via_safe: bool
    ) -> None:
        """There is nothing it could replay, and it must never send fresh."""
        send = test_signer.send_via_safe if via_safe else test_signer.send
        with pytest.raises(SignerError, match="needs the request id"):
            send("testchain", TOKEN, data=TOKEN_CALL, replay_only=True)
        assert not fake_w3.eth.sent

    def test_holds_request_keeps_the_two_paths_apart(
        self, test_signer: Signer, fake_w3: FakeW3, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A safe send's id is not the EOA's, and an in-flight one is held too.

        A wrong namespace would let a fresh EOA send ride on a completed
        safe send's id, uncharged.
        """
        assert not test_signer.holds_request("r1", True)
        test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL, request_id="r1")
        assert test_signer.holds_request("r1", True)
        assert not test_signer.holds_request("r1", False)
        test_signer.send("testchain", TOKEN, data=TOKEN_CALL, request_id="r2")
        assert test_signer.holds_request("r2", False)
        assert not test_signer.holds_request("r2", True)
        seen: list = []
        send_raw = fake_w3.eth.send_raw_transaction

        def mid_broadcast(raw: bytes) -> t.Any:
            seen.append(test_signer.holds_request("r3", False))
            return send_raw(raw)

        monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", mid_broadcast)
        test_signer.send("testchain", TOKEN, data=TOKEN_CALL, request_id="r3")
        assert seen == [True]  # in flight counts as held

    def test_no_simulation_means_no_signature(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """An RPC that refuses eth_simulateV1 refuses the send, naming the cause."""
        fake_w3.provider.unavailable = True
        with pytest.raises(SignerError, match="'simulation-unavailable'"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
        assert not fake_w3.eth.sent

    def test_a_raising_provider_is_simulation_unavailable(
        self,
        test_signer: Signer,
        fake_w3: FakeW3,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A transport error is the same refusal as an RPC that says no."""

        def boom(method: str, params: list) -> dict:
            raise ConnectionError("rpc down")

        monkeypatch.setattr(fake_w3.provider, "make_request", boom)
        with pytest.raises(SignerError, match="'simulation-unavailable'") as refused:
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
        assert "rpc down" not in str(refused.value)  # the RPC's text: log only

    def test_an_unreachable_rpc_is_simulation_unavailable(
        self, test_signer: Signer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Building the chain's client needs the RPC too; failing that is the same."""

        def no_client(chain: str) -> t.Any:
            raise ConnectionError("no route")

        monkeypatch.setattr(test_signer, "w3", no_client)
        reason = test_signer.refusal_reason(
            "testchain", EOA, value=1, intent=pay(EOA, 1)
        )
        assert reason is not None
        assert "'simulation-unavailable'" in reason

    def test_a_bad_intent_is_refused_without_simulating(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A malformed intent is the caller's mistake, named as bad-intent."""
        with pytest.raises(SignerError, match="'bad-intent'"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent="spend it")
        assert fake_w3.provider.simulated == []

    def test_server_built_transactions_skip_the_gate(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """The mech flow and the top-up build their own calls; no intent applies."""
        test_signer.send_via_safe("testchain", EOA, value=5, intent=SERVER_BUILT)
        test_signer.send("testchain", EOA, value=5, intent=SERVER_BUILT)
        assert fake_w3.provider.simulated == []
        assert len(fake_w3.eth.sent) == 2
        assert repr(SERVER_BUILT) == "SERVER_BUILT"

    def test_unaudited_refusal_records_nothing(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """audit=False callers audit outcomes themselves, refusals included."""
        fake_w3.provider.logs = [_approval_log(10)]
        with pytest.raises(SignerError):
            test_signer.send_via_safe("testchain", TOKEN, data=TOKEN_CALL, audit=False)
        assert not [e for e in audit_entries(store_path) if e["kind"] == "refusal"]

    def test_check_reports_the_gate_problems(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A dry run answers what the send would: the same rules, nothing spent."""
        fake_w3.provider.logs = [_approval_log(10)]
        reason, problems = test_signer.check("testchain", TOKEN, data=TOKEN_CALL)
        assert reason is not None
        assert "undeclared-approval" in reason
        assert [p["rule"] for p in problems] == ["undeclared-approval"]
        fake_w3.provider.logs = []
        assert test_signer.check(
            "testchain", EOA, value=5, intent=pay(EOA, 5), via_safe=False
        ) == (None, [])

    def test_an_eoa_exec_transaction_is_gated_as_the_safe(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """send_transaction to the safe with execTransaction moves the safe's assets.

        Simulated as the EOA it would look like it moves nothing; the gate
        simulates the call inside it, as the safe, so the safe's grant counts.
        """
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0xabcdef", owner=test_signer.address
        )
        fake_w3.provider.logs = [_approval_log(10)]  # granted by the safe
        with pytest.raises(SignerError, match="'undeclared-approval'"):
            test_signer.send("testchain", SAFE, data=calldata)
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        assert fake_w3.provider.simulated[-1]["to"] == EOA
        assert fake_w3.provider.simulated[-1]["data"] == "0xabcdef"
        fake_w3.provider.logs = []
        test_signer.send("testchain", SAFE, data=calldata, intent=pay(EOA, 7))
        assert len(fake_w3.eth.sent) == 1
        with pytest.raises(SignerError, match="may not also carry value"):
            test_signer.send(
                "testchain", SAFE, value=1, data=calldata, intent=pay(EOA, 7)
            )
        with pytest.raises(ValueError, match="could not decode"):
            safe_module.SafeExec.decode("0x6a761202" + "zz")
        with pytest.raises(ValueError, match="not execTransaction"):
            safe_module.SafeExec.decode("0x12345678")

    @pytest.mark.parametrize("field", [6, 7, 8])
    def test_an_eoa_exec_transaction_may_not_pay_a_gas_refund(
        self, test_signer: Signer, fake_w3: FakeW3, field: int
    ) -> None:
        """A refund in gasToken to refundReceiver is paid outside the inner call.

        The gate simulates only the inner call, so a refund would move the
        safe's assets unseen: gasPrice, gasToken and refundReceiver must be 0.
        """
        from eth_abi import encode  # pylint: disable=import-outside-toplevel

        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        args: list = [EOA, 0, b"", 0, 0, 0, 0, safe_module.ZERO_ADDRESS]
        args += [safe_module.ZERO_ADDRESS, b""]
        args[field] = 10**18 if field == 6 else EOA
        calldata = "0x" + safe_module.EXEC_TRANSACTION_SELECTOR
        calldata += encode(safe_module.EXEC_TRANSACTION_TYPES, args).hex()
        with pytest.raises(SignerError, match="may not pay a gas refund"):
            test_signer.send("testchain", SAFE, data=calldata, intent={})
        assert fake_w3.provider.simulated == []
        assert fake_w3.eth.sent == []

    def test_an_approve_hash_is_refused_and_audited(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """A pre-approved safe tx hash could later be executed by anyone, unseen."""
        calldata = "0xd4d9bdcd" + "ab" * 32
        with pytest.raises(SignerError, match="'approve-hash'"):
            test_signer.send("testchain", SAFE, data=calldata)
        assert fake_w3.provider.simulated == []
        assert fake_w3.eth.sent == []
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["rule"] == "approve-hash"
        reason, problems = test_signer.check(
            "testchain", SAFE, data=calldata, via_safe=False
        )
        assert "'approve-hash'" in str(reason)
        assert problems[0]["rule"] == "approve-hash"

    def test_an_uppercase_hex_prefix_is_read_as_the_same_bytes(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """`0X...` signs the same bytes as `0x...`, so it meets the same checks.

        A selector check that stripped only `0x` would simulate the EOA's own
        call, which moves nothing, and the safe's execTransaction inside would
        be signed unchecked; approveHash would slip past its refusal.
        """
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0xabcdef", owner=test_signer.address
        )
        fake_w3.provider.logs = [_approval_log(10)]
        with pytest.raises(SignerError, match="'undeclared-approval'"):
            test_signer.send("testchain", SAFE, data="0X" + calldata[2:])
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        with pytest.raises(SignerError, match="'approve-hash'"):
            test_signer.send("testchain", SAFE, data="0Xd4d9bdcd" + "ab" * 32)
        assert fake_w3.eth.sent == []
        rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert rules == ["undeclared-approval", "approve-hash"]

    def test_the_floor_reads_an_uppercase_hex_prefix(
        self, test_signer: Signer, guard: Guard, fake_w3: FakeW3
    ) -> None:
        """The guard's floor decodes `0X` execTransaction calldata too."""
        from eth_abi import encode  # pylint: disable=import-outside-toplevel

        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        test_signer.set_guard(guard)
        args: list = [EOA, 0, b"", 1, 0, 0, 0, safe_module.ZERO_ADDRESS]
        args += [safe_module.ZERO_ADDRESS, b""]
        calldata = "0X" + safe_module.EXEC_TRANSACTION_SELECTOR
        calldata += encode(safe_module.EXEC_TRANSACTION_TYPES, args).hex()
        with pytest.raises(SignerError, match="delegatecall"):
            test_signer.send("testchain", TOKEN, data=calldata, intent={})
        assert fake_w3.eth.sent == []

    def test_a_checksummed_safe_address_still_unwraps(
        self, test_signer: Signer, app_config: AppConfig, fake_w3: FakeW3
    ) -> None:
        """The safe is matched case-insensitively, whichever side is checksummed."""
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        lower = "0x" + "ab" * 20
        app_config.chain("testchain").safe_address = (
            "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB"
        )
        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0x", owner=test_signer.address
        )
        fake_w3.provider.logs = [_approval_log(10, owner=lower)]
        with pytest.raises(SignerError, match="'undeclared-approval'"):
            test_signer.send("testchain", lower, data=calldata)
        assert fake_w3.provider.simulated[-1]["from"].lower() == lower

    def test_exec_transaction_bytes_to_another_contract_run_as_the_eoa(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Only the configured safe unwraps them: elsewhere the EOA's call runs."""
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0x", owner=test_signer.address
        )
        test_signer.send("testchain", TOKEN, data=calldata)
        assert fake_w3.provider.simulated[-1]["from"] == test_signer.address
        assert fake_w3.provider.simulated[-1]["to"] == TOKEN

    def test_the_dry_runs_answer_as_the_send_does(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """check() and simulate() unwrap, and refuse, an EOA execTransaction too."""
        from eth_abi import encode  # pylint: disable=import-outside-toplevel

        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        moving = safe_module.exec_transaction(
            target=EOA, value=7, data="0x", owner=test_signer.address
        )
        fake_w3.provider.logs = [_approval_log(10)]
        reason, problems = test_signer.check(
            "testchain", SAFE, data=moving, via_safe=False
        )
        assert "'undeclared-approval'" in str(reason)
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        args: list = [EOA, 0, b"", 1, 0, 0, 0, safe_module.ZERO_ADDRESS]
        args += [safe_module.ZERO_ADDRESS, b""]
        delegate = "0x" + safe_module.EXEC_TRANSACTION_SELECTOR
        delegate += encode(safe_module.EXEC_TRANSACTION_TYPES, args).hex()
        result = test_signer.simulate("testchain", SAFE, data=delegate, via_safe=False)
        assert result["fits_intent"] is False
        assert _rules(result["problems"])[0] == "bad-exec-transaction"
        assert "DELEGATECALL" in result["problems"][0]
        args[3], args[6] = 0, 1
        refund = "0x" + safe_module.EXEC_TRANSACTION_SELECTOR
        refund += encode(safe_module.EXEC_TRANSACTION_TYPES, args).hex()
        reason, _ = test_signer.check(
            "testchain", SAFE, data=refund, via_safe=False, intent={}
        )
        assert "may not pay a gas refund" in str(reason)
        bad = test_signer.simulate(
            "testchain", SAFE, data="0x6a761202zz", via_safe=False
        )
        assert _rules(bad["problems"])[0] == "bad-exec-transaction"

    def test_a_replay_answers_before_the_gate(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A completed send replays its hash even when the RPC cannot simulate now."""
        first = test_signer.send_via_safe(
            "testchain", EOA, value=1, intent=pay(EOA, 1), request_id="r1"
        )
        simulated = len(fake_w3.provider.simulated)
        fake_w3.provider.unavailable = True
        again = test_signer.send_via_safe(
            "testchain", EOA, value=1, intent=pay(EOA, 1), request_id="r1"
        )
        assert again == first
        assert len(fake_w3.provider.simulated) == simulated

    def test_the_guard_answers_before_anything_is_simulated(
        self, test_signer: Signer, fake_w3: FakeW3, guard: Guard
    ) -> None:
        """A floor refusal (the safe calling itself) never reaches the RPC."""
        test_signer.set_guard(guard)
        with pytest.raises(SignerError, match="may not call itself"):
            test_signer.send_via_safe("testchain", SAFE, value=1, intent=pay(SAFE, 1))
        assert fake_w3.provider.simulated == []

    def test_unreadable_rpc_answers_are_simulation_unavailable(
        self,
        test_signer: Signer,
        fake_w3: FakeW3,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A recipient lookup that fails, or an answer with no result, refuses by rule."""

        def no_code(address: str) -> bytes:
            raise ConnectionError("getCode timed out")

        monkeypatch.setattr(fake_w3.eth, "get_code", no_code)
        with pytest.raises(SignerError, match="'simulation-unavailable'"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
        monkeypatch.setattr(fake_w3.provider, "make_request", lambda m, p: {})
        with pytest.raises(SignerError, match="'simulation-unavailable'"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))

    def test_a_garbled_answer_building_the_client_is_the_rpcs_fault(
        self, test_signer: Signer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """eth_chainId answering non-JSON is a ValueError, but not the caller's."""

        def garbled(chain: str) -> t.Any:
            raise json.JSONDecodeError("Expecting value", "<html>", 0)

        monkeypatch.setattr(test_signer, "w3", garbled)
        reason, problems = test_signer.check(
            "testchain", EOA, value=1, intent=pay(EOA, 1)
        )
        assert "'simulation-unavailable'" in str(reason)
        assert problems[0]["rule"] == "simulation-unavailable"
        with pytest.raises(ValueError, match="mystery"):  # an unknown chain is
            test_signer.simulate("mystery", EOA, via_safe=False)


@pytest.mark.parametrize(
    ("stage", "error", "said"),
    [
        ("broadcast", ConnectionError("read timed out"), SEND_UNKNOWN),
        ("broadcast", TimeoutError("read timed out"), SEND_UNKNOWN),
        ("broadcast", ValueError("nonce too low"), SEND_FAILED),  # the RPC answered
        # web3 7's node rejection, which is not a ValueError
        ("broadcast", Web3RPCError("replacement transaction underpriced"), SEND_FAILED),
        ("estimate", ConnectionError("rpc down"), SEND_FAILED),  # nothing signed
    ],
)
def test_a_failed_send_says_whether_it_may_have_been_broadcast(
    test_signer: Signer,
    fake_w3: FakeW3,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    error: Exception,
    said: str,
) -> None:
    """Only a broadcast the RPC never answered is possibly sent; retrying it pays twice."""

    def broken(*_args: t.Any) -> t.Any:
        raise error

    name = {"broadcast": "send_raw_transaction", "estimate": "estimate_gas"}[stage]
    monkeypatch.setattr(fake_w3.eth, name, broken)
    with pytest.raises(SignerError) as failed:
        test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1))
    assert str(failed.value).startswith(said)


# an RPC key in a URL's path, as a provider puts it there
RPC_KEY = "k3y" + "0f9a" * 16


def test_a_failed_send_s_record_and_log_carry_the_message_s_redaction(
    test_signer: Signer,
    fake_w3: FakeW3,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The caller's message, the send_failed record and the log keep no RPC key."""

    def broken(*_args: t.Any) -> t.Any:
        raise ValueError(f"rejected by https://rpc.example/v2/{RPC_KEY}?x=1")

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", broken)
    with caplog.at_level("WARNING", logger="agent"), pytest.raises(SignerError) as e:
        test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1))
    assert str(e.value) == SEND_FAILED
    (failed,) = [r for r in audit_entries(store_path) if r["kind"] == "send_failed"]
    assert failed["error"] == "ValueError: rejected by https://rpc.example/..."
    assert RPC_KEY not in json.dumps(audit_entries(store_path))
    assert "https://rpc.example/..." in caplog.text
    assert RPC_KEY not in caplog.text


def _raise_chained(link: str) -> None:
    """Raise a RuntimeError whose `link` (__cause__ or __context__) names an RPC key."""
    try:
        raise ConnectionError(f"https://rpc.example/v2/{RPC_KEY}?x=1 refused")
    except ConnectionError as inner:
        if link == "__cause__":
            raise RuntimeError("the read failed") from inner
        raise RuntimeError("the read failed")  # pylint: disable=raise-missing-from


@pytest.mark.parametrize("link", ["__cause__", "__context__"])
def test_a_cause_s_url_is_redacted_wherever_it_sits_in_the_chain(link: str) -> None:
    """A URL only in an inner link is cut to scheme and host, in the record and the log."""
    with pytest.raises(RuntimeError) as raised:
        _raise_chained(link)
    assert getattr(raised.value, link) is not None
    said = cause_of(raised.value)
    assert said == (
        "RuntimeError: the read failed <- "
        "ConnectionError: https://rpc.example/... refused"
    )
    assert RPC_KEY not in logged_cause(raised.value)


def test_a_logged_cause_says_where_each_link_was_raised() -> None:
    """Each link's frames name its file, line and function, so our own bug is found."""
    with pytest.raises(RuntimeError) as raised:
        _raise_chained("__cause__")
    logged = logged_cause(raised.value)
    assert logged.startswith(cause_of(raised.value) + "\n")
    assert "RuntimeError raised at:" in logged
    assert "ConnectionError raised at:" in logged
    assert f'"{__file__}", line ' in logged
    assert "in _raise_chained" in logged
    assert RPC_KEY not in logged


def test_a_failed_send_s_log_locates_the_code_that_failed(
    test_signer: Signer,
    fake_w3: FakeW3,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed send logs the frames it was raised from, never the RPC's key."""

    def refused_broadcast(*_args: t.Any) -> t.Any:
        raise ValueError(f"rejected by https://rpc.example/v2/{RPC_KEY}?x=1")

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", refused_broadcast)
    with caplog.at_level("WARNING", logger="agent"), pytest.raises(SignerError):
        test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1))
    (record,) = [r for r in caplog.records if r.message.startswith("send on ")]
    assert "ValueError raised at:" in record.message
    assert "in refused_broadcast" in record.message
    assert RPC_KEY not in record.message


def test_an_unavailable_simulation_s_log_locates_the_code_that_failed(
    test_signer: Signer,
    monkeypatch: pytest.MonkeyPatch,
    store_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A bug under the gate's simulation logs its frames, never a library's text."""

    def buggy_simulate(*_args: t.Any, **_kwargs: t.Any) -> t.Any:
        try:
            raise TypeError(f"bad log from https://rpc.example/v2/{RPC_KEY}")
        except TypeError as e:
            raise intent_module.SimulationUnavailable(str(e)) from e

    monkeypatch.setattr(intent_module, "simulate", buggy_simulate)
    with caplog.at_level("WARNING", logger="agent"), pytest.raises(SignerError):
        test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
    (record,) = [r for r in caplog.records if "cannot simulate" in r.message]
    assert "in buggy_simulate" in record.message
    assert "TypeError raised at:" in record.message
    assert RPC_KEY not in record.message
    assert RPC_KEY not in json.dumps(audit_entries(store_path))


@pytest.mark.parametrize("value", [0, 1])
def test_an_unreadable_prepaid_tracker_table_refuses_every_send_unsimulated(
    test_signer: Signer,
    fake_w3: FakeW3,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    value: int,
) -> None:
    """A prepaid fall the gate could not see is spend: no table, no signature."""

    def unreadable(_chain: str) -> dict[str, str]:
        raise ValueError("invalid literal for int() with base 10: 'not-a-number'")

    monkeypatch.setattr(signer_module, "prepaid_balance_trackers", unreadable)
    with caplog.at_level("WARNING", logger="agent"):
        with pytest.raises(SignerError, match="'simulation-unavailable'"):
            test_signer.send_via_safe(
                "testchain", EOA, value=value, intent=pay(EOA, value)
            )
        verdict = test_signer.simulate("testchain", EOA, value=value)
    assert not fake_w3.eth.sent
    assert not fake_w3.provider.simulated
    assert _rules(verdict["problems"]) == ["simulation-unavailable"]
    record, _ = [r for r in caplog.records if "cannot simulate" in r.message]
    assert "ValueError raised at:" in record.message
    assert "in unreadable" in record.message


def test_a_possibly_sent_broadcast_with_no_request_id_promises_no_replay(
    test_signer: Signer, fake_w3: FakeW3, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no request_id nothing is held: the caller gets the hash to look up."""

    def timed_out(_raw: bytes) -> t.Any:
        raise TimeoutError("read timed out")

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", timed_out)
    with pytest.raises(SendUnknown) as failed:
        test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1))
    said = str(failed.value)
    assert failed.value.tx_hash in said
    assert "request_id" not in said
    assert "or the account's nonce before sending again" in said


def test_a_possibly_sent_broadcast_names_its_hash_nonce_and_id_for_the_operator(
    test_signer: Signer,
    fake_w3: FakeW3,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The warning and the send_failed record both say where to look on chain."""
    fake_w3.eth.pending_nonce = nonce = 7

    def timed_out(_raw: bytes) -> t.Any:
        raise TimeoutError("read timed out")

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", timed_out)
    with caplog.at_level(logging.WARNING, logger="agent"):
        with pytest.raises(SendUnknown) as failed:
            test_signer.send(
                "testchain", EOA, value=1, intent=pay(EOA, 1), request_id="op-1"
            )
    tx_hash = failed.value.tx_hash
    (record,) = [e for e in audit_entries(store_path) if e["kind"] == "send_failed"]
    assert (record["tx_hash"], record["nonce"], record["request_id"]) == (
        tx_hash,
        nonce,
        "op-1",
    )
    (warning,) = [r for r in caplog.records if "may have landed" in r.getMessage()]
    for named in (tx_hash, f"'nonce': {nonce}", "'request_id': 'op-1'"):
        assert named in warning.getMessage()


@pytest.mark.parametrize("via_safe", [False, True])
def test_a_retry_of_a_possibly_sent_broadcast_replays_its_hash(
    test_signer: Signer,
    fake_w3: FakeW3,
    monkeypatch: pytest.MonkeyPatch,
    via_safe: bool,
) -> None:
    """The node took the transaction but the answer timed out: a retry sends nothing."""
    taken: list[bytes] = []

    def timed_out(raw: bytes) -> t.Any:
        taken.append(bytes(raw))  # the node has it
        raise TimeoutError("read timed out")

    monkeypatch.setattr(fake_w3.eth, "send_raw_transaction", timed_out)
    send = test_signer.send_via_safe if via_safe else test_signer.send
    target = TOKEN if via_safe else EOA
    with pytest.raises(SendUnknown) as failed:
        send("testchain", target, value=1, intent=pay(target, 1), request_id="x")
    assert "its request_id stays held with that hash" in str(failed.value)
    assert test_signer.holds_request("x", via_safe)
    with pytest.raises(SendUnknown) as replayed:  # never as a confirmed send
        send("testchain", target, value=1, intent=pay(target, 1), request_id="x")
    (raw,) = taken  # one broadcast, never a second at the next nonce
    assert replayed.value.tx_hash == Web3.keccak(raw).to_0x_hex()
    assert str(replayed.value) == str(failed.value)
    # a different call under the held id is refused as one, never handed the
    # possibly-sent hash of a transaction it did not ask for
    with pytest.raises(SignerError, match="already used for a different call") as other:
        send("testchain", target, value=2, intent=pay(target, 2), request_id="x")
    assert not isinstance(other.value, SendUnknown)
    assert len(taken) == 1
    assert not fake_w3.eth.sent


def test_a_send_that_failed_before_broadcasting_frees_its_request_id(
    test_signer: Signer, fake_w3: FakeW3
) -> None:
    """A node rejection sent nothing: the same request id may send again."""
    fake_w3.eth.fail_broadcast = True
    with pytest.raises(SignerError, match="the RPC could not take"):
        test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1), request_id="y")
    assert not test_signer.holds_request("y", via_safe=False)
    fake_w3.eth.fail_broadcast = False
    test_signer.send("testchain", EOA, value=1, intent=pay(EOA, 1), request_id="y")
    assert len(fake_w3.eth.sent) == 1


class TestSimulate:
    """Signer.simulate backs the simulate_transaction tool."""

    def test_reports_the_diff_and_the_verdict(self, test_signer: Signer) -> None:
        """The asset diff plus fits_intent and problems."""
        result = test_signer.simulate("testchain", EOA, value=5)
        assert result["native"] == "-5"
        assert result["fits_intent"] is True  # strict: held to what it says
        assert result["problems"] == []
        fits = test_signer.simulate("testchain", EOA, value=5, intent=pay(EOA, 5))
        assert fits["fits_intent"] is True
        assert fits["problems"] == []

    def test_strict_simulation_answers_as_the_send_would(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A no-intent approval is reported, as the send refuses it."""
        fake_w3.provider.logs = [_approval_log(10)]
        result = test_signer.simulate("testchain", TOKEN, data=TOKEN_CALL)
        assert result["fits_intent"] is False
        assert _rules(result["problems"]) == ["undeclared-approval"]
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = {"message": "execution reverted"}
        reverted = test_signer.simulate("testchain", EOA, value=5)
        assert _rules(reverted["problems"])[0] == "reverts"

    def test_simulate_only_answers_a_no_intent_call_with_no_verdict(
        self,
        account: LocalAccount,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
    ) -> None:
        """The bench's position: no verdict, and a revert shows in the diff alone."""
        signer = on_fake_chain(
            Signer(account, app_config, activity, switches=TEST_INTERFACE), fake_w3
        )
        fake_w3.provider.logs = [_approval_log(10)]
        granted = signer.simulate("testchain", TOKEN, data=TOKEN_CALL)
        assert (granted["fits_intent"], granted["problems"]) == (None, [])
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = {"message": "execution reverted"}
        result = signer.simulate("testchain", EOA, value=5)
        assert result["ok"] is False
        assert result["fits_intent"] is None
        assert result["problems"] == []

    def test_a_problem_is_the_reference_s_string(self, test_signer: Signer) -> None:
        """Each problem reads `intent gate: rule '<id>' (<detail>)`."""
        result = test_signer.simulate("testchain", EOA, value=5, intent=pay(EOA, 4))
        assert result["problems"] == [
            "intent gate: rule 'overspend' (native: spends 5, intent allows 4)"
        ]

    def test_bad_intent_and_unavailable_rpc(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Neither yields a diff; both say why."""
        bad = test_signer.simulate("testchain", EOA, intent=[1])
        assert bad["fits_intent"] is False
        assert _rules(bad["problems"])[0] == "bad-intent"
        fake_w3.provider.unavailable = True
        down = test_signer.simulate("testchain", EOA, via_safe=False)
        assert _rules(down["problems"])[0] == "simulation-unavailable"

    def test_needs_a_safe_on_the_safe_path(
        self, test_signer: Signer, app_config: AppConfig
    ) -> None:
        """No safe on the chain: the same refusal the send gives."""
        app_config.chains["testchain"].safe_address = None
        with pytest.raises(SignerError, match="no service safe"):
            test_signer.simulate("testchain", EOA)


class TestTools:
    """The MCP surface of the gate and the read tools."""

    async def test_safe_transaction_takes_an_intent(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """The tool forwards the intent to the gate."""
        result = await tools["safe_transaction"](
            "testchain", EOA, 5, intent=pay(EOA, 5)
        )
        assert result["tx_hash"].startswith("0x")
        with pytest.raises(SignerError, match="undeclared-recipient"):
            await tools["safe_transaction"](
                "testchain", EOA, 5, intent={"spend": {"native": "5"}}
            )

    async def test_preflight_runs_no_gate(
        self, tools: dict[str, t.Callable], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A value-moving call with no intent is permitted, and nothing simulated."""
        monkeypatch.setattr(
            intent_module, "simulate", lambda *a, **k: pytest.fail("simulated")
        )
        assert await tools["preflight_transaction"]("testchain", EOA, 5) == {
            "permitted": True
        }

    async def test_preflight_permits_a_call_that_would_revert(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """The guardrail permits these bytes; whether they revert is not asked."""
        fake_w3.provider.status = "0x0"
        fake_w3.provider.error = {"message": "execution reverted"}
        assert await tools["preflight_transaction"](
            "testchain", TOKEN, data=TOKEN_CALL
        ) == {"permitted": True}
        assert fake_w3.provider.simulated == []

    async def test_simulate_transaction_tool(
        self, tools: dict[str, t.Callable]
    ) -> None:
        """The tool is Signer.simulate over the worker thread."""
        result = await tools["simulate_transaction"]("testchain", EOA, 5)
        assert result["native"] == "-5"

    async def test_read_tools(
        self,
        tools: dict[str, t.Callable],
        fake_w3: FakeW3,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """chain_call, get_abi and decode_calldata reach the read helpers."""
        monkeypatch.setattr(
            chain_read, "chain_call", lambda w3, to, data, block: {"result": block}
        )
        monkeypatch.setattr(chain_read, "get_abi", lambda w3, address: {"a": address})
        assert await tools["chain_call"]("testchain", EOA, "0x", "pending") == {
            "result": "pending"
        }
        assert await tools["get_abi"]("testchain", EOA) == {"a": EOA}
        decoded = await tools["decode_calldata"]("testchain", "0x095ea7b3")
        assert decoded["signature"] == "approve(address,uint256)"


def test_http_routes_take_an_intent(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
    fake_w3: FakeW3,
) -> None:
    """Skill scripts pass intents through the HTTP routes; a broken one is a 400."""
    app = make_app(test_signer, app_config, activity, token=TOKEN_TOKEN)
    headers = {"Authorization": f"Bearer {TOKEN_TOKEN}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        refused = client.post(
            "/safe-transaction",
            json={
                "chain": "testchain",
                "target": EOA,
                "value": 5,
                "intent": {"spend": {"native": 5}},
            },
            headers=headers,
        )
        sent = client.post(
            "/safe-transaction",
            json={
                "chain": "testchain",
                "target": EOA,
                "value": 5,
                "intent": pay(EOA, 5),
            },
            headers=headers,
        )
    assert refused.status_code == 400
    assert "undeclared-recipient" in refused.json()["detail"]
    assert sent.status_code == 200
