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
import typing as t

import pytest
from fastapi.testclient import TestClient

from connect import chain_read
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import MechService
from connect.server.auth import GrantStore
from connect.server.mcp_tools import build_mcp
from connect.settings import SettingsStore
from connect.signer import SERVER_BUILT, Signer, SignerError

from tests.conftest import FakeW3, audit_entries, pay

SAFE = "0x" + "22" * 20
EOA = "0x" + "aa" * 20
TOKEN = "0x" + "70" * 20
SPENDER = "0x" + "5e" * 20
TOKEN_CALL = "0x" + "12" * 4
TOKEN_TOKEN = "unit-test-token"  # nosec B105


def _approval_log(amount: int) -> dict:
    return {
        "address": TOKEN,
        "topics": [
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925",
            "0x" + SAFE[2:].rjust(64, "0"),
            "0x" + SPENDER[2:].rjust(64, "0"),
        ],
        "data": "0x" + hex(amount)[2:].rjust(64, "0"),
    }


@pytest.fixture
def tools(  # pylint: disable=too-many-arguments
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    guard: Guard,
    mech_service: MechService,
    settings_store: SettingsStore,
) -> dict[str, t.Callable]:
    """Return the registered MCP tool functions keyed by name."""
    test_signer.set_guard(guard)
    mcp = build_mcp(
        test_signer,
        app_config,
        activity,
        guard=guard,
        mech=mech_service,
        settings_store=settings_store,
        grants=GrantStore("workspace-token"),
    )
    manager = mcp._tool_manager  # pylint: disable=protected-access
    return {tool.name: tool.fn for tool in manager.list_tools()}


class TestSignerGate:
    """The gate sits after the guard on every agent-originated send."""

    def test_value_without_an_intent_is_refused_and_audited(
        self, test_signer: Signer, fake_w3: FakeW3, store_path: t.Any
    ) -> None:
        """No intent, value moves: refused naming missing-intent, nothing sent."""
        with pytest.raises(SignerError, match="rule 'missing-intent'"):
            test_signer.send_via_safe("testchain", EOA, value=5)
        assert not fake_w3.eth.sent
        (entry,) = [e for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert entry["rule"] == "missing-intent"
        assert entry["to"] == EOA

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
        with pytest.raises(SignerError, match="rpc down"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))

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
        self, test_signer: Signer, store_path: t.Any
    ) -> None:
        """audit=False callers audit outcomes themselves, refusals included."""
        with pytest.raises(SignerError):
            test_signer.send_via_safe("testchain", EOA, value=5, audit=False)
        assert not [e for e in audit_entries(store_path) if e["kind"] == "refusal"]

    def test_check_reports_the_gate_problems(self, test_signer: Signer) -> None:
        """A dry run answers what the send would: the same rules, nothing spent."""
        reason, problems = test_signer.check("testchain", EOA, value=5)
        assert reason is not None
        assert "missing-intent" in reason
        assert [p["rule"] for p in problems] == ["missing-intent"]
        assert test_signer.check(
            "testchain", EOA, value=5, intent=pay(EOA, 5), via_safe=False
        ) == (None, [])

    def test_an_eoa_exec_transaction_is_gated_as_the_safe(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """send_transaction to the safe with execTransaction moves the safe's assets.

        Simulated as the EOA it would look like it moves nothing; the gate
        simulates the call inside it, as the safe, so it needs an intent.
        """
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0xabcdef", owner=test_signer.address
        )
        with pytest.raises(SignerError, match="'missing-intent'"):
            test_signer.send("testchain", SAFE, data=calldata)
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        assert fake_w3.provider.simulated[-1]["to"] == EOA
        assert fake_w3.provider.simulated[-1]["data"] == "0xabcdef"
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
        be signed with no intent; approveHash would slip past its refusal.
        """
        from connect import (
            safe as safe_module,  # pylint: disable=import-outside-toplevel
        )

        calldata = safe_module.exec_transaction(
            target=EOA, value=7, data="0xabcdef", owner=test_signer.address
        )
        with pytest.raises(SignerError, match="'missing-intent'"):
            test_signer.send("testchain", SAFE, data="0X" + calldata[2:])
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        with pytest.raises(SignerError, match="'approve-hash'"):
            test_signer.send("testchain", SAFE, data="0Xd4d9bdcd" + "ab" * 32)
        assert fake_w3.eth.sent == []
        rules = [e["rule"] for e in audit_entries(store_path) if e["kind"] == "refusal"]
        assert rules == ["missing-intent", "approve-hash"]

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
        with pytest.raises(SignerError, match="'missing-intent'"):
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
        reason, problems = test_signer.check(
            "testchain", SAFE, data=moving, via_safe=False
        )
        assert "'missing-intent'" in str(reason)
        assert fake_w3.provider.simulated[-1]["from"] == SAFE
        args: list = [EOA, 0, b"", 1, 0, 0, 0, safe_module.ZERO_ADDRESS]
        args += [safe_module.ZERO_ADDRESS, b""]
        delegate = "0x" + safe_module.EXEC_TRANSACTION_SELECTOR
        delegate += encode(safe_module.EXEC_TRANSACTION_TYPES, args).hex()
        result = test_signer.simulate("testchain", SAFE, data=delegate, via_safe=False)
        assert result["fits_intent"] is False
        assert result["problems"][0]["rule"] == "bad-exec-transaction"
        assert "DELEGATECALL" in result["problems"][0]["detail"]
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
        assert bad["problems"][0]["rule"] == "bad-exec-transaction"

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
        with pytest.raises(SignerError, match="'simulation-unavailable'.*getCode"):
            test_signer.send_via_safe("testchain", EOA, value=1, intent=pay(EOA, 1))
        monkeypatch.setattr(fake_w3.provider, "make_request", lambda m, p: {})
        with pytest.raises(SignerError, match="no result in the answer"):
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


class TestSimulate:
    """Signer.simulate backs the simulate_transaction tool."""

    def test_reports_the_diff_and_the_verdict(self, test_signer: Signer) -> None:
        """The asset diff plus fits_intent and problems."""
        result = test_signer.simulate("testchain", EOA, value=5)
        assert result["native"] == "-5"
        assert result["fits_intent"] is None  # no intent given
        assert [p["rule"] for p in result["problems"]] == ["missing-intent"]
        fits = test_signer.simulate("testchain", EOA, value=5, intent=pay(EOA, 5))
        assert fits["fits_intent"] is True
        assert fits["problems"] == []

    def test_bad_intent_and_unavailable_rpc(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Neither yields a diff; both say why."""
        bad = test_signer.simulate("testchain", EOA, intent=[1])
        assert bad["fits_intent"] is False
        assert bad["problems"][0]["rule"] == "bad-intent"
        fake_w3.provider.unavailable = True
        down = test_signer.simulate("testchain", EOA, via_safe=False)
        assert down["problems"][0]["rule"] == "simulation-unavailable"

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
        with pytest.raises(SignerError, match="missing-intent"):
            await tools["safe_transaction"]("testchain", EOA, 5)

    async def test_preflight_reports_problems(
        self, tools: dict[str, t.Callable]
    ) -> None:
        """A gate refusal comes back with its problems listed."""
        refused = await tools["preflight_transaction"]("testchain", EOA, 5)
        assert refused["allowed"] is False
        assert refused["problems"][0]["rule"] == "missing-intent"
        allowed = await tools["preflight_transaction"](
            "testchain", EOA, 5, intent=pay(EOA, 5)
        )
        assert allowed == {"allowed": True}

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
    """Skill scripts pass intents through the HTTP routes; a missing one is a 400."""
    app = make_app(test_signer, app_config, activity, token=TOKEN_TOKEN)
    headers = {"Authorization": f"Bearer {TOKEN_TOKEN}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        refused = client.post(
            "/safe-transaction",
            json={"chain": "testchain", "target": EOA, "value": 5},
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
    assert "missing-intent" in refused.json()["detail"]
    assert sent.status_code == 200
