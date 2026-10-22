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

"""The agent top-up: the rule, the /funds-status deficits it leaves, the task."""

import asyncio
import json
import logging
import threading
import time
import typing as t

import pytest
from fastapi.testclient import TestClient
from web3 import Web3

from connect import wallet
from connect.activity import ActivityLog, PERFORMANCE_FILE
from connect.config import AppConfig, ChainConfig, FundRequirement, NATIVE_ASSET
from connect.guard import Guard
from connect.server import app as app_module
from connect.settings import MODE_RESTRICTED, Protected, Settings, SettingsStore
from connect.signer import Signer, SignerError, _ChainState
from connect.wallet import AgentTopUp, plan_agent_topup

from tests.conftest import FakeW3, audit_entries

SAFE = "0x" + "22" * 20
TOKEN = "0x" + "77" * 20

AGENT_NATIVE = FundRequirement(threshold=100, topup=500)
SAFE_NATIVE = FundRequirement(threshold=1000, topup=5000)
REQUIREMENTS = {
    "agent": {NATIVE_ASSET: AGENT_NATIVE},
    "safe": {NATIVE_ASSET: SAFE_NATIVE},
}


class BalancesW3(FakeW3):
    """Fake Web3 answering a native balance per address; sends are mined."""

    def __init__(self, balances: dict[str, int]) -> None:
        """Hold the balances, keyed by any-case address."""
        super().__init__()
        self.balances = {k.lower(): v for k, v in balances.items()}
        self.eth.get_balance = self._balance  # type: ignore[method-assign]
        self.eth.receipt = {"status": 1}

    def _balance(self, address: str) -> int:
        """Return the address's balance."""
        return self.balances[address.lower()]


def _signer_on(test_signer: Signer, w3: FakeW3, chain: str = "testchain") -> Signer:
    """Point one of the signer's chains at the given fake."""
    test_signer._chains._states[chain] = (  # pylint: disable=protected-access
        _ChainState(w3=t.cast(Web3, w3), lock=threading.Lock(), chain_id=31337)
    )
    return test_signer


class TestRule:
    """The per-chain rule, mirroring funds-manager's get_agent_topup."""

    @pytest.mark.parametrize(
        ("agent_balance", "safe_balance", "expected"),
        [
            # at the threshold: nothing due
            (100, 10_000, AgentTopUp(need=0, move=0)),
            # below it: up to topup, also from an empty EOA
            (99, 10_000, AgentTopUp(need=401, move=401)),
            (0, 10_000, AgentTopUp(need=500, move=500)),
            # the safe covers the need exactly
            (99, 401, AgentTopUp(need=401, move=401)),
            # the safe holds less: all of it moves
            (99, 400, AgentTopUp(need=401, move=400)),
            # the safe is empty
            (99, 0, AgentTopUp(need=401, move=0)),
        ],
    )
    def test_table(
        self, agent_balance: int, safe_balance: int, expected: AgentTopUp
    ) -> None:
        """Each row of the rule, with its boundaries."""
        assert plan_agent_topup(AGENT_NATIVE, agent_balance, safe_balance) == expected

    def test_topup_below_balance_is_nothing_due(self) -> None:
        """A topup under the balance (a misconfiguration) never asks for less than 0."""
        requirement = FundRequirement(threshold=100, topup=50)
        assert plan_agent_topup(requirement, 60, 10_000) == AgentTopUp(0, 0)


class TestAgentTopup:
    """agent_topup reads the balances it plans from."""

    def test_reads_both_native_balances(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """The agent EOA and the chain's safe are what the rule sees."""
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 99, SAFE: 400})
        )
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        assert wallet.agent_topup(app_config, signer) == {
            "testchain": AgentTopUp(need=401, move=400)
        }

    def test_only_configured_chains_with_a_safe(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """A chain without an RPC or without a safe gets no entry at all."""
        app_config.fund_requirements = {
            "testchain": REQUIREMENTS,
            "other": REQUIREMENTS,
        }
        app_config.chains["testchain"].safe_address = None
        assert not wallet.agent_topup(app_config, test_signer)

    @pytest.mark.parametrize(
        "requirements",
        [
            # no native safe entry
            {"agent": {NATIVE_ASSET: AGENT_NATIVE}, "safe": {TOKEN: SAFE_NATIVE}},
            {"agent": {NATIVE_ASSET: AGENT_NATIVE}},
            # no native agent entry: tokens never move
            {"agent": {TOKEN: AGENT_NATIVE}, "safe": {NATIVE_ASSET: SAFE_NATIVE}},
        ],
    )
    def test_no_rule_without_both_native_entries(
        self, app_config: AppConfig, test_signer: Signer, requirements: dict
    ) -> None:
        """Without a native entry for both roles, the chain is not planned."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 0, SAFE: 0}))
        app_config.fund_requirements = {"testchain": requirements}
        assert not wallet.agent_topup(app_config, signer)

    def test_unreadable_balance_leaves_the_chain_out(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An RPC failure plans nothing on that chain, and says why in the log."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 0}))
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        with caplog.at_level(logging.WARNING, logger="agent"):
            plans = wallet.agent_topup(app_config, signer)
        assert not plans
        assert "could not read native balances on testchain" in caplog.text


class TestFundsStatus:
    """/funds-status leaves the agent EOA to a top-up only once one has worked."""

    def _deficits(
        self, app_config: AppConfig, signer: Signer, topped_up: set[str]
    ) -> tuple[str, str]:
        """Return the (agent, safe) native deficits funds_status reports."""
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        report = wallet.funds_status(app_config, signer, topped_up)["testchain"]
        return (
            report[signer.address][NATIVE_ASSET]["deficit"],
            report[SAFE][NATIVE_ASSET]["deficit"],
        )

    @pytest.mark.parametrize(
        ("agent_balance", "safe_balance", "expected"),
        [
            # nothing due: the safe's own rule, up to its topup
            (100, 600, ("0", str(5000 - 600))),
            (100, 1000, ("0", "0")),
            # a full move: the safe is judged on what it keeps
            (99, 1401, ("0", "0")),
            (99, 1400, ("0", str(5000 - 999))),
            (99, 600, ("0", str(5000 - 199))),
            # a short move: the shortfall joins the safe's topup
            (99, 400, ("0", str(5000 + 1))),
            (99, 0, ("0", str(5000 + 401))),
        ],
    )
    def test_after_a_successful_topup(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        agent_balance: int,
        safe_balance: int,
        expected: tuple[str, str],
    ) -> None:
        """The safe is reported as it stands after the move; balances stay as read."""
        signer = _signer_on(
            test_signer,
            BalancesW3({test_signer.address: agent_balance, SAFE: safe_balance}),
        )
        assert self._deficits(app_config, signer, {"testchain"}) == expected

    @pytest.mark.parametrize(
        ("agent_balance", "safe_balance", "expected"),
        [
            (100, 10_000, ("0", "0")),
            (99, 10_000, ("401", "0")),
            (40, 0, ("460", "5000")),
        ],
    )
    def test_without_a_successful_topup(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        agent_balance: int,
        safe_balance: int,
        expected: tuple[str, str],
    ) -> None:
        """No success on the chain yet, or the last one failed: each role's own rule."""
        signer = _signer_on(
            test_signer,
            BalancesW3({test_signer.address: agent_balance, SAFE: safe_balance}),
        )
        assert self._deficits(app_config, signer, {"other"}) == expected

    def test_tokens_keep_their_own_rule(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A token entry beside the native ones is never touched by the rule."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 99, SAFE: 0}))
        real_balance = wallet.asset_balance

        def balance(w3: Web3, asset: str, address: str, chain: str) -> tuple[int, int]:
            """Answer the token from a fixed balance, natives from the fake."""
            if asset == TOKEN:
                return 2, 6
            return real_balance(w3, asset, address, chain)

        monkeypatch.setattr(wallet, "asset_balance", balance)
        requirements = {
            "agent": {NATIVE_ASSET: AGENT_NATIVE},
            "safe": {
                NATIVE_ASSET: SAFE_NATIVE,
                TOKEN: FundRequirement(threshold=10, topup=20),
            },
        }
        app_config.fund_requirements = {"testchain": requirements}
        report = wallet.funds_status(app_config, signer, {"testchain"})["testchain"]
        assert report[SAFE][TOKEN] == {"balance": "2", "deficit": "18", "decimals": 6}
        assert report[SAFE][NATIVE_ASSET]["deficit"] == str(5000 + 401)

    def test_without_both_native_entries_reports_as_read(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """A chain the top-up does not apply to keeps the agent EOA's own deficit."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 40}))
        app_config.fund_requirements = {
            "testchain": {"agent": {NATIVE_ASSET: AGENT_NATIVE}}
        }
        report = wallet.funds_status(app_config, signer, {"testchain"})["testchain"]
        assert report[signer.address][NATIVE_ASSET]["deficit"] == "460"


def _audited(app_config: AppConfig, kind: str) -> list[dict]:
    """Return the audit entries of one kind."""
    return [e for e in audit_entries(app_config.store_path) if e["kind"] == kind]


def _performance_card(app_config: AppConfig) -> tuple[int, str | None]:
    """Return the transactions metric and last_activity, as Pearl reads them."""
    payload = json.loads((app_config.store_path / PERFORMANCE_FILE).read_text())
    (metric,) = payload["metrics"]
    return metric["value"], payload["last_activity"]


class TestTopUpAgentSigner:
    """One check: a plain safe CALL per chain that has something to move."""

    @pytest.fixture
    def sends(
        self, test_signer: Signer, monkeypatch: pytest.MonkeyPatch
    ) -> list[tuple[str, str, int, str]]:
        """Record every send_via_safe while still sending it."""
        calls: list[tuple[str, str, int, str]] = []
        send_via_safe = test_signer.send_via_safe

        def spy(chain: str, target: str, **kwargs: t.Any) -> str:
            """Record the call, then send it for real (against the fake)."""
            calls.append((chain, target, kwargs["value"], kwargs["data"]))
            return send_via_safe(chain, target, **kwargs)

        monkeypatch.setattr(test_signer, "send_via_safe", spy)
        return calls

    def _restricted_guard(
        self, settings_store: SettingsStore, app_config: AppConfig, signer: Signer
    ) -> Guard:
        """Return a restricted guard with an empty whitelist, wired to the signer."""
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        guard = Guard(settings_store, app_config, agent_signer=signer.address)
        signer.set_guard(guard)
        return guard

    def _two_chains(self, app_config: AppConfig, signer: Signer) -> BalancesW3:
        """Add a "broken" chain before testchain, both due 401; return its fake."""
        app_config.chains = {
            "broken": ChainConfig(rpc_url="http://127.0.0.1:9", safe_address=SAFE),
            "testchain": app_config.chains["testchain"],
        }
        broken = BalancesW3({signer.address: 99, SAFE: 10_000})
        _signer_on(signer, broken, chain="broken")
        _signer_on(signer, BalancesW3({signer.address: 99, SAFE: 10_000}))
        app_config.fund_requirements = {
            "broken": REQUIREMENTS,
            "testchain": REQUIREMENTS,
        }
        return broken

    def test_moves_once_and_audits(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unrestricted: one bare native transfer, no allowance armed."""
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 99, SAFE: 10_000})
        )
        signer.set_guard(guard)
        armed: list[dict] = []
        monkeypatch.setattr(
            guard, "allow_agent_topup_once", lambda **k: armed.append(k)
        )
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        topped_up: set[str] = set()
        app_module.top_up_agent_signer(app_config, signer, guard, activity, topped_up)
        assert sends == [("testchain", signer.address, 401, "0x")]
        assert not armed
        assert topped_up == {"testchain"}
        (entry,) = _audited(app_config, "agent_topup")
        assert (entry["chain"], entry["value"]) == ("testchain", "401")
        assert entry["tx_hash"].startswith("0x")

    def test_a_topup_is_not_the_agent_s_activity(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
    ) -> None:
        """A top-up is audited only as itself; Pearl's card shows the agent's last act."""
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 99, SAFE: 10_000})
        )
        signer.set_guard(guard)
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        activity.record("sign_message", digest="0x" + "ab" * 32)
        app_module.top_up_agent_signer(app_config, signer, guard, activity, set())
        assert len(sends) == 1
        assert [e["kind"] for e in audit_entries(app_config.store_path)] == [
            "sign_message",
            "agent_topup",
        ]
        assert _performance_card(app_config) == (0, "sign_message")

    def test_restricted_arms_the_allowance_it_spends(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        settings_store: SettingsStore,
        activity: ActivityLog,
        sends: list,
    ) -> None:
        """Restricted, nothing whitelisted: the armed allowance lets the send pass, once."""
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 99, SAFE: 400})
        )
        guard = self._restricted_guard(settings_store, app_config, signer)
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        topped_up: set[str] = set()
        app_module.top_up_agent_signer(app_config, signer, guard, activity, topped_up)
        assert sends == [("testchain", signer.address, 400, "0x")]
        assert topped_up == {"testchain"}
        with pytest.raises(SignerError, match="do not allow the safe to call"):
            signer.send_via_safe("testchain", signer.address, value=400, data="0x")

    def test_restricted_refuses_without_the_allowance(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        settings_store: SettingsStore,
    ) -> None:
        """The same send, unarmed, is what restricted mode refuses."""
        signer = _signer_on(test_signer, BalancesW3({}))
        self._restricted_guard(settings_store, app_config, signer)
        with pytest.raises(SignerError, match="do not allow the safe to call"):
            signer.send_via_safe("testchain", signer.address, value=1, data="0x")

    def test_empty_safe_and_nothing_due_send_nothing(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An empty safe is logged and left to /funds-status; nothing is sent."""
        w3 = BalancesW3({test_signer.address: 99, SAFE: 0})
        signer = _signer_on(test_signer, w3)
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        topped_up = {"testchain"}
        with caplog.at_level(logging.INFO, logger="agent"):
            app_module.top_up_agent_signer(
                app_config, signer, guard, activity, topped_up
            )
            w3.balances[signer.address.lower()] = 100
            app_module.top_up_agent_signer(
                app_config, signer, guard, activity, topped_up
            )
        assert not sends
        assert topped_up == {"testchain"}  # no send, so no new outcome
        # nothing due is not worth a line every hour
        assert caplog.text.count("agent top-up on testchain") == 1
        assert "the safe holds no native token" in caplog.text

    @pytest.mark.parametrize(
        ("receipt", "error"),
        [({"status": 0}, "reverted"), (None, "not mined")],
    )
    def test_a_send_that_does_not_land_is_a_failure(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        receipt: dict | None,
        error: str,
    ) -> None:
        """A reverted or unmined top-up is audited as failed, with its hash."""
        w3 = BalancesW3({test_signer.address: 99, SAFE: 10_000})
        w3.eth.receipt = receipt
        signer = _signer_on(test_signer, w3)
        signer.set_guard(guard)
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        topped_up = {"testchain"}
        app_module.top_up_agent_signer(app_config, signer, guard, activity, topped_up)
        assert not topped_up
        assert not _audited(app_config, "agent_topup")
        (entry,) = _audited(app_config, "agent_topup_failed")
        assert (entry["chain"], entry["value"]) == ("testchain", "401")
        assert entry["tx_hash"].startswith("0x")
        assert error in entry["error"]

    def test_a_failing_broadcast_does_not_stop_the_others(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A send that fails on one chain is logged and audited; the next still moves."""
        self._two_chains(app_config, test_signer).eth.fail_broadcast = True
        test_signer.set_guard(guard)
        topped_up = {"broken"}
        with caplog.at_level(logging.ERROR, logger="agent"):
            app_module.top_up_agent_signer(
                app_config, test_signer, guard, activity, topped_up
            )
        assert [chain for chain, *_ in sends] == ["broken", "testchain"]
        assert "agent top-up of 401 wei on broken failed" in caplog.text
        assert topped_up == {"testchain"}
        assert [e["chain"] for e in _audited(app_config, "agent_topup")] == [
            "testchain"
        ]
        (failed,) = _audited(app_config, "agent_topup_failed")
        assert (failed["chain"], failed["tx_hash"]) == ("broken", None)
        assert "nonce too low" in failed["error"]
        assert not _audited(app_config, "send_failed")
        assert _performance_card(app_config) == (0, None)

    def test_a_guard_refusal_does_not_stop_the_others(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        settings_store: SettingsStore,
        activity: ActivityLog,
        sends: list,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Restricted: an allowance that never arms on one chain is refused there only."""
        self._two_chains(app_config, test_signer)
        guard = self._restricted_guard(settings_store, app_config, test_signer)
        allow = guard.allow_agent_topup_once

        def allow_but_broken(*, chain: str, amount_cap: int) -> None:
            """Arm every chain but "broken"."""
            if chain != "broken":
                allow(chain=chain, amount_cap=amount_cap)

        monkeypatch.setattr(guard, "allow_agent_topup_once", allow_but_broken)
        topped_up: set[str] = set()
        app_module.top_up_agent_signer(
            app_config, test_signer, guard, activity, topped_up
        )
        assert [chain for chain, *_ in sends] == ["broken", "testchain"]
        assert topped_up == {"testchain"}
        (failed,) = _audited(app_config, "agent_topup_failed")
        assert failed["chain"] == "broken"
        assert "do not allow the safe to call" in failed["error"]
        assert not _audited(app_config, "blocked")
        assert _performance_card(app_config) == (0, None)

    def test_an_unreadable_chain_does_not_stop_the_others(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
    ) -> None:
        """A balance read that fails on one chain skips it; the next still moves."""
        broken = self._two_chains(app_config, test_signer)
        del broken.balances[SAFE.lower()]
        test_signer.set_guard(guard)
        topped_up = {"broken"}
        app_module.top_up_agent_signer(
            app_config, test_signer, guard, activity, topped_up
        )
        assert [chain for chain, *_ in sends] == ["testchain"]
        assert topped_up == {"broken", "testchain"}  # nothing was sent on broken
        assert not _audited(app_config, "agent_topup_failed")


class TestTopUpTask:
    """The background job: at start, then every interval, until cancelled."""

    def _run(
        self, monkeypatch: pytest.MonkeyPatch, check: t.Callable[..., None]
    ) -> list[str]:
        """Run the job until its second sleep; return what happened, in order."""
        events: list[str] = []

        def recorded_check(*args: t.Any) -> None:
            """Record a check, then run the given one."""
            events.append("check")
            check(*args)

        async def sleep(seconds: float) -> None:
            """Record the sleep; end the job at the second one."""
            events.append(f"sleep {seconds}")
            if events.count(f"sleep {seconds}") == 2:
                raise asyncio.CancelledError

        monkeypatch.setattr(app_module, "top_up_agent_signer", recorded_check)
        monkeypatch.setattr(app_module.asyncio, "sleep", sleep)
        args: tuple = (None, None, None, None, set())
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(app_module.top_up_agent(*args))  # type: ignore[arg-type]
        return events

    def test_checks_at_start_then_every_interval(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The first check does not wait; each later one follows the interval."""
        events = self._run(monkeypatch, lambda *a: None)
        assert events == ["check", "sleep 3600.0", "check", "sleep 3600.0"]

    def test_a_failed_check_does_not_end_the_job(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Whatever a check raises is logged, and the next one still runs."""

        def failing(*_: t.Any) -> None:
            """Fail every check."""
            raise RuntimeError("boom")

        with caplog.at_level(logging.ERROR, logger="agent"):
            events = self._run(monkeypatch, failing)
        assert events.count("check") == 2
        assert "agent top-up check failed" in caplog.text

    def test_runs_with_the_app_and_stops_after(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The lifespan starts the job with the app and cancels it on shutdown."""
        monkeypatch.setattr(app_module, "AGENT_TOPUP_INTERVAL_SECONDS", 0.01)
        checks: list[tuple] = []
        monkeypatch.setattr(
            app_module, "top_up_agent_signer", lambda *a: checks.append(a)
        )
        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716"):
            deadline = time.monotonic() + 5
            while len(checks) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(checks) >= 2
        config, signer, guard, _, topped_up = checks[0]
        assert (config, signer, guard) == (app_config, test_signer, app.state.guard)
        assert topped_up is app.state.topped_up
        at_shutdown = len(checks)
        time.sleep(0.1)
        assert len(checks) == at_shutdown

    def test_funds_status_reads_the_task_s_outcomes(
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
    ) -> None:
        """/funds-status leaves the agent EOA to the top-up once one succeeded."""
        _signer_on(test_signer, BalancesW3({test_signer.address: 99, SAFE: 10_000}))
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        app = make_app(test_signer, app_config, activity)
        app.state.topped_up.add("testchain")
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            report = client.get("/funds-status").json()["testchain"]
        assert report[test_signer.address][NATIVE_ASSET]["deficit"] == "0"
