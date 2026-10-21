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
import logging
import threading
import time
import typing as t

import pytest
from fastapi.testclient import TestClient
from web3 import Web3

from connect import wallet
from connect.activity import ActivityLog
from connect.config import AppConfig, ChainConfig, FundRequirement, NATIVE_ASSET
from connect.guard import Guard
from connect.server import app as app_module
from connect.settings import MODE_RESTRICTED, Protected, Settings, SettingsStore
from connect.signer import Signer, SignerError, _ChainState
from connect.wallet import AgentTopUp, TopUpAction, plan_agent_topup

from tests.conftest import FakeW3, audit_entries

SAFE = "0x" + "22" * 20
TOKEN = "0x" + "77" * 20

AGENT_NATIVE = FundRequirement(threshold=100, topup=500, min_tx_balance=10)
SAFE_NATIVE = FundRequirement(threshold=1000, topup=5000)
REQUIREMENTS = {
    "agent": {NATIVE_ASSET: AGENT_NATIVE},
    "safe": {NATIVE_ASSET: SAFE_NATIVE},
}


class BalancesW3(FakeW3):
    """Fake Web3 answering a native balance per address."""

    def __init__(self, balances: dict[str, int]) -> None:
        """Hold the balances, keyed by any-case address."""
        super().__init__()
        self.balances = {k.lower(): v for k, v in balances.items()}
        self.eth.get_balance = self._balance  # type: ignore[method-assign]

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
    """The per-chain table, mirroring funds-manager's get_agent_topup."""

    @pytest.mark.parametrize(
        ("agent_balance", "safe_balance", "expected"),
        [
            # unreadable balance: nothing moves, deficits as read
            (None, 10_000, AgentTopUp(TopUpAction.NONE, 0, None, None)),
            (50, None, AgentTopUp(TopUpAction.NONE, 0, None, None)),
            # at the threshold: nothing due
            (100, 10_000, AgentTopUp(TopUpAction.NONE, 0, None, None)),
            # below min_tx_balance: the agent EOA cannot pay for the transfer
            (9, 10_000, AgentTopUp(TopUpAction.SIGNER_ALERT, 0, 491, None)),
            # exactly min_tx_balance can pay
            (10, 10_000, AgentTopUp(TopUpAction.MOVE, 490, 0, None)),
            # the safe covers the need, also exactly
            (99, 10_000, AgentTopUp(TopUpAction.MOVE, 401, 0, None)),
            (99, 401, AgentTopUp(TopUpAction.MOVE, 401, 0, None)),
            # the safe holds less: all of it moves, the safe asks for the rest
            (99, 400, AgentTopUp(TopUpAction.MOVE, 400, 0, 1 + 5000)),
            (99, 1, AgentTopUp(TopUpAction.MOVE, 1, 0, 400 + 5000)),
            # the safe is empty
            (99, 0, AgentTopUp(TopUpAction.SAFE_ALERT, 0, 0, 401 + 5000)),
        ],
    )
    def test_table(
        self, agent_balance: int | None, safe_balance: int | None, expected: AgentTopUp
    ) -> None:
        """Each row of the table, with its boundaries."""
        assert plan_agent_topup(REQUIREMENTS, agent_balance, safe_balance) == expected

    def test_topup_below_balance_is_nothing_due(self) -> None:
        """A topup under the balance (a misconfiguration) never asks for less than 0."""
        requirements = {
            "agent": {
                NATIVE_ASSET: FundRequirement(threshold=100, topup=50, min_tx_balance=0)
            },
            "safe": {NATIVE_ASSET: SAFE_NATIVE},
        }
        assert plan_agent_topup(requirements, 60, 10_000).action is TopUpAction.NONE

    @pytest.mark.parametrize(
        "requirements",
        [
            # no min_tx_balance: never move, report as today
            {
                "agent": {NATIVE_ASSET: FundRequirement(threshold=100, topup=500)},
                "safe": {NATIVE_ASSET: SAFE_NATIVE},
            },
            # no native safe entry
            {"agent": {NATIVE_ASSET: AGENT_NATIVE}, "safe": {TOKEN: SAFE_NATIVE}},
            {"agent": {NATIVE_ASSET: AGENT_NATIVE}},
            # no native agent entry: tokens never move
            {"agent": {TOKEN: AGENT_NATIVE}, "safe": {NATIVE_ASSET: SAFE_NATIVE}},
        ],
    )
    def test_no_rule_without_native_entries_and_min_tx_balance(
        self, requirements: dict
    ) -> None:
        """Without both native entries and min_tx_balance, nothing moves."""
        assert plan_agent_topup(requirements, 0, 10_000) == AgentTopUp(
            TopUpAction.NONE, 0, None, None
        )


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
            "testchain": AgentTopUp(TopUpAction.MOVE, 400, 0, 5001)
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

    def test_unreadable_balance_moves_nothing(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An RPC failure plans nothing, and says why in the log."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 0}))
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        with caplog.at_level(logging.WARNING, logger="agent"):
            plans = wallet.agent_topup(app_config, signer)
        assert plans == {"testchain": AgentTopUp(TopUpAction.NONE, 0, None, None)}
        assert "could not read native balances on testchain" in caplog.text


class TestFundsStatus:
    """/funds-status reports what is left after the top-up."""

    def _deficits(
        self, app_config: AppConfig, signer: Signer, requirements: dict
    ) -> tuple[str, str]:
        """Return the (agent, safe) native deficits funds_status reports."""
        app_config.fund_requirements = {"testchain": requirements}
        report = wallet.funds_status(app_config, signer)["testchain"]
        return (
            report[signer.address][NATIVE_ASSET]["deficit"],
            report[SAFE][NATIVE_ASSET]["deficit"],
        )

    @pytest.mark.parametrize(
        ("agent_balance", "safe_balance", "expected"),
        [
            (100, 600, ("0", "400")),  # nothing due: the threshold rule as today
            (9, 600, ("491", "400")),  # signer alert: topup - balance
            (99, 600, ("0", "400")),  # moved; the safe's own threshold as today
            (99, 400, ("0", str(1 + 5000))),  # moved all; safe asks for the rest
            (99, 0, ("0", str(401 + 5000))),  # safe empty
        ],
    )
    def test_reports_after_the_topup(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        agent_balance: int,
        safe_balance: int,
        expected: tuple[str, str],
    ) -> None:
        """Native deficits follow the rule; balances stay as read."""
        signer = _signer_on(
            test_signer,
            BalancesW3({test_signer.address: agent_balance, SAFE: safe_balance}),
        )
        assert self._deficits(app_config, signer, REQUIREMENTS) == expected

    def test_without_min_tx_balance_reports_as_today(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """No min_tx_balance: threshold - balance on both, as before."""
        signer = _signer_on(test_signer, BalancesW3({test_signer.address: 40, SAFE: 0}))
        requirements = {
            "agent": {NATIVE_ASSET: FundRequirement(threshold=100, topup=500)},
            "safe": {NATIVE_ASSET: SAFE_NATIVE},
        }
        assert self._deficits(app_config, signer, requirements) == ("60", "1000")

    def test_tokens_keep_the_threshold_rule(
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
        report = wallet.funds_status(app_config, signer)["testchain"]
        assert report[SAFE][TOKEN] == {"balance": "2", "deficit": "8", "decimals": 6}
        assert report[SAFE][NATIVE_ASSET]["deficit"] == str(401 + 5000)


class TestTopUpAgentSigner:
    """One check: a plain safe CALL per chain that the rule says to move."""

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
        app_module.top_up_agent_signer(app_config, signer, guard, activity)
        assert sends == [("testchain", signer.address, 401, "0x")]
        assert not armed
        (entry,) = [
            e
            for e in audit_entries(app_config.store_path)
            if e["kind"] == "agent_topup"
        ]
        assert (entry["chain"], entry["value"]) == ("testchain", "401")
        assert entry["tx_hash"].startswith("0x")

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
        app_module.top_up_agent_signer(app_config, signer, guard, activity)
        assert sends == [("testchain", signer.address, 400, "0x")]
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

    def test_alerts_and_nothing_due_send_nothing(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An alert is logged and left to /funds-status; nothing is sent."""
        w3 = BalancesW3({test_signer.address: 9, SAFE: 10_000})
        signer = _signer_on(test_signer, w3)
        app_config.fund_requirements = {"testchain": REQUIREMENTS}
        with caplog.at_level(logging.INFO, logger="agent"):
            app_module.top_up_agent_signer(app_config, signer, guard, activity)
            w3.balances[signer.address.lower()] = 99
            w3.balances[SAFE] = 0
            app_module.top_up_agent_signer(app_config, signer, guard, activity)
            w3.balances[signer.address.lower()] = 100
            app_module.top_up_agent_signer(app_config, signer, guard, activity)
        assert not sends
        assert "agent top-up on testchain: signer_alert" in caplog.text
        assert "agent top-up on testchain: safe_alert" in caplog.text
        # nothing due is not worth a line every hour
        assert caplog.text.count("agent top-up on testchain") == 2

    def test_a_failing_chain_does_not_stop_the_others(  # pylint: disable=too-many-arguments
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        sends: list,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A send that fails on one chain is logged; the next chain still moves."""
        app_config.chains = {
            "broken": ChainConfig(rpc_url="http://127.0.0.1:9", safe_address=SAFE),
            "testchain": app_config.chains["testchain"],
        }
        broken = BalancesW3({test_signer.address: 99, SAFE: 10_000})
        broken.eth.fail_broadcast = True
        signer = _signer_on(test_signer, broken, chain="broken")
        _signer_on(signer, BalancesW3({signer.address: 99, SAFE: 10_000}))
        signer.set_guard(guard)
        app_config.fund_requirements = {
            "broken": REQUIREMENTS,
            "testchain": REQUIREMENTS,
        }
        with caplog.at_level(logging.ERROR, logger="agent"):
            app_module.top_up_agent_signer(app_config, signer, guard, activity)
        assert [chain for chain, *_ in sends] == ["broken", "testchain"]
        assert "agent top-up of 401 wei on broken failed" in caplog.text
        topups = [
            e["chain"]
            for e in audit_entries(app_config.store_path)
            if e["kind"] == "agent_topup"
        ]
        assert topups == ["testchain"]


class TestTopUpTask:
    """The background job: at start, then hourly, until cancelled."""

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
        args = (None, None, None, None)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(app_module.top_up_agent(*args))  # type: ignore[arg-type]
        return events

    def test_checks_at_start_then_hourly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The first check does not wait; each later one follows an hour's sleep."""
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
        config, signer, guard, _ = checks[0]
        assert (config, signer, guard) == (app_config, test_signer, app.state.guard)
        at_shutdown = len(checks)
        time.sleep(0.1)
        assert len(checks) == at_shutdown
