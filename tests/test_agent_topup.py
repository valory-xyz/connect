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

import logging
import threading
import typing as t

import pytest
from web3 import Web3

from connect import wallet
from connect.config import AppConfig, FundRequirement, NATIVE_ASSET
from connect.signer import Signer, _ChainState
from connect.wallet import AgentTopUp, TopUpAction, plan_agent_topup

from tests.conftest import FakeW3

SAFE = "0x" + "22" * 20
TOKEN = "0x" + "77" * 20

AGENT_NATIVE = FundRequirement(threshold=100, topup=500, min_tx_balance=10)
SAFE_NATIVE = FundRequirement(threshold=1000, topup=5000)
REQUIREMENTS = {"agent": {NATIVE_ASSET: AGENT_NATIVE}, "safe": {NATIVE_ASSET: SAFE_NATIVE}}


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


def _signer_on(test_signer: Signer, w3: FakeW3) -> Signer:
    """Point the signer's testchain at the given fake."""
    test_signer._chains._states["testchain"] = (  # pylint: disable=protected-access
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
        app_config.fund_requirements = {"testchain": REQUIREMENTS, "other": REQUIREMENTS}
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
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 40, SAFE: 0})
        )
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
        signer = _signer_on(
            test_signer, BalancesW3({test_signer.address: 99, SAFE: 0})
        )
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

