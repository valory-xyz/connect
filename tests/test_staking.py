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

"""Staking: the env vars, the session reminder, and the checkpoint."""

import asyncio
import logging
import time
import typing as t
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import function_signature_to_4byte_selector
from fastapi.testclient import TestClient
from hexbytes import HexBytes
from web3 import Web3

from connect import staking
from connect.activity import ActivityLog, PERFORMANCE_FILE
from connect.config import (
    ACTIVITY_CHECKER_ENV,
    AppConfig,
    SERVICE_ID_ENV,
    STAKING_CONTRACT_ENV,
    STORE_PATH_ENV,
    StakingConfig,
    load_config,
)
from connect.guard import Guard
from connect.server import app as app_module
from connect.server import pearl_routes
from connect.settings import MODE_RESTRICTED, Protected, Settings, SettingsStore
from connect.signer import Signer, SignerError
from connect.workspace import SESSION_NOTICE_FILE

from tests.conftest import FakeW3, audit_entries

STAKING_CONTRACT = Web3.to_checksum_address("0x" + "5a" * 20)
CHECKER = Web3.to_checksum_address("0x" + "c4" * 20)
SAFE = "0x" + "22" * 20
SERVICE_ID = 42
NOW = 1_800_000_000
DAY = 86_400
# ~1 request a day, as the Connect checkers are configured
RATIO = 11_337_868_480_725
PROGRAM = StakingConfig(
    staking_contract=STAKING_CONTRACT, activity_checker=CHECKER, service_id=SERVICE_ID
)


def _sel(signature: str) -> bytes:
    """Return a selector."""
    return function_signature_to_4byte_selector(signature)


class StakingW3(FakeW3):
    """Fake Web3 answering the staking and checker reads.

    The shapes are the ABIs olas-operate-middleware vendors:
    `staking_token/build/StakingToken.json` (`getServiceInfo` returns the
    `ServiceInfo` struct, multisig, owner, nonces, tsStart, reward, inactivity)
    and `requester_activity_checker` (`getMultisigNonces(multisig)` returns
    `[safe nonce, Marketplace request count]`).
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        *,
        safe_requests: int = 10,
        staked_requests: int = 9,
        ts_checkpoint: int = NOW - DAY + 60,
        next_checkpoint: int | None = None,
        available_rewards: int = 10**18,
        record: bool = True,
    ) -> None:
        """Hold the on-chain state the reads answer from.

        `next_checkpoint` defaults to `ts_checkpoint + livenessPeriod`, the
        answer of a contract with no rebaseline pending.
        """
        super().__init__()
        self.safe_requests = safe_requests
        self.staked_requests = staked_requests
        self.ts_checkpoint = ts_checkpoint
        self.next_checkpoint = next_checkpoint
        self.available_rewards = available_rewards
        self.record = record
        self.fail: Exception | None = None
        self.calls: list[tuple[str, bytes]] = []
        self.eth.call = self._call  # type: ignore[attr-defined]
        self.eth.receipt = {"status": 1}

    def _call(self, tx: dict) -> bytes:
        """Answer one eth_call."""
        if self.fail is not None:
            raise self.fail
        to, data = tx["to"], bytes(tx["data"])
        self.calls.append((to, data))
        answers = {
            (CHECKER, _sel("getMultisigNonces(address)")): lambda: abi_encode(
                ["uint256[]"], [[3, self.safe_requests]]
            ),
            (CHECKER, _sel("livenessRatio()")): lambda: abi_encode(
                ["uint256"], [RATIO]
            ),
            (STAKING_CONTRACT, _sel("getServiceInfo(uint256)")): self._service_info,
            (STAKING_CONTRACT, _sel("livenessPeriod()")): lambda: abi_encode(
                ["uint256"], [DAY]
            ),
            (STAKING_CONTRACT, _sel("tsCheckpoint()")): lambda: abi_encode(
                ["uint256"], [self.ts_checkpoint]
            ),
            (
                STAKING_CONTRACT,
                _sel("getNextRewardCheckpointTimestamp()"),
            ): lambda: abi_encode(
                ["uint256"],
                [
                    (
                        self.ts_checkpoint + DAY
                        if self.next_checkpoint is None
                        else self.next_checkpoint
                    )
                ],
            ),
            (STAKING_CONTRACT, _sel("availableRewards()")): lambda: abi_encode(
                ["uint256"], [self.available_rewards]
            ),
        }
        return HexBytes(answers[(to, data[:4])]())

    def _service_info(self) -> bytes:
        """Encode getServiceInfo for the service, or an empty record."""
        nonces = [2, self.staked_requests] if self.record else []
        return abi_encode(
            ["(address,address,uint256[],uint256,uint256,uint256)"],
            [(SAFE, SAFE, nonces, NOW - DAY, 0, 0)],
        )


@pytest.fixture
def staked_config(app_config: AppConfig) -> AppConfig:
    """Return the test config, staked on its one chain."""
    app_config.staking = PROGRAM
    return app_config


@pytest.fixture
def w3(test_signer: Signer) -> StakingW3:
    """Point the signer's test chain at a staking fake."""
    fake = StakingW3()
    test_signer._chains._states["testchain"].w3 = (  # pylint: disable=protected-access
        t.cast(Web3, fake)
    )
    return fake


def _now() -> float:
    """Return the fixed clock's time."""
    return float(NOW)


def _audited(config: AppConfig, kind: str) -> list[dict]:
    """Return the audit entries of one kind."""
    return [e for e in audit_entries(config.store_path) if e["kind"] == kind]


class TestConfig:
    """The three env vars Pearl sets at deploy."""

    def _env(self, tmp_path: Path, **staking_env: str) -> dict:
        """Return a minimal environment plus the given staking values."""
        return {
            "CONNECTION_LEDGER_CONFIG_LEDGER_APIS_GNOSIS_ADDRESS": "http://rpc",
            STORE_PATH_ENV: str(tmp_path),
            **staking_env,
        }

    def test_a_staked_instance(self, tmp_path: Path) -> None:
        """All three set: the program, checksummed."""
        config = load_config(
            self._env(
                tmp_path,
                **{
                    STAKING_CONTRACT_ENV: STAKING_CONTRACT.lower(),
                    ACTIVITY_CHECKER_ENV: CHECKER,
                    SERVICE_ID_ENV: str(SERVICE_ID),
                },
            )
        )
        assert config.staking == PROGRAM
        assert staking.is_staked(config)

    @pytest.mark.parametrize(
        "staking_env",
        [
            {},
            {STAKING_CONTRACT_ENV: ""},
            {
                STAKING_CONTRACT_ENV: "0x" + "00" * 20,
                ACTIVITY_CHECKER_ENV: "0x" + "00" * 20,
                SERVICE_ID_ENV: "7",
            },
        ],
        ids=["unset", "empty", "zero-address"],
    )
    def test_unstaked(self, tmp_path: Path, staking_env: dict) -> None:
        """Unset or the zero address is unstaked, quietly."""
        config = load_config(self._env(tmp_path, **staking_env))
        assert config.staking is None
        assert not staking.is_staked(config)

    @pytest.mark.parametrize(
        "staking_env",
        [
            {STAKING_CONTRACT_ENV: "not-an-address"},
            {STAKING_CONTRACT_ENV: STAKING_CONTRACT, ACTIVITY_CHECKER_ENV: "0x12"},
            {
                STAKING_CONTRACT_ENV: STAKING_CONTRACT,
                ACTIVITY_CHECKER_ENV: CHECKER,
                SERVICE_ID_ENV: "-1",
            },
            {STAKING_CONTRACT_ENV: STAKING_CONTRACT, SERVICE_ID_ENV: "7"},
            {STAKING_CONTRACT_ENV: STAKING_CONTRACT, ACTIVITY_CHECKER_ENV: CHECKER},
        ],
        ids=["bad-contract", "bad-checker", "bad-id", "no-checker", "no-id"],
    )
    def test_unusable_values_read_as_unstaked(
        self, tmp_path: Path, staking_env: dict, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A value Connect cannot use never stops the wallet: unstaked, and logged."""
        with caplog.at_level(logging.WARNING, logger="agent"):
            config = load_config(self._env(tmp_path, **staking_env))
        assert config.staking is None
        assert "staking read as unstaked" in caplog.text


class TestRequestMade:
    """request_made_this_epoch, against the Basius-style requirement."""

    @pytest.mark.parametrize(
        ("safe_requests", "ts_checkpoint", "expected"),
        [
            # a day since the checkpoint needs ceil(86400 * ratio / 1e18) = 1
            (10, NOW - DAY, True),
            (9, NOW - DAY, False),
            # within the liveness period, the period itself is what counts:
            # right after a checkpoint, none would be needed without the floor
            (9, NOW, False),
            (9, NOW - 60, False),
            (10, NOW - 60, True),
            # two days without a checkpoint need two
            (10, NOW - 2 * DAY, False),
            (11, NOW - 2 * DAY, True),
        ],
    )
    def test_requirement(
        self, safe_requests: int, ts_checkpoint: int, expected: bool
    ) -> None:
        """The count since the checkpoint against what the checker will need."""
        fake = StakingW3(safe_requests=safe_requests, ts_checkpoint=ts_checkpoint)
        assert (
            staking.request_made_this_epoch(t.cast(Web3, fake), PROGRAM, SAFE, NOW)
            is expected
        )
        to, data = next(
            c for c in fake.calls if c[1][:4] == _sel("getMultisigNonces(address)")
        )
        assert to == CHECKER
        assert abi_decode(["address"], data[4:]) == (Web3.to_checksum_address(SAFE),)

    def test_no_staking_record_is_an_error(self) -> None:
        """An empty record cannot be read as "made" or "not made"."""
        fake = StakingW3(record=False)
        with pytest.raises(ValueError, match="no staking record"):
            staking.request_made_this_epoch(t.cast(Web3, fake), PROGRAM, SAFE, NOW)


class TestReminder:
    """staking_reminder, for POST /session."""

    def test_reminds_while_the_request_is_not_made(
        self, staked_config: AppConfig, test_signer: Signer, w3: StakingW3
    ) -> None:
        """Staked and short of the request: the reminder."""
        w3.safe_requests = 9
        assert (
            staking.staking_reminder(staked_config, test_signer, now=_now)
            == staking.STAKING_REMINDER
        )

    def test_silent_once_the_request_is_made(
        self, staked_config: AppConfig, test_signer: Signer, w3: StakingW3
    ) -> None:
        """The request made: nothing to say."""
        assert staking.staking_reminder(staked_config, test_signer, now=_now) is None
        assert w3.calls

    def test_silent_while_unstaked(
        self, app_config: AppConfig, test_signer: Signer, w3: StakingW3
    ) -> None:
        """Unstaked: no read at all."""
        assert staking.staking_reminder(app_config, test_signer, now=_now) is None
        assert not w3.calls

    def test_silent_without_an_instance_chain(
        self, staked_config: AppConfig, test_signer: Signer, w3: StakingW3
    ) -> None:
        """No chain carrying the safe: nothing to read."""
        staked_config.chains["testchain"].safe_address = None
        assert staking.staking_reminder(staked_config, test_signer, now=_now) is None
        assert not w3.calls

    def test_a_failed_read_never_reminds(
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        w3: StakingW3,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """An RPC failure is logged, without the RPC's words, and reminds nothing."""
        w3.fail = ConnectionError("http://rpc.example/secret-key unreachable")
        with caplog.at_level(logging.WARNING, logger="agent"):
            assert (
                staking.staking_reminder(staked_config, test_signer, now=_now) is None
            )
        assert "could not read the staking state on testchain" in caplog.text
        assert "secret-key" not in caplog.text


class TestCheckpoint:
    """checkpoint_if_due, the lifespan's checkpoint call."""

    def test_not_due_sends_nothing(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
    ) -> None:
        """Before the next checkpoint time: nothing sent, nothing audited."""
        test_signer.set_guard(guard)
        assert (
            staking.checkpoint_if_due(
                staked_config, test_signer, guard, activity, now=_now
            )
            is None
        )
        assert not w3.eth.sent
        assert not audit_entries(staked_config.store_path)

    def test_unstaked_reads_nothing(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
    ) -> None:
        """Unstaked: no read, no send."""
        assert (
            staking.checkpoint_if_due(app_config, test_signer, guard, activity) is None
        )
        assert not w3.calls
        assert not w3.eth.sent

    def test_due_sends_checkpoint_from_the_eoa(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Due: one checkpoint() call, audited only as itself, no allowance armed."""
        test_signer.set_guard(guard)
        w3.ts_checkpoint = NOW - DAY
        sends: list[tuple[str, str, dict]] = []
        send = test_signer.send

        def spy(chain: str, to: str, **kwargs: t.Any) -> str:
            """Record the send, then make it."""
            sends.append((chain, to, kwargs))
            return send(chain, to, **kwargs)

        monkeypatch.setattr(test_signer, "send", spy)
        armed: list[dict] = []
        monkeypatch.setattr(guard, "allow_checkpoint_once", lambda **k: armed.append(k))
        tx_hash = staking.checkpoint_if_due(
            staked_config, test_signer, guard, activity, now=_now
        )
        assert tx_hash is not None
        assert tx_hash.startswith("0x")
        ((chain, to, kwargs),) = sends
        assert (chain, to, kwargs["data"]) == (
            "testchain",
            STAKING_CONTRACT,
            "0xc2c4c5c1",
        )
        assert kwargs.get("value", 0) == 0
        assert kwargs["audit"] is False
        assert len(w3.eth.sent) == 1
        assert not armed
        assert [e["kind"] for e in audit_entries(staked_config.store_path)] == [
            "staking_checkpoint"
        ]
        (entry,) = _audited(staked_config, "staking_checkpoint")
        assert entry["tx_hash"] == tx_hash
        payload = (staked_config.store_path / PERFORMANCE_FILE).read_text()
        assert '"last_activity": null' in payload

    def test_restricted_arms_the_allowance_it_spends(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        settings_store: SettingsStore,
        activity: ActivityLog,
        w3: StakingW3,
    ) -> None:
        """Restricted, nothing whitelisted: the allowance lets exactly one call pass."""
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        guard = Guard(settings_store, staked_config, agent_signer=test_signer.address)
        test_signer.set_guard(guard)
        w3.ts_checkpoint = NOW - DAY - 1
        assert staking.checkpoint_if_due(
            staked_config, test_signer, guard, activity, now=_now
        )
        assert len(w3.eth.sent) == 1
        with pytest.raises(SignerError, match="only allow transactions targeting"):
            test_signer.send(
                "testchain", STAKING_CONTRACT, data=staking.CHECKPOINT_DATA
            )

    @pytest.mark.parametrize(
        "receipt", [{"status": 0}, None], ids=["reverted", "unmined"]
    )
    def test_a_failed_call_is_audited_and_returns_none(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
        receipt: dict | None,
    ) -> None:
        """A revert or a receipt that never comes: audited as failed, retried later."""
        test_signer.set_guard(guard)
        w3.ts_checkpoint = NOW - DAY
        w3.eth.receipt = receipt
        assert (
            staking.checkpoint_if_due(
                staked_config, test_signer, guard, activity, now=_now
            )
            is None
        )
        (entry,) = _audited(staked_config, "staking_checkpoint_failed")
        assert entry["tx_hash"].startswith("0x")
        assert entry["staking_contract"] == STAKING_CONTRACT
        payload = (staked_config.store_path / PERFORMANCE_FILE).read_text()
        assert '"last_activity": null' in payload

    def test_no_rewards_left_sends_nothing(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
    ) -> None:
        """Due, but with no rewards a checkpoint changes nothing: not sent."""
        test_signer.set_guard(guard)
        w3.ts_checkpoint = NOW - 2 * DAY
        w3.available_rewards = 0
        assert (
            staking.checkpoint_if_due(
                staked_config, test_signer, guard, activity, now=_now
            )
            is None
        )
        assert not w3.eth.sent
        assert not audit_entries(staked_config.store_path)

    def test_a_pending_rebaseline_is_sent_without_rewards(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
    ) -> None:
        """v0.4 signals a rebaseline by its next checkpoint time: sent even so."""
        test_signer.set_guard(guard)
        w3.available_rewards = 0
        w3.next_checkpoint = NOW + DAY
        assert staking.checkpoint_if_due(
            staked_config, test_signer, guard, activity, now=_now
        )
        assert len(w3.eth.sent) == 1

    def test_a_failed_read_sends_nothing(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        w3: StakingW3,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The due-time read failing: audited without the RPC's words, nothing sent."""
        w3.fail = ConnectionError("http://rpc.example/secret-key unreachable")
        with caplog.at_level(logging.WARNING, logger="agent"):
            assert (
                staking.checkpoint_if_due(staked_config, test_signer, guard, activity)
                is None
            )
        assert not w3.eth.sent
        (entry,) = _audited(staked_config, "staking_checkpoint_failed")
        assert entry["tx_hash"] is None
        assert "secret-key" not in entry["error"]
        assert "staking checkpoint on testchain failed" in caplog.text
        assert "secret-key" not in caplog.text


class TestGuardAllowance:
    """allow_checkpoint_once admits exactly checkpoint() to the armed contract."""

    @pytest.fixture
    def restricted(
        self, settings_store: SettingsStore, app_config: AppConfig, test_signer: Signer
    ) -> Guard:
        """Return a restricted guard with an empty whitelist."""
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        return Guard(settings_store, app_config, agent_signer=test_signer.address)

    @pytest.mark.parametrize(
        ("to", "value", "data"),
        [
            (STAKING_CONTRACT, 1, staking.CHECKPOINT_DATA),
            (STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA + "00"),
            (STAKING_CONTRACT, 0, "0x"),
            (CHECKER, 0, staking.CHECKPOINT_DATA),
        ],
        ids=["value", "extra-data", "no-data", "other-contract"],
    )
    def test_refuses_anything_else(
        self, restricted: Guard, to: str, value: int, data: str
    ) -> None:
        """Value, other calldata or another contract: refused, allowance kept."""
        restricted.allow_checkpoint_once(
            chain="testchain", staking_contract=STAKING_CONTRACT
        )
        with pytest.raises(Exception, match="only allow transactions targeting"):
            restricted.check_transaction("testchain", to, value, data)
        # the allowance is still there for the exact call
        restricted.check_transaction(
            "testchain", STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA
        )

    def test_a_dry_run_consumes_nothing(self, restricted: Guard) -> None:
        """consume=False answers without spending the allowance."""
        restricted.allow_checkpoint_once(
            chain="testchain", staking_contract=STAKING_CONTRACT
        )
        restricted.check_transaction(
            "testchain", STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA, consume=False
        )
        restricted.check_transaction(
            "testchain", STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA
        )
        with pytest.raises(Exception, match="only allow transactions targeting"):
            restricted.check_transaction(
                "testchain", STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA
            )

    def test_an_allowance_expires(
        self,
        restricted: Guard,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Unused past its TTL: gone, and the log says so."""
        clock = [1000.0]
        monkeypatch.setattr("connect.guard.time.monotonic", lambda: clock[0])
        restricted.allow_checkpoint_once(
            chain="testchain", staking_contract=STAKING_CONTRACT
        )
        clock[0] += 3600
        with caplog.at_level(logging.WARNING, logger="agent"):
            with pytest.raises(Exception, match="only allow transactions targeting"):
                restricted.check_transaction(
                    "testchain", STAKING_CONTRACT, 0, staking.CHECKPOINT_DATA
                )
        assert "checkpoint allowance" in caplog.text


class TestCheckpointTask:
    """checkpoint_staking, the lifespan task."""

    def test_unstaked_never_starts(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unstaked: the task returns at once, having called nothing."""
        called: list[int] = []
        monkeypatch.setattr(
            staking, "checkpoint_if_due", lambda *a, **k: called.append(1)
        )
        asyncio.run(
            app_module.checkpoint_staking(app_config, test_signer, guard, activity)
        )
        assert not called

    def test_staked_checks_every_interval(
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Staked: a check, then one per interval, until cancelled."""
        called: list[int] = []
        monkeypatch.setattr(
            staking, "checkpoint_if_due", lambda *a, **k: called.append(1)
        )
        monkeypatch.setattr(app_module, "STAKING_CHECKPOINT_INTERVAL_SECONDS", 0.0)

        async def run() -> None:
            task = asyncio.create_task(
                app_module.checkpoint_staking(
                    staked_config, test_signer, guard, activity
                )
            )
            deadline = time.monotonic() + 5
            while len(called) < 3 and time.monotonic() < deadline:
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        asyncio.run(run())
        assert len(called) >= 3

    def test_a_failed_check_does_not_end_the_task(  # pylint: disable=too-many-arguments
        self,
        staked_config: AppConfig,
        test_signer: Signer,
        guard: Guard,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Whatever a check raises is logged, and the next one still runs."""
        called: list[int] = []

        def failing(*_: t.Any, **__: t.Any) -> None:
            """Fail every check."""
            called.append(1)
            raise RuntimeError("boom")

        monkeypatch.setattr(staking, "checkpoint_if_due", failing)
        monkeypatch.setattr(app_module, "STAKING_CHECKPOINT_INTERVAL_SECONDS", 0.0)

        async def run() -> None:
            task = asyncio.create_task(
                app_module.checkpoint_staking(
                    staked_config, test_signer, guard, activity
                )
            )
            deadline = time.monotonic() + 5
            while len(called) < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        with caplog.at_level(logging.ERROR, logger="agent"):
            asyncio.run(run())
        assert len(called) >= 2
        assert "staking checkpoint check failed" in caplog.text

    def test_runs_with_the_app_and_stops_after(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        staked_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The lifespan starts the task with the app and cancels it on shutdown."""
        monkeypatch.setattr(app_module, "STAKING_CHECKPOINT_INTERVAL_SECONDS", 0.01)
        monkeypatch.setattr(app_module, "AGENT_TOPUP_INTERVAL_SECONDS", 3600.0)
        checks: list[tuple] = []
        monkeypatch.setattr(
            staking, "checkpoint_if_due", lambda *a, **k: checks.append(a)
        )
        app = make_app(test_signer, staked_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716"):
            deadline = time.monotonic() + 5
            while len(checks) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
            assert len(checks) >= 2
        assert checks[0][:3] == (staked_config, test_signer, app.state.guard)
        at_shutdown = len(checks)
        time.sleep(0.1)
        assert len(checks) == at_shutdown


class TestSessionNotice:
    """POST /session leaves the reminder for the session, or clears it."""

    @pytest.fixture
    def client(
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
        monkeypatch: pytest.MonkeyPatch,
    ) -> t.Iterator[TestClient]:
        """Yield a client whose launches open nothing, noting the notice they see."""

        def opened(self: t.Any, harness: str, *, fallback: bool = False) -> str:
            """Record what the session would find, then open nothing."""
            notice = app_config.store_path / SESSION_NOTICE_FILE
            self.seen_notices.append(
                notice.read_text(encoding="utf-8") if notice.exists() else None
            )
            return harness

        monkeypatch.setattr("connect.workspace.Workspace.open_session", opened)
        monkeypatch.setattr(
            "connect.workspace.Workspace.seen_notices", [], raising=False
        )
        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            yield client

    def _notice(self, app_config: AppConfig) -> Path:
        """Where the session finds its notice."""
        return app_config.store_path / SESSION_NOTICE_FILE

    def test_writes_the_reminder(
        self,
        client: TestClient,
        app_config: AppConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A reminder due: written before the session opens."""
        monkeypatch.setattr(
            staking, "staking_reminder", lambda config, signer: staking.STAKING_REMINDER
        )
        assert client.post("/session").json()["launched"] is True
        # there before the session opened, not only after
        assert client.app.state.workspace.seen_notices == [  # type: ignore[attr-defined]
            staking.STAKING_REMINDER + "\n"
        ]

    def test_clears_an_old_reminder(
        self,
        client: TestClient,
        app_config: AppConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Nothing to say: an earlier session's notice is removed."""
        monkeypatch.setattr(staking, "staking_reminder", lambda config, signer: None)
        assert client.get("/healthcheck").json() == {"is_healthy": True}
        self._notice(app_config).write_text("stale", encoding="utf-8")
        assert client.post("/session").json()["launched"] is True
        assert not self._notice(app_config).exists()
        # and with none to clear
        assert client.post("/session").json()["launched"] is True

    def test_an_unwritable_notice_never_fails_the_launch(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A disk error writing the notice: logged, and the session still opens."""
        monkeypatch.setattr(
            staking, "staking_reminder", lambda config, signer: staking.STAKING_REMINDER
        )

        def broken(self: t.Any, notice: str | None) -> None:
            raise OSError("read-only store")

        monkeypatch.setattr("connect.workspace.Workspace.write_session_notice", broken)
        with caplog.at_level(logging.ERROR, logger="agent"):
            assert client.post("/session").json()["launched"] is True
        assert "could not write the session notice" in caplog.text

    def test_a_slow_read_never_holds_the_launch(
        self,
        client: TestClient,
        app_config: AppConfig,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A read past the time limit: no reminder, an old one cleared, launched."""
        monkeypatch.setattr(pearl_routes, "REMINDER_READ_SECONDS", 0.01)

        def slow(config: AppConfig, signer: Signer) -> str:
            """Answer only after the launch has given up."""
            time.sleep(0.5)
            return staking.STAKING_REMINDER

        monkeypatch.setattr(staking, "staking_reminder", slow)
        assert client.get("/healthcheck").json() == {"is_healthy": True}
        self._notice(app_config).write_text("stale", encoding="utf-8")
        started = time.monotonic()
        with caplog.at_level(logging.WARNING, logger="agent"):
            assert client.post("/session").json()["launched"] is True
        assert time.monotonic() - started < 0.4
        assert not self._notice(app_config).exists()
        assert "took over" in caplog.text

    def test_the_brief_tells_the_session_to_say_it(self) -> None:
        """The shipped brief names the file and says to relay it first."""
        brief = (Path(staking.__file__).parent / "assets" / "CLAUDE.md").read_text(
            encoding="utf-8"
        )
        assert f"If `{SESSION_NOTICE_FILE}` is in this workspace" in brief
