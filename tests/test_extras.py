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

"""Tests for entrypoint, wallet helpers, signer and route edge cases."""

import json
import typing as t
from pathlib import Path

import pytest
import uvicorn
from web3 import Web3

from pearl_connect import __main__ as main_module
from pearl_connect import wallet
from pearl_connect.activity import ActivityLog, MAX_LOG_BYTES
from pearl_connect.config import (
    AppConfig,
    ChainConfig,
    FUND_REQUIREMENTS_ENV,
    SAFES_ENV,
    STORE_PATH_ENV,
    load_config,
)
from pearl_connect.keystore import KeystoreError, load_account
from pearl_connect.signer import Signer, SignerError

from tests.conftest import FakeW3, TEST_PASSWORD


class StubServer:
    """uvicorn.Server stand-in that never serves."""

    def __init__(self, config: uvicorn.Config) -> None:
        """Initialize."""
        self.config = config
        self.started = False
        self.should_exit = True

    def run(self) -> None:
        """Do nothing."""


class TestMain:
    """Entrypoint tests."""

    def test_parse_args_both_forms(self) -> None:
        """Both --password forms parse."""
        assert main_module.parse_args(["--password", "x"]).password == "x"  # nosec B105
        assert main_module.parse_args(["--password=y"]).password == "y"  # nosec B105

    def test_main_config_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Missing STORE_PATH env returns exit code 1."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(STORE_PATH_ENV, raising=False)
        assert main_module.main(["--password", "x"]) == 1

    def test_main_keystore_error(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store_path: Path
    ) -> None:
        """Missing keystore returns exit code 1."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        assert main_module.main(["--password", "x"]) == 1

    def test_main_happy_path(
        self, monkeypatch: pytest.MonkeyPatch, keystore_dir: Path, store_path: Path
    ) -> None:
        """Full boot with a stubbed uvicorn server returns 0."""
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        monkeypatch.delenv(SAFES_ENV, raising=False)
        monkeypatch.delenv(FUND_REQUIREMENTS_ENV, raising=False)
        monkeypatch.setattr(main_module.uvicorn, "Server", StubServer)
        assert main_module.main(["--password", TEST_PASSWORD]) == 0


class TestActivityExtras:
    """Activity log rotation and public performance writer."""

    def test_rotation(self, store_path: Path, activity: ActivityLog) -> None:
        """Oversized log rotates to .jsonl.1."""
        log_file = store_path / "activity_log.jsonl"
        log_file.write_text("x" * (MAX_LOG_BYTES + 1))
        activity.record("transaction", chain="testchain")
        assert (store_path / "activity_log.jsonl.1").exists()

    def test_write_performance_public(
        self, store_path: Path, activity: ActivityLog
    ) -> None:
        """write_performance produces the SDK contract fields."""
        activity.write_performance()
        payload = json.loads((store_path / "agent_performance.json").read_text())
        assert set(payload) == {
            "timestamp",
            "metrics",
            "agent_behavior",
            "last_activity",
            "last_chat_message",
        }

    def test_transactions_metric_counts_only_transactions(
        self, store_path: Path, activity: ActivityLog
    ) -> None:
        """Non-transaction signer actions do not inflate the transactions metric."""
        activity.record("sign_message", digest="0x" + "ab" * 32)
        activity.record("send_failed", chain="testchain", error="nonce too low")
        activity.record("transaction", chain="testchain", tx_hash="0x" + "11" * 32)
        payload = json.loads((store_path / "agent_performance.json").read_text())
        (metric,) = payload["metrics"]
        assert metric["name"] == "transactions"
        assert metric["value"] == 1
        assert activity.count == 3  # the all-actions counter still sees everything


class TestConfigExtras:
    """Config parsing edge cases."""

    def test_safes_json_non_dict_raises(self, tmp_path: Path) -> None:
        """A JSON array of safes is a misconfiguration and fails loudly."""
        env = {STORE_PATH_ENV: str(tmp_path), SAFES_ENV: '["0xabc"]'}
        with pytest.raises(ValueError, match="JSON object"):
            load_config(env)

    def test_fund_requirements_non_dict_raises(self, tmp_path: Path) -> None:
        """A JSON array for fund requirements raises."""
        env = {STORE_PATH_ENV: str(tmp_path), FUND_REQUIREMENTS_ENV: "[1]"}
        with pytest.raises(ValueError, match="JSON object"):
            load_config(env)

    def test_fund_requirements_invalid_json_names_the_var(self, tmp_path: Path) -> None:
        """Malformed JSON names the offending env var, like the safes parser."""
        env = {STORE_PATH_ENV: str(tmp_path), FUND_REQUIREMENTS_ENV: "{nope"}
        with pytest.raises(ValueError, match=FUND_REQUIREMENTS_ENV):
            load_config(env)


def test_keystore_invalid_json(tmp_path: Path) -> None:
    """A non-JSON keystore raises KeystoreError."""
    (tmp_path / "ethereum_private_key.txt").write_text("not json")
    with pytest.raises(KeystoreError, match="not valid JSON"):
        load_account(TEST_PASSWORD, tmp_path)


def test_keystore_valid_json_but_not_keystore(tmp_path: Path) -> None:
    """Valid JSON that is not a keystore raises KeystoreError, not KeyError."""
    (tmp_path / "ethereum_private_key.txt").write_text('{"hello": "world"}')
    with pytest.raises(KeystoreError, match="failed to decrypt"):
        load_account(TEST_PASSWORD, tmp_path)


class TestSignerExtras:
    """Signer edge cases."""

    def test_chain_state_builds_real_web3(
        self, monkeypatch: pytest.MonkeyPatch, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Unknown-but-configured chains get a Web3 client, cached."""
        from pearl_connect import signer as signer_module

        pool = test_signer._chains  # pylint: disable=protected-access
        pool._config.chains["otherchain"] = (  # pylint: disable=protected-access
            ChainConfig(rpc_url="http://127.0.0.1:9")
        )
        fake_w3.eth.chain_id = 4242  # type: ignore[attr-defined]

        class FakeWeb3Factory:
            """Web3 replacement returning the fake client."""

            HTTPProvider = staticmethod(lambda url, request_kwargs=None: url)

            def __new__(cls, provider: object) -> t.Any:
                """Return the fake w3."""
                return fake_w3

        monkeypatch.setattr(signer_module, "Web3", FakeWeb3Factory)
        assert test_signer.w3("otherchain") is fake_w3
        assert test_signer.w3("otherchain") is fake_w3  # cached

    def test_broadcast_failure(
        self, test_signer: Signer, fake_w3: FakeW3, activity: ActivityLog
    ) -> None:
        """A node rejection surfaces as SignerError and is logged."""
        fake_w3.eth.fail_broadcast = True
        with pytest.raises(SignerError, match="send failed"):
            test_signer.send("testchain", to="0x" + "aa" * 20)
        assert activity.recent()[-1]["kind"] == "send_failed"

    def test_estimation_failure_is_signer_error(
        self, test_signer: Signer, fake_w3: FakeW3, activity: ActivityLog
    ) -> None:
        """A gas-estimation revert surfaces as SignerError, not a raw exception."""

        def reverting_estimate(tx: dict) -> int:
            raise RuntimeError("execution reverted: not enough funds")

        fake_w3.eth.estimate_gas = reverting_estimate  # type: ignore[method-assign]
        with pytest.raises(SignerError, match="execution reverted"):
            test_signer.send("testchain", to="0x" + "aa" * 20)
        assert activity.recent()[-1]["kind"] == "send_failed"

    def test_concurrent_duplicate_request_id_rejected(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A retry racing an in-flight send with the same id cannot double-spend."""
        import threading

        started = threading.Event()
        release = threading.Event()
        original_estimate = fake_w3.eth.estimate_gas

        def blocking_estimate(tx: dict) -> int:
            started.set()
            release.wait(timeout=10)
            return original_estimate(tx)

        fake_w3.eth.estimate_gas = blocking_estimate  # type: ignore[method-assign]
        results: list[object] = []

        def first_send() -> None:
            results.append(
                test_signer.send("testchain", to="0x" + "aa" * 20, request_id="dup")
            )

        thread = threading.Thread(target=first_send)
        thread.start()
        assert started.wait(timeout=10)  # original is now mid-broadcast
        with pytest.raises(SignerError, match="already in flight"):
            test_signer.send("testchain", to="0x" + "aa" * 20, request_id="dup")
        release.set()
        thread.join(timeout=10)
        assert len(fake_w3.eth.sent) == 1
        # after completion the cached hash is returned, still without rebroadcast
        assert (
            test_signer.send("testchain", to="0x" + "aa" * 20, request_id="dup")
            == results[0]
        )
        assert len(fake_w3.eth.sent) == 1

    def test_idempotency_cache_returns_cached_inside_run(self) -> None:
        """run() itself replays a completed key (guards the racing-caller path)."""
        from pearl_connect.signer import _IdempotencyCache

        cache = _IdempotencyCache()
        assert cache.run("k", lambda: "0xaaa") == "0xaaa"
        assert cache.run("k", lambda: "0xbbb") == "0xaaa"  # action not re-run

    def test_idempotency_cache_evicts_oldest(self) -> None:
        """The result cache is bounded; the oldest replays are dropped first."""
        from pearl_connect.signer import _IdempotencyCache

        cache = _IdempotencyCache(max_results=2)
        cache.run("a", lambda: "0xa")
        cache.run("b", lambda: "0xb")
        cache.run("c", lambda: "0xc")
        assert cache.cached("a") is None  # evicted; a very late retry re-runs
        assert cache.cached("b") == "0xb"
        assert cache.cached("c") == "0xc"

    def test_failed_send_releases_request_id(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A failed send frees its request_id so a retry can re-attempt."""
        fake_w3.eth.fail_broadcast = True
        with pytest.raises(SignerError):
            test_signer.send("testchain", to="0x" + "aa" * 20, request_id="retry-me")
        fake_w3.eth.fail_broadcast = False
        tx_hash = test_signer.send(
            "testchain", to="0x" + "aa" * 20, request_id="retry-me"
        )
        assert tx_hash.startswith("0x")
        assert len(fake_w3.eth.sent) == 1  # only the successful retry broadcast

    def test_priority_fee_fallback(self, test_signer: Signer, fake_w3: FakeW3) -> None:
        """A missing eth_maxPriorityFeePerGas falls back to 1 gwei."""
        fake_w3.eth.priority_fee_raises = True
        assert test_signer.send("testchain", to="0x" + "aa" * 20).startswith("0x")

    def test_legacy_gas_price(self, test_signer: Signer, fake_w3: FakeW3) -> None:
        """Chains without base fee use legacy gasPrice."""
        fake_w3.eth.base_fee = None
        assert test_signer.send("testchain", to="0x" + "aa" * 20).startswith("0x")


class FakeToken:
    """ERC-20 contract stand-in."""

    class _Call:
        """Callable returning a fixed value."""

        def __init__(self, value: int) -> None:
            """Initialize."""
            self._value = value

        def call(self) -> int:
            """Return the value."""
            return self._value

    class _Functions:
        """Functions namespace."""

        def decimals(self) -> "FakeToken._Call":
            """Token decimals."""
            return FakeToken._Call(6)

        def balanceOf(self, _address: str) -> "FakeToken._Call":  # noqa: N802
            """Token balance."""
            return FakeToken._Call(777)

    functions = _Functions()


class TestWalletExtras:
    """wallet helpers."""

    def test_asset_balance_native_and_erc20(self, fake_w3: FakeW3) -> None:
        """Native uses get_balance; ERC-20 uses the token contract."""
        fake_w3.eth.contract = (  # type: ignore[attr-defined]
            lambda address, abi: FakeToken()
        )
        native = wallet.asset_balance(
            t.cast(Web3, fake_w3), "0x" + "00" * 20, "0x" + "aa" * 20, "c1"
        )
        assert native == (12345, 18)
        erc20 = wallet.asset_balance(
            t.cast(Web3, fake_w3), "0x" + "99" * 20, "0x" + "aa" * 20, "c1"
        )
        assert erc20 == (777, 6)
        # decimals cached on second call
        assert wallet.asset_balance(
            t.cast(Web3, fake_w3), "0x" + "99" * 20, "0x" + "aa" * 20, "c1"
        ) == (777, 6)

    def test_funds_status_resolves_safe_role(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """The "safe" role resolves to the chain's configured safe address."""
        app_config.fund_requirements = {
            "testchain": {"safe": {"0x" + "00" * 20: 99999}}
        }
        report = wallet.funds_status(app_config, test_signer)
        safe = app_config.chains["testchain"].safe_address
        assert list(report["testchain"]) == [safe]

    def test_funds_status_skips_unknown_chain_and_missing_safe(
        self, app_config: AppConfig, test_signer: Signer
    ) -> None:
        """Unknown chains and unresolvable roles are skipped."""
        app_config.chains["testchain"].safe_address = None
        app_config.fund_requirements = {
            "notachain": {"agent": {"0x" + "00" * 20: 1}},
            "testchain": {
                "safe": {"0x" + "00" * 20: 1},  # unresolvable: no safe configured
                "agent": {"0x" + "00" * 20: 99999},
            },
        }
        report = wallet.funds_status(app_config, test_signer)
        assert list(report) == ["testchain"]
        entry = report["testchain"][test_signer.address]["0x" + "00" * 20]
        assert entry == {
            "balance": "12345",
            "deficit": str(99999 - 12345),
            "decimals": 18,
        }

    def test_wallet_overview_error_branch(
        self,
        app_config: AppConfig,
        test_signer: Signer,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per-chain RPC failures land in the balances as errors."""
        monkeypatch.setattr(
            test_signer, "w3", lambda chain: (_ for _ in ()).throw(RuntimeError("down"))
        )
        overview = wallet.wallet_overview(app_config, test_signer)
        assert overview["balances"]["testchain"] == {"error": "down"}


class TestPearlRoutesExtras:
    """funds-status caching and failure handling."""

    def test_funds_status_cache_hit(
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
    ) -> None:
        """A warm cache short-circuits computation."""
        import time as time_module

        from fastapi.testclient import TestClient

        app = make_app(test_signer, app_config, activity)
        app.state.funds_cache["at"] = time_module.monotonic()
        app.state.funds_cache["value"] = {"cached": True}
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            assert client.get("/funds-status").json() == {"cached": True}

    def test_funds_status_failure_returns_empty(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
        make_app: t.Callable,
    ) -> None:
        """RPC failure yields {} instead of an error."""
        from fastapi.testclient import TestClient

        monkeypatch.setattr(
            wallet, "funds_status", lambda c, s: (_ for _ in ()).throw(RuntimeError())
        )
        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            assert client.get("/funds-status").json() == {}


class TestSignerRoutesExtras:
    """Signer route validation edge cases."""

    def test_int_value_passthrough(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
        make_app: t.Callable,
    ) -> None:
        """Integer values pass the coercing validator untouched."""
        from fastapi.testclient import TestClient

        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            response = client.post(
                "/sign-and-send",
                json={"chain": "testchain", "to": "0x" + "aa" * 20, "value": 5},
                headers={"Authorization": "Bearer tok"},
            )
        assert response.status_code == 200

    def test_negative_value_is_422(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
        make_app: t.Callable,
    ) -> None:
        """Negative amounts are rejected by validation, before the signer."""
        from fastapi.testclient import TestClient

        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            response = client.post(
                "/sign-and-send",
                json={"chain": "testchain", "to": "0x" + "aa" * 20, "value": -1},
                headers={"Authorization": "Bearer tok"},
            )
        assert response.status_code == 422
        assert not fake_w3.eth.sent

    def test_sign_message_bad_digest_is_400(
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
    ) -> None:
        """A short digest is rejected with 400."""
        from fastapi.testclient import TestClient

        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            response = client.post(
                "/sign-message",
                json={"digest": "0xabcd"},
                headers={"Authorization": "Bearer tok"},
            )
        assert response.status_code == 400
