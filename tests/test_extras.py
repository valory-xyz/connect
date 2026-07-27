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

"""Tests for entrypoint, MCP tools, wallet helpers, workspace launch and auth ASGI."""

import json
import logging
import threading
import time as time_module
import typing as t
from pathlib import Path

import pytest
import uvicorn
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from web3 import Web3

from connect import __main__ as main_module
from connect import signer as signer_module
from connect import wallet, workspace
from connect.activity import ActivityLog, MAX_LOG_BYTES
from connect.config import (
    AppConfig,
    ChainConfig,
    FUND_REQUIREMENTS_ENV,
    SAFES_ENV,
    STORE_PATH_ENV,
    load_config,
)
from connect.guard import Guard
from connect.keystore import KeystoreError, load_account
from connect.mech import MechService
from connect.server.auth import AuthFailureLimiter, AuthMiddleware
from connect.server.mcp_tools import build_mcp
from connect.settings import SettingsStore
from connect.signer import Signer, SignerError, _IdempotencyCache

from tests.conftest import FakeW3, TEST_PASSWORD, audit_kinds


class StubServer:
    """uvicorn.Server stand-in that never serves."""

    def __init__(self, config: uvicorn.Config) -> None:
        """Initialize."""
        self.config = config
        self.started = False
        self.should_exit = True

    def run(self) -> None:
        """Do nothing."""


@pytest.fixture(name="served")
def served_fixture(monkeypatch: pytest.MonkeyPatch) -> list[StubServer]:
    """Capture the servers main() builds, so tests can read the app it served."""
    servers: list[StubServer] = []

    def record(config: uvicorn.Config) -> StubServer:
        servers.append(StubServer(config))
        return servers[-1]

    monkeypatch.setattr(main_module.uvicorn, "Server", record)
    return servers


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
        self,
        monkeypatch: pytest.MonkeyPatch,
        keystore_dir: Path,
        store_path: Path,
        served: list[StubServer],
    ) -> None:
        """A clean boot provisions the workspace and reports itself healthy.

        The mirror of the unhealthy cases below: Pearl only opens a session
        once is_healthy turns true, so a regression that left a good boot
        unhealthy would quietly mean no session ever opens.
        """
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        monkeypatch.delenv(SAFES_ENV, raising=False)
        monkeypatch.delenv(FUND_REQUIREMENTS_ENV, raising=False)
        assert main_module.main(["--password", TEST_PASSWORD]) == 0
        assert (store_path / ".mcp.json").exists()
        app = served[0].config.app
        assert app.state.workspace.reason is None
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            assert client.get("/healthcheck").json() == {"is_healthy": True}

    def test_populate_failure_serves_unhealthy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keystore_dir: Path,
        store_path: Path,
        served: list[StubServer],
    ) -> None:
        """A workspace failure keeps the server up, but never claims health.

        Pearl opens the session as soon as we report healthy — with no
        .mcp.json and no skills, that session could not reach the signer, so
        the honest answer is unhealthy rather than an invitation we cannot
        honor.
        """
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        monkeypatch.setattr(
            workspace.Workspace,
            "_provision",
            lambda self: (_ for _ in ()).throw(RuntimeError("disk full")),
        )
        assert main_module.main(["--password", TEST_PASSWORD]) == 0
        app = served[0].config.app
        assert app.state.workspace.reason is not None
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            assert client.get("/healthcheck").json() == {"is_healthy": False}
            # and the session Pearl would start is refused, not half-opened
            assert client.post("/session").status_code == 503

    def test_degraded_boot_still_writes_the_sdk_contract_file(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keystore_dir: Path,
        store_path: Path,
        served: list[StubServer],
    ) -> None:
        """Pearl reads agent_performance.json whatever our health says.

        A workspace that failed to populate (here: a bundle with no CLAUDE.md)
        still leaves a readable store — withholding the SDK contract file on
        top of reporting unhealthy would just break the desktop app twice.
        """
        assets = store_path / "fake-assets"
        (assets / "skills").mkdir(parents=True)  # no CLAUDE.md: populate raises
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        monkeypatch.delenv(SAFES_ENV, raising=False)
        monkeypatch.delenv(FUND_REQUIREMENTS_ENV, raising=False)
        assert main_module.main(["--password", TEST_PASSWORD]) == 0
        assert served[0].config.app.state.workspace.reason is not None
        assert (store_path / "agent_performance.json").exists()

    def test_unusable_store_serves_unhealthy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keystore_dir: Path,
        tmp_path: Path,
        served: list[StubServer],
    ) -> None:
        """A store we cannot write to must not crash-loop the binary.

        Everything that provisions the store fails here — populate and the
        performance file alike — and the middleware would just restart a
        process that dies. Serve, and report unhealthy.

        The store is placed under a regular file rather than a chmod'd
        directory: permission bits do not stop a write on Windows, and this
        failure must be reproduced on every platform we ship to.
        """
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("a file where the store's parent should be")
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(blocker / "store"))
        monkeypatch.delenv(SAFES_ENV, raising=False)
        monkeypatch.delenv(FUND_REQUIREMENTS_ENV, raising=False)
        assert main_module.main(["--password", TEST_PASSWORD]) == 0  # not a crash
        assert served[0].config.app.state.workspace.reason is not None

    def test_boot_opens_no_session(
        self,
        monkeypatch: pytest.MonkeyPatch,
        keystore_dir: Path,
        store_path: Path,
        served: list[StubServer],
    ) -> None:
        """Booting never opens a session: Pearl drives POST /session itself.

        Launching here would strand a failure in this process's log, where
        neither the FE nor the operator can see it.
        """
        monkeypatch.chdir(keystore_dir)
        monkeypatch.setenv(STORE_PATH_ENV, str(store_path))
        monkeypatch.delenv(SAFES_ENV, raising=False)
        monkeypatch.delenv(FUND_REQUIREMENTS_ENV, raising=False)
        opened: list[Path] = []
        monkeypatch.setattr(
            workspace.Workspace,
            "open_session",
            lambda self, harness=None: opened.append(self.path),
        )
        assert main_module.main(["--password", TEST_PASSWORD]) == 0
        assert not opened
        assert served  # it did serve — it just did not launch anything


class TestActivityExtras:
    """Activity log rotation and public performance writer."""

    def test_rotation(self, store_path: Path, activity: ActivityLog) -> None:
        """Oversized log rotates to .jsonl.1."""
        log_file = store_path / "activity_log.jsonl"
        log_file.write_text("x" * (MAX_LOG_BYTES + 1))
        activity.record("transaction", chain="testchain")
        assert (store_path / "activity_log.jsonl.1").exists()

    def test_unwritable_log_never_fails_the_caller(
        self,
        store_path: Path,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A failing disk must not undo work the caller already completed.

        record() runs after the fact — the transaction is broadcast, the
        session is open. Raising here would report those as failures and
        invite a retry of work that already happened.
        """
        monkeypatch.setattr(
            ActivityLog,
            "_append",
            lambda self, entry: (_ for _ in ()).throw(OSError("read-only fs")),
        )
        with caplog.at_level(logging.ERROR):
            activity.record("session_launched", harness="claude_code_cli")
        assert "could not persist activity entry" in caplog.text
        # the caller's work stands: still counted, so the UI stays coherent
        assert activity.count == 1

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


class TestAuthMiddlewareASGI:
    """Direct ASGI-level tests of the MCP mount auth."""

    @staticmethod
    async def _run(
        middleware: AuthMiddleware, scope: dict
    ) -> tuple[list[dict], list[str]]:
        """Invoke the middleware, returning (sent messages, inner-app calls)."""
        sent: list[dict] = []
        passed: list[str] = []

        async def inner(scope: t.Any, receive: t.Any, send: t.Any) -> None:
            passed.append(scope["type"])

        middleware._app = inner  # pylint: disable=protected-access

        async def send(message: dict) -> None:
            sent.append(message)

        await middleware(scope, None, send)
        return sent, passed

    async def test_non_http_passthrough(self, activity: ActivityLog) -> None:
        """Lifespan scopes bypass auth."""
        middleware = AuthMiddleware(
            lambda *a: None, "tok", activity, AuthFailureLimiter()
        )
        _, passed = await self._run(middleware, {"type": "lifespan"})
        assert passed == ["lifespan"]

    async def test_bad_origin_rejected(self, activity: ActivityLog) -> None:
        """Cross-origin requests get 403."""
        middleware = AuthMiddleware(
            lambda *a: None, "tok", activity, AuthFailureLimiter()
        )
        scope = {
            "type": "http",
            "headers": [(b"origin", b"https://evil.example")],
        }
        sent, passed = await self._run(middleware, scope)
        assert sent[0]["status"] == 403
        assert not passed

    async def test_bad_token_rejected(self, activity: ActivityLog) -> None:
        """Missing token gets 401."""
        middleware = AuthMiddleware(
            lambda *a: None, "tok", activity, AuthFailureLimiter()
        )
        sent, passed = await self._run(middleware, {"type": "http", "headers": []})
        assert sent[0]["status"] == 401
        assert not passed

    async def test_websocket_scope_refused_cleanly(self, activity: ActivityLog) -> None:
        """Websocket scopes never reach the inner app; the handshake is closed."""
        middleware = AuthMiddleware(
            lambda *a: None, "tok", activity, AuthFailureLimiter()
        )
        sent, passed = await self._run(middleware, {"type": "websocket", "headers": []})
        assert not passed
        assert sent == [{"type": "websocket.close"}]

    async def test_valid_request_passes(self, activity: ActivityLog) -> None:
        """Correct token reaches the inner app."""
        middleware = AuthMiddleware(
            lambda *a: None, "tok", activity, AuthFailureLimiter()
        )
        scope = {"type": "http", "headers": [(b"authorization", b"Bearer tok")]}
        _, passed = await self._run(middleware, scope)
        assert passed == ["http"]


class TestMcpTools:
    """MCP tool behavior via the registered tool functions."""

    @pytest.fixture
    def tools(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        guard: Guard,
        mech_service: MechService,
        settings_store: SettingsStore,
    ) -> dict[str, t.Callable]:
        """Return the registered tool functions keyed by name."""
        mcp = build_mcp(
            test_signer,
            app_config,
            activity,
            guard=guard,
            mech=mech_service,
            settings_store=settings_store,
        )
        manager = mcp._tool_manager  # pylint: disable=protected-access
        return {tool.name: tool.fn for tool in manager.list_tools()}

    async def test_wallet_info(
        self, tools: dict[str, t.Callable], test_signer: Signer
    ) -> None:
        """wallet_info reports the agent EOA, balances and what is actionable."""
        info = await tools["wallet_info"]()
        assert info["agent_eoa"] == test_signer.address
        assert info["chains"]["testchain"]["balances"]["agent_eoa"] == "12345"
        # the verdict is stated, not left to be inferred from the other keys
        assert info["actionable_chains"] == ["testchain"]
        assert info["chains"]["testchain"]["actionable"] is True
        assert "not_actionable_because" not in info["chains"]["testchain"]

    async def test_send_transaction_request_id_idempotency(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """Retrying the tool with the same request_id broadcasts exactly once."""
        first = await tools["send_transaction"](
            "testchain", "0x" + "aa" * 20, request_id="r1"
        )
        retry = await tools["send_transaction"](
            "testchain", "0x" + "aa" * 20, request_id="r1"
        )
        assert first["tx_hash"] == retry["tx_hash"]
        assert len(fake_w3.eth.sent) == 1

    async def test_send_transaction_no_wait(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """send_transaction returns the hash immediately."""
        result = await tools["send_transaction"]("testchain", "0x" + "aa" * 20)
        assert result["tx_hash"].startswith("0x")
        assert len(fake_w3.eth.sent) == 1

    async def test_safe_transaction_spends_from_the_safe(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """The tool names the inner call; the server wraps it and broadcasts."""
        result = await tools["safe_transaction"](
            "testchain", "0x" + "aa" * 20, value=10**18
        )
        assert result["tx_hash"].startswith("0x")
        assert len(fake_w3.eth.sent) == 1

    async def test_safe_transaction_settles_like_any_other_send(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """Receipt when it mines, 'pending' when it does not."""
        fake_w3.eth.receipt = {
            "status": 1,
            "blockNumber": 7,
            "gasUsed": 21000,
            "logs": [],
        }
        mined = await tools["safe_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=5
        )
        assert mined["receipt"]["status"] == 1

        fake_w3.eth.receipt = None
        pending = await tools["safe_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=0
        )
        assert pending["status"] == "pending"

    async def test_a_reverted_tx_is_not_reported_as_success(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """status==0 surfaces as top-level 'reverted', not a success-shaped dict."""
        fake_w3.eth.receipt = {
            "status": 0,
            "blockNumber": 7,
            "gasUsed": 21000,
            "logs": [],
        }
        result = await tools["safe_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=5
        )
        assert result["status"] == "reverted"
        assert result["tx_hash"].startswith("0x")

    async def test_a_post_broadcast_receipt_error_keeps_the_hash(
        self,
        tools: dict[str, t.Callable],
        fake_w3: FakeW3,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A receipt-read hiccup after broadcast is 'pending', never a lost hash.

        The tx is already on-chain; reporting failure would invite a resend that
        double-spends. It comes back pending, with the hash and the error.
        """

        def boom(*_a: object, **_kw: object) -> dict:
            raise ConnectionError("rpc dropped")

        monkeypatch.setattr(fake_w3.eth, "wait_for_transaction_receipt", boom)
        result = await tools["safe_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=5
        )
        assert fake_w3.eth.sent  # the premise: it really was broadcast first
        assert result["status"] == "pending"
        assert result["tx_hash"].startswith("0x")
        assert "rpc dropped" in result["receipt_error"]

    async def test_safe_transaction_rejects_a_negative_value(
        self, tools: dict[str, t.Callable]
    ) -> None:
        """A negative value is the caller's mistake, caught before the chain."""
        with pytest.raises(ValueError, match="non-negative"):
            await tools["safe_transaction"]("testchain", "0x" + "aa" * 20, value=-1)

    async def test_safe_transaction_malformed_target_is_a_clean_error(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """A bad compose input fails as an error, not a broadcast — at the tool too."""
        with pytest.raises(SignerError, match="cannot compose"):
            await tools["safe_transaction"]("testchain", "0x1234")
        assert not fake_w3.eth.sent

    async def test_send_transaction_wait_mined(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """send_transaction with wait returns the receipt when mined."""
        fake_w3.eth.receipt = {
            "status": 1,
            "blockNumber": 7,
            "gasUsed": 21000,
            "logs": [],
        }
        result = await tools["send_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=5
        )
        assert result["receipt"]["status"] == 1

    async def test_send_transaction_wait_pending(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """send_transaction with wait times out to pending."""
        result = await tools["send_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=0
        )
        assert result["status"] == "pending"

    async def test_send_transaction_wait_caps_timeout(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """The wait timeout is capped at MAX_RECEIPT_TIMEOUT."""
        waits: list[float] = []

        def recording_wait(
            tx_hash: object, timeout: float = 120, poll_latency: float = 0.1
        ) -> dict:
            waits.append(timeout)
            return {"status": 1, "blockNumber": 9, "gasUsed": 21000, "logs": []}

        fake_w3.eth.wait_for_transaction_receipt = (  # type: ignore[method-assign]
            recording_wait
        )
        result = await tools["send_transaction"](
            "testchain", "0x" + "aa" * 20, wait_for_receipt=True, timeout=10**9
        )
        assert result["receipt"]["block_number"] == 9
        assert waits == [300]

    async def test_transaction_status(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """transaction_status reports pending, then mined, then reverted.

        It speaks the same top-level status the send tools do, so a tx polled
        here after a pending send is read the same way — a revert is not a
        success-shaped dict a caller reads past.
        """
        tx_hash = "0x" + "11" * 32
        pending = await tools["transaction_status"]("testchain", tx_hash)
        assert pending["status"] == "pending"
        fake_w3.eth.receipt = {
            "status": 1,
            "blockNumber": 7,
            "gasUsed": 21000,
            "logs": [],
        }
        mined = await tools["transaction_status"]("testchain", tx_hash)
        assert mined["status"] == "mined"
        assert mined["receipt"]["block_number"] == 7
        fake_w3.eth.receipt = {**fake_w3.eth.receipt, "status": 0}
        reverted = await tools["transaction_status"]("testchain", tx_hash)
        assert reverted["status"] == "reverted"

    async def test_transaction_status_rejects_malformed_hash(
        self, tools: dict[str, t.Callable]
    ) -> None:
        """A hash that can never resolve raises instead of polling as pending."""
        with pytest.raises(ValueError, match="32-byte"):
            await tools["transaction_status"]("testchain", "0xzz")
        with pytest.raises(ValueError, match="32-byte"):
            await tools["transaction_status"]("testchain", "0x1234")

    async def test_transaction_status_surfaces_rpc_errors(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """A dead RPC is an error, not a fake "pending"."""

        def broken(tx_hash: object) -> dict:
            raise RuntimeError("rpc down")

        fake_w3.eth.get_transaction_receipt = broken  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="rpc down"):
            await tools["transaction_status"]("testchain", "0x" + "11" * 32)

    async def test_sign_message(
        self, tools: dict[str, t.Callable], account: LocalAccount
    ) -> None:
        """sign_message signs a raw digest."""
        result = await tools["sign_message"]("0x" + "ab" * 32)
        assert len(bytes.fromhex(result["signature"][2:])) == 65

    async def test_sign_message_rejects_bad_hex(
        self, tools: dict[str, t.Callable]
    ) -> None:
        """Malformed digests get a clean error, matching the HTTP route."""
        with pytest.raises(ValueError, match="0x-hex"):
            await tools["sign_message"]("0xzz")

    async def test_send_transaction_rejects_negative_value(
        self, tools: dict[str, t.Callable], fake_w3: FakeW3
    ) -> None:
        """Negative amounts fail fast, before reaching the signer."""
        with pytest.raises(ValueError, match="non-negative"):
            await tools["send_transaction"]("testchain", "0x" + "aa" * 20, value=-1)
        assert not fake_w3.eth.sent


class TestSignerExtras:
    """Signer edge cases."""

    def test_chain_state_builds_real_web3(
        self, monkeypatch: pytest.MonkeyPatch, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Unknown-but-configured chains get a Web3 client, cached."""
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
        self,
        store_path: Path,
        test_signer: Signer,
        fake_w3: FakeW3,
        activity: ActivityLog,
    ) -> None:
        """A node rejection surfaces as SignerError and is logged."""
        fake_w3.eth.fail_broadcast = True
        with pytest.raises(SignerError, match="send failed"):
            test_signer.send("testchain", to="0x" + "aa" * 20)
        assert audit_kinds(store_path)[-1] == "send_failed"

    def test_estimation_failure_is_signer_error(
        self,
        store_path: Path,
        test_signer: Signer,
        fake_w3: FakeW3,
        activity: ActivityLog,
    ) -> None:
        """A gas-estimation revert surfaces as SignerError, not a raw exception."""

        def reverting_estimate(tx: dict) -> int:
            raise RuntimeError("execution reverted: not enough funds")

        fake_w3.eth.estimate_gas = reverting_estimate  # type: ignore[method-assign]
        with pytest.raises(SignerError, match="execution reverted"):
            test_signer.send("testchain", to="0x" + "aa" * 20)
        assert audit_kinds(store_path)[-1] == "send_failed"

    def test_concurrent_duplicate_request_id_rejected(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A retry racing an in-flight send with the same id cannot double-spend."""
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
        cache = _IdempotencyCache()
        assert cache.run("k", lambda: "0xaaa") == "0xaaa"
        assert cache.run("k", lambda: "0xbbb") == "0xaaa"  # action not re-run

    def test_idempotency_cache_evicts_oldest(self) -> None:
        """The result cache is bounded; the oldest replays are dropped first."""
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
        """A chain whose RPC failed is reported unusable, not merely balance-less.

        Nothing established that the chain is usable, and an optimistic guess
        is what sends an agent off to plan work it cannot carry out.
        """
        monkeypatch.setattr(
            test_signer, "w3", lambda chain: (_ for _ in ()).throw(RuntimeError("down"))
        )
        overview = wallet.wallet_overview(app_config, test_signer)
        entry = overview["chains"]["testchain"]
        assert entry["balances"] == {"error": "down"}
        assert entry["actionable"] is False
        assert "down" in entry["not_actionable_because"]
        assert overview["actionable_chains"] == []

    def test_overview_separates_undeployed_from_unfunded_chains(
        self, app_config: AppConfig, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """The two unusable cases are named apart; they need different remedies.

        A chain with no safe was never deployed to. A chain with a safe but no
        gas in the EOA is deployed and merely needs funding — telling an
        operator the wrong one sends them to fix the wrong thing. The missing
        safe is reported as such even though this chain's RPC is unreachable,
        because that fact comes from configuration, not from the network.
        """
        app_config.chains["nosafe"] = ChainConfig(rpc_url="http://127.0.0.1:9")
        overview = wallet.wallet_overview(app_config, test_signer)
        assert overview["chains"]["nosafe"]["safe"] is None
        assert (
            "no service safe" in overview["chains"]["nosafe"]["not_actionable_because"]
        )
        assert overview["actionable_chains"] == ["testchain"]  # the deployed one

        # deployed, but the EOA cannot pay gas there
        fake_w3.eth.balance = 0
        overview = wallet.wallet_overview(app_config, test_signer)
        assert "no gas" in overview["chains"]["testchain"]["not_actionable_because"]
        assert overview["actionable_chains"] == []


class TestPearlRoutesExtras:
    """funds-status caching and failure handling."""

    def test_racing_pollers_rebuild_the_workspace_once(
        self, store_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loser of the readiness race must not repopulate on top of it.

        /healthcheck is polled, so two calls can arrive together while the
        workspace is unusable. The second blocks on the lock, and by the time
        it gets in the first has already succeeded — it has to see that, not
        redo the work.
        """
        agent_workspace = workspace.Workspace(store_path, "tok")  # nosec B106
        populated: list[int] = []
        monkeypatch.setattr(
            workspace.Workspace, "_provision", lambda self: populated.append(1)
        )

        class LostTheRace:
            """A lock whose holder finished the job while we were waiting."""

            def __enter__(self) -> None:
                # pylint: disable=protected-access
                agent_workspace._reason = None  # the other poller got there first

            def __exit__(self, *_: object) -> None:
                """Nothing to release: this lock exists only to lose the race."""

        monkeypatch.setattr(agent_workspace, "_lock", LostTheRace())
        assert agent_workspace.ensure() is True
        assert populated == []  # the work was already done

    def test_funds_status_cache_hit(
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
    ) -> None:
        """A warm cache short-circuits computation."""
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
        app = make_app(test_signer, app_config, activity)
        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            response = client.post(
                "/sign-message",
                json={"digest": "0xabcd"},
                headers={"Authorization": "Bearer tok"},
            )
        assert response.status_code == 400


class TestWorkspaceExtras:
    """Workspace population and launch edge cases."""

    def test_assets_dir_meipass(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The PyInstaller _MEIPASS dir containing assets/ is used."""
        (tmp_path / "assets").mkdir()
        monkeypatch.setattr(workspace.sys, "_MEIPASS", str(tmp_path), raising=False)
        assert workspace.assets_dir() == tmp_path / "assets"

    def test_assets_dir_missing_raises(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """No assets anywhere raises FileNotFoundError."""
        monkeypatch.setattr(workspace.sys, "_MEIPASS", str(tmp_path), raising=False)
        with pytest.raises(FileNotFoundError):
            workspace.assets_dir()

    def test_missing_claude_md_fails_the_workspace(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store_path: Path
    ) -> None:
        """A bundle with no CLAUDE.md fails populate, so boot reports unhealthy.

        Warning and carrying on would open the session into a workspace with
        no idea what it is — while the server claimed to be healthy.
        """
        assets = tmp_path / "assets"
        (assets / "skills").mkdir(parents=True)
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)
        agent_workspace = workspace.Workspace(store_path, "tok")  # nosec B106
        assert agent_workspace.ensure() is False
        assert "CLAUDE.md" in str(agent_workspace.reason)

    def test_invalid_mcp_json_rewritten(self, store_path: Path) -> None:
        """Corrupt .mcp.json is replaced rather than crashing."""
        (store_path / ".mcp.json").write_text("{corrupt")
        assert workspace.Workspace(store_path, "tok").ensure() is True  # nosec B106
        config = json.loads((store_path / ".mcp.json").read_text())
        assert "pearl-connect" in config["mcpServers"]

    def test_stray_file_in_skill_assets_skipped(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, store_path: Path
    ) -> None:
        """Non-directory entries under assets/skills are ignored."""
        skills = tmp_path / "assets" / "skills"
        (skills / "my-skill").mkdir(parents=True)
        (skills / "my-skill" / "SKILL.md").write_text("hi")
        (skills / "stray.txt").write_text("not a skill")
        (tmp_path / "assets" / "CLAUDE.md").write_text("brief")  # populate requires it
        monkeypatch.setattr(workspace.sys, "_MEIPASS", str(tmp_path), raising=False)
        assert workspace.Workspace(store_path, "tok").ensure() is True  # nosec B106
        installed = store_path / ".claude" / "skills"
        assert (installed / "my-skill" / "SKILL.md").exists()
        assert not (installed / "stray.txt").exists()

    def test_open_url_linux(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """xdg-open success, failure and exception paths."""

        class Result:
            """subprocess result stub."""

            def __init__(self, code: int) -> None:
                """Initialize."""
                self.returncode = code

        monkeypatch.setattr(workspace.sys, "platform", "linux")
        monkeypatch.setattr(workspace.subprocess, "run", lambda *a, **k: Result(0))
        assert workspace._open_url("claude://x")  # pylint: disable=protected-access
        monkeypatch.setattr(workspace.subprocess, "run", lambda *a, **k: Result(1))
        assert not workspace._open_url("claude://x")  # pylint: disable=protected-access
        monkeypatch.setattr(
            workspace.subprocess,
            "run",
            lambda *a, **k: (_ for _ in ()).throw(OSError("no handler")),
        )
        assert not workspace._open_url("claude://x")  # pylint: disable=protected-access
