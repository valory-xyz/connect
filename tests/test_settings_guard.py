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

"""Tests for the tamper-evident settings store and the guardrail."""

import json
import logging
import typing as t
from pathlib import Path

import pytest
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from pearl_connect import settings as settings_module
from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig, ChainConfig
from pearl_connect.guard import EXEC_TRANSACTION_SELECTOR, Guard, GuardError
from pearl_connect.settings import (
    MODE_RESTRICTED,
    MODE_UNRESTRICTED,
    Settings,
    SettingsStore,
    default_whitelist,
    defaults,
    derive_mac_key,
)
from pearl_connect.signer import Signer, SignerError

from tests.conftest import FakeW3, TEST_PASSWORD

SAFE = "0x" + "22" * 20
WHITELISTED = "0x" + "aa" * 20
OTHER = "0x" + "bb" * 20


def exec_transaction_calldata(  # pylint: disable=too-many-arguments
    to: str,
    value: int = 0,
    data: bytes = b"",
    operation: int = 0,
    gas_price: int = 0,
    gas_token: str = "0x" + "00" * 20,
    refund_receiver: str = "0x" + "00" * 20,
) -> str:
    """Encode Safe execTransaction calldata."""
    encoded = abi_encode(
        [
            "address",
            "uint256",
            "bytes",
            "uint8",
            "uint256",
            "uint256",
            "uint256",
            "address",
            "address",
            "bytes",
        ],
        [to, value, data, operation, 0, 0, gas_price, gas_token, refund_receiver, b""],
    )
    return "0x" + EXEC_TRANSACTION_SELECTOR + encoded.hex()


@pytest.fixture(name="store")
def store_fixture(
    account: LocalAccount, store_path: Path, activity: ActivityLog
) -> SettingsStore:
    """Return a settings store with a fresh (never-written) file."""
    return SettingsStore(
        store_path / "pearl-connect.settings.json", derive_mac_key(account), activity
    )


class TestSettingsStore:
    """SettingsStore verification behavior."""

    def test_missing_file_writes_restricted_defaults(
        self, store: SettingsStore
    ) -> None:
        """A fresh store fails closed to restricted defaults and persists them."""
        loaded = store.load()
        assert loaded.mode == MODE_RESTRICTED
        assert loaded.whitelist == default_whitelist()
        assert store._path.exists()  # pylint: disable=protected-access

    def test_roundtrip(self, store: SettingsStore) -> None:
        """Saved settings load back identically, immediately (no cache)."""
        store.save(
            Settings(
                mode=MODE_UNRESTRICTED,
                whitelist={"gnosis": (OTHER,)},
                harness="claude_code_cli",
            )
        )
        loaded = store.load()
        assert loaded.mode == MODE_UNRESTRICTED
        assert loaded.whitelist == {"gnosis": (OTHER,)}
        assert loaded.harness == "claude_code_cli"
        # a fresh store defaults to the desktop harness
        assert defaults().harness == "claude_code_desktop"

    @pytest.mark.parametrize(
        "corrupt",
        [
            "not json at all",
            "[]",
            json.dumps({"version": 1, "mode": "unrestricted", "whitelist": {}}),
        ],
    )
    def test_tampered_content_restores_defaults(
        self, store: SettingsStore, activity: ActivityLog, corrupt: str
    ) -> None:
        """Unverifiable content is replaced with defaults and audited."""
        store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
        store._path.write_text(corrupt)  # pylint: disable=protected-access
        loaded = store.load()
        assert loaded.mode == MODE_RESTRICTED
        assert any(e["kind"] == "settings_tampered" for e in activity.recent())
        # the rewritten file verifies again
        assert store.load().mode == MODE_RESTRICTED

    def test_edited_field_fails_mac(self, store: SettingsStore) -> None:
        """Flipping the mode in the JSON without the key fails verification."""
        store.save(Settings(mode=MODE_RESTRICTED, whitelist={}))
        path = store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["mode"] = "unrestricted"  # the attack this file exists to stop
        path.write_text(json.dumps(payload))
        assert store.load().mode == MODE_RESTRICTED

    def test_valid_mac_but_bad_mode_rejected(self, store: SettingsStore) -> None:
        """A MAC'd payload with an unknown mode still falls back to defaults."""
        payload: dict = {"version": 1, "mode": "yolo", "whitelist": {}}
        payload["mac"] = store._mac(payload)  # pylint: disable=protected-access
        store._path.write_text(json.dumps(payload))  # pylint: disable=protected-access
        assert store.load().mode == MODE_RESTRICTED

    def test_mac_key_requires_the_private_key(
        self, store: SettingsStore, activity: ActivityLog
    ) -> None:
        """A store keyed by a different account rejects the file."""
        store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
        other = SettingsStore(
            store._path,  # pylint: disable=protected-access
            derive_mac_key(Account.create()),
            activity,
        )
        assert other.load().mode == MODE_RESTRICTED

    def test_replayed_old_file_is_rejected(
        self, store: SettingsStore, activity: ActivityLog
    ) -> None:
        """Putting back an old validly-MAC'd file fails like any other tamper."""
        store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
        path = store._path  # pylint: disable=protected-access
        unrestricted_file = path.read_bytes()  # captured while unrestricted
        store.save(Settings(mode=MODE_RESTRICTED, whitelist={}))
        path.write_bytes(unrestricted_file)  # the rollback attack
        assert store.load().mode == MODE_RESTRICTED
        assert any(e["kind"] == "settings_tampered" for e in activity.recent())

    def test_fresh_process_accepts_any_valid_mac(
        self, store: SettingsStore, account: LocalAccount, activity: ActivityLog
    ) -> None:
        """A new store instance (a restart) pins the first valid file it sees."""
        store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
        restarted = SettingsStore(
            store._path,  # pylint: disable=protected-access
            derive_mac_key(account),
            activity,
        )
        assert restarted.load().mode == MODE_UNRESTRICTED

    def test_unwritable_store_still_fails_closed(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If persisting the reset fails, enforcement still gets defaults."""
        store._path.write_text("garbage")  # pylint: disable=protected-access
        monkeypatch.setattr(
            SettingsStore,
            "_save",
            lambda self, settings: (_ for _ in ()).throw(OSError("read-only fs")),
        )
        assert store.load().mode == MODE_RESTRICTED


class TestDefaults:
    """Default whitelist composition."""

    def test_extra_default_whitelist_merged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operator-provided extras form the default whitelist, normalized."""
        monkeypatch.setattr(
            settings_module,
            "EXTRA_DEFAULT_WHITELIST",
            {"gnosis": ("0x" + "CC" * 20,), "testchain": ("0x" + "dd" * 20,)},
        )
        whitelist = default_whitelist()
        assert "0x" + "cc" * 20 in whitelist["gnosis"]
        assert whitelist["testchain"] == ("0x" + "dd" * 20,)
        assert defaults().mode == MODE_RESTRICTED


def make_guard(
    store: SettingsStore, mode: str, whitelist: dict[str, tuple[str, ...]] | None = None
) -> Guard:
    """Save the given state and return a guard over it."""
    store.save(Settings(mode=mode, whitelist=whitelist or {}))
    config = AppConfig(
        chains={
            "testchain": ChainConfig(rpc_url="http://127.0.0.1:9", safe_address=SAFE),
            "nosafe": ChainConfig(rpc_url="http://127.0.0.1:9"),
        },
        store_path=Path("/nonexistent"),
    )
    return Guard(store, config)


class TestGuard:
    """The single gate's allow/deny matrix."""

    def test_unrestricted_passes_everything(self, store: SettingsStore) -> None:
        """Unrestricted mode is today's behavior."""
        guard = make_guard(store, MODE_UNRESTRICTED)
        guard.check_transaction("testchain", OTHER, 10**18, "0xdeadbeef")
        guard.check_sign_digest()
        assert guard.mode() == MODE_UNRESTRICTED

    def test_restricted_blocks_sign_digest(self, store: SettingsStore) -> None:
        """Raw digest signing is off in restricted mode."""
        guard = make_guard(store, MODE_RESTRICTED)
        with pytest.raises(GuardError, match="digest signing is disabled"):
            guard.check_sign_digest()

    def test_restricted_requires_safe_target(self, store: SettingsStore) -> None:
        """Everything must go to (or through) the service safe."""
        guard = make_guard(store, MODE_RESTRICTED)
        with pytest.raises(GuardError, match="only target the service safe"):
            guard.check_transaction("testchain", OTHER, 1, "0x")
        with pytest.raises(GuardError, match="no service safe"):
            guard.check_transaction("nosafe", SAFE, 1, "0x")

    def test_restricted_allows_native_sweep(self, store: SettingsStore) -> None:
        """A plain EOA -> safe transfer is always allowed."""
        guard = make_guard(store, MODE_RESTRICTED)
        guard.check_transaction("testchain", SAFE, 10**18, "0x")
        guard.check_transaction("testchain", SAFE.upper().replace("0X", "0x"), 0, "")

    def test_restricted_allows_whitelisted_call(self, store: SettingsStore) -> None:
        """Allow an execTransaction CALL to a whitelisted address."""
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(WHITELISTED, value=10**18, data=b"\x01")
        guard.check_transaction("testchain", SAFE, 0, calldata)

    @pytest.mark.parametrize(
        ("calldata", "message"),
        [
            (exec_transaction_calldata(OTHER), "not in the testchain whitelist"),
            (
                exec_transaction_calldata(WHITELISTED, operation=1),
                "only CALL operations",
            ),
            ("0xdeadbeef", "must be execTransaction"),
            ("0x" + EXEC_TRANSACTION_SELECTOR + "ff", "could not decode"),
        ],
    )
    def test_restricted_denials(
        self, store: SettingsStore, calldata: str, message: str
    ) -> None:
        """Delegatecall, unknown targets/selectors and garbage are denied."""
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        with pytest.raises(GuardError, match=message):
            guard.check_transaction("testchain", SAFE, 0, calldata)

    def test_restricted_denies_outer_value(self, store: SettingsStore) -> None:
        """Deny execTransaction with native value on the outer tx."""
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(WHITELISTED)
        with pytest.raises(GuardError, match="must not carry native value"):
            guard.check_transaction("testchain", SAFE, 1, calldata)

    @pytest.mark.parametrize(
        "refund_kwargs",
        [
            {"gas_price": 1},
            {"gas_token": OTHER},
            {"refund_receiver": OTHER},
        ],
    )
    def test_restricted_denies_gas_refund_fields(
        self, store: SettingsStore, refund_kwargs: dict
    ) -> None:
        """A non-zero refund field would pay out of the safe past the whitelist."""
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(WHITELISTED, **refund_kwargs)
        with pytest.raises(GuardError, match="refund fields must be zero"):
            guard.check_transaction("testchain", SAFE, 0, calldata)

    def test_restricted_accepts_uppercase_calldata(self, store: SettingsStore) -> None:
        """Hex case must not matter to the gate."""
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(WHITELISTED)
        guard.check_transaction(
            "testchain", SAFE, 0, "0x" + calldata.removeprefix("0x").upper()
        )


class TestSignerGuardIntegration:
    """The guard wired into the signing choke point."""

    @pytest.fixture(name="restricted_signer")
    def restricted_signer_fixture(  # pylint: disable=too-many-arguments
        self,
        account: LocalAccount,
        app_config: AppConfig,
        activity: ActivityLog,
        fake_w3: FakeW3,
        settings_store: SettingsStore,
    ) -> Signer:
        """Return a signer whose guard enforces restricted mode."""
        import threading

        from web3 import Web3

        from pearl_connect.signer import _ChainState

        settings_store.save(Settings(mode=MODE_RESTRICTED, whitelist={}))
        signer = Signer(
            account=account,
            config=app_config,
            activity=activity,
            guard=Guard(settings_store, app_config),
        )
        signer._chains._states["testchain"] = (  # pylint: disable=protected-access
            _ChainState(w3=t.cast(Web3, fake_w3), lock=threading.Lock(), chain_id=31337)
        )
        return signer

    def test_blocked_send_is_audited(
        self, restricted_signer: Signer, activity: ActivityLog, fake_w3: FakeW3
    ) -> None:
        """A denied send raises SignerError, records 'blocked', broadcasts nothing."""
        with pytest.raises(SignerError, match="restricted mode"):
            restricted_signer.send("testchain", OTHER, value=1)
        assert any(e["kind"] == "blocked" for e in activity.recent())
        assert not fake_w3.eth.sent

    def test_sweep_passes_the_gate(
        self, restricted_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """EOA -> safe sweep broadcasts even in restricted mode."""
        tx_hash = restricted_signer.send("testchain", SAFE, value=5)
        assert tx_hash.startswith("0x")
        assert fake_w3.eth.sent

    def test_blocked_sign_digest_is_audited(
        self, restricted_signer: Signer, activity: ActivityLog
    ) -> None:
        """A denied digest signing raises SignerError and records 'blocked'."""
        with pytest.raises(SignerError, match="digest signing is disabled"):
            restricted_signer.sign_digest(b"\x11" * 32)
        assert any(
            e["kind"] == "blocked" and e.get("action") == "sign_digest"
            for e in activity.recent()
        )

    def test_completed_request_id_replays_across_tightening(
        self,
        restricted_signer: Signer,
        settings_store: SettingsStore,
        fake_w3: FakeW3,
    ) -> None:
        """A completed send answers its request_id even after the mode flips.

        The transaction already happened; replaying its hash signs nothing
        new. A *fresh* request_id still hits the tightened gate.
        """
        settings_store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
        tx_hash = restricted_signer.send("testchain", OTHER, value=1, request_id="r1")
        settings_store.save(Settings(mode=MODE_RESTRICTED, whitelist={}))
        assert (
            restricted_signer.send("testchain", OTHER, value=1, request_id="r1")
            == tx_hash
        )
        assert len(fake_w3.eth.sent) == 1  # no second broadcast
        with pytest.raises(SignerError, match="restricted mode"):
            restricted_signer.send("testchain", OTHER, value=1, request_id="r2")


class TestSettingsEndpoints:
    """GET/POST /settings and the UI wiring."""

    @pytest.fixture(name="client")
    def client_fixture(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
        keystore_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> t.Iterator[TestClient]:
        """Client with the keystore reachable at cwd (as in production)."""
        monkeypatch.chdir(keystore_dir)
        with TestClient(
            make_app(test_signer, app_config, activity),
            base_url="http://127.0.0.1:8716",
        ) as client:
            yield client

    def test_get_settings_shape(self, client: TestClient) -> None:
        """GET /settings mirrors the enforced state."""
        body = client.get("/settings").json()
        assert body == {
            "mode": "unrestricted",
            "whitelist": {},
            "harness": "claude_code_desktop",
        }

    def test_wrong_password_is_throttled_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad passwords burn a second and reveal nothing."""
        from pearl_connect.server import settings_routes

        sleeps: list[float] = []
        monkeypatch.setattr(settings_routes.time, "sleep", sleeps.append)
        response = client.post(
            "/settings",
            json={
                "password": "nope",
                "mode": "restricted",
                "whitelist": {},
            },  # nosec B105
        )
        assert response.status_code == 401
        assert sleeps == [settings_routes.WRONG_PASSWORD_DELAY_SECONDS]

    def test_foreign_keystore_is_rejected(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        make_app: t.Callable,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A keystore for a different EOA does not authorize changes."""
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        keystore = Account.encrypt(Account.create().key, TEST_PASSWORD)
        (other_dir / "ethereum_private_key.txt").write_text(json.dumps(keystore))
        monkeypatch.chdir(other_dir)
        monkeypatch.setattr(
            "pearl_connect.server.settings_routes.time.sleep", lambda _: None
        )
        with TestClient(
            make_app(test_signer, app_config, activity),
            base_url="http://127.0.0.1:8716",
        ) as client:
            response = client.post(
                "/settings",
                json={"password": TEST_PASSWORD, "mode": "restricted", "whitelist": {}},
            )
        assert response.status_code == 401

    def test_valid_password_applies_live(
        self, client: TestClient, activity: ActivityLog
    ) -> None:
        """A mode flip takes effect on the very next signing request."""
        response = client.post(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "mode": "restricted",
                "whitelist": {"testchain": [WHITELISTED]},
            },
        )
        assert response.status_code == 200
        assert response.json()["mode"] == "restricted"
        assert response.json()["whitelist"] == {"testchain": [WHITELISTED.lower()]}
        assert any(e["kind"] == "settings_changed" for e in activity.recent())

        blocked = client.post(
            "/sign-and-send",
            json={"chain": "testchain", "to": OTHER, "value": 1},
            headers={"Authorization": "Bearer tok"},
        )
        assert blocked.status_code == 400
        assert "restricted mode" in blocked.json()["detail"]

    def test_harness_updates_and_validates(self, client: TestClient) -> None:
        """The harness is updatable from the UI endpoint and validated."""
        flipped = client.post(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "mode": "unrestricted",
                "whitelist": {},
                "harness": "claude_code_cli",
            },
        )
        assert flipped.status_code == 200
        assert flipped.json()["harness"] == "claude_code_cli"
        assert client.get("/settings").json()["harness"] == "claude_code_cli"
        # the UI's Open button now targets the CLI deep link
        page = client.get("/").text
        assert "claude-cli://open?cwd=" in page
        assert 'value="claude_code_cli"' in page

        bad = client.post(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "mode": "unrestricted",
                "whitelist": {},
                "harness": "cursor",
            },
        )
        assert bad.status_code == 400
        assert "harness" in bad.json()["detail"]

    def test_unconfigured_whitelist_chain_warns(
        self, client: TestClient, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A whitelist entry for an unconfigured chain saves, but loudly.

        Rejecting would break saving the defaults (they span chains this run
        may not have); silence would hide the typo until a call is blocked.
        """
        with caplog.at_level(logging.WARNING):
            response = client.post(
                "/settings",
                json={
                    "password": TEST_PASSWORD,
                    "mode": "restricted",
                    "whitelist": {"gnosiss": [WHITELISTED]},
                },
            )
        assert response.status_code == 200
        assert "gnosiss" in caplog.text

    def test_invalid_mode_and_address_are_400(self, client: TestClient) -> None:
        """Validation errors name the offending value."""
        bad_mode = client.post(
            "/settings",
            json={"password": TEST_PASSWORD, "mode": "yolo", "whitelist": {}},
        )
        assert bad_mode.status_code == 400
        bad_address = client.post(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "mode": "restricted",
                "whitelist": {"testchain": ["not-an-address"]},
            },
        )
        assert bad_address.status_code == 400
        assert "not-an-address" in bad_address.json()["detail"]

    def test_index_shows_mode_and_whitelist(
        self, client: TestClient, settings_store: SettingsStore
    ) -> None:
        """The agent UI renders the mode and the whitelist entries."""
        settings_store.save(
            Settings(mode=MODE_RESTRICTED, whitelist={"testchain": (WHITELISTED,)})
        )
        page = client.get("/").text
        assert "restricted" in page
        assert f"testchain:{WHITELISTED}" in page
        assert "Guardrail settings" in page


class TestMcpGuardrailTools:
    """New MCP tools: settings."""

    @pytest.fixture(name="tools")
    def tools_fixture(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        guard: Guard,
        settings_store: SettingsStore,
    ) -> dict[str, t.Callable]:
        """Return the registered tool functions keyed by name."""
        from pearl_connect.server.mcp_tools import build_mcp

        mcp = build_mcp(
            test_signer,
            app_config,
            activity,
            guard=guard,
            settings_store=settings_store,
        )
        manager = mcp._tool_manager  # pylint: disable=protected-access
        return {tool.name: tool.fn for tool in manager.list_tools()}

    def test_no_settings_write_tool_exists(self, tools: dict[str, t.Callable]) -> None:
        """The MCP surface must not be able to change the guardrail."""
        writers = [name for name in tools if "settings" in name and name != "settings"]
        assert not writers
        assert set(tools) >= {"settings", "wallet_info"}

    async def test_settings_reports_enforced_state(
        self, tools: dict[str, t.Callable], settings_store: SettingsStore
    ) -> None:
        """The tool reflects the post-verification settings."""
        assert await tools["settings"]() == {
            "mode": "unrestricted",
            "whitelist": {},
            "harness": "claude_code_desktop",
        }
        # tampering is not visible through the tool — only the enforced defaults
        settings_store._path.write_text("garbage")  # pylint: disable=protected-access
        assert (await tools["settings"]())["mode"] == "restricted"

    async def test_wallet_info_reports_mode(self, tools: dict[str, t.Callable]) -> None:
        """wallet_info carries the mode for quick agent orientation."""
        assert (await tools["wallet_info"]())["mode"] == "unrestricted"
