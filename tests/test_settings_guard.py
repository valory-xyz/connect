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

"""Tests for the tamper-evident settings store, the guardrail, and mech wiring."""

import asyncio
import json
import threading
import time
import typing as t
from pathlib import Path
from types import SimpleNamespace

import pytest
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from pearl_connect import settings as settings_module
from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig, ChainConfig
from pearl_connect.guard import EXEC_TRANSACTION_SELECTOR, Guard, GuardError
from pearl_connect.mech import (
    MAX_DELIVERY_TIMEOUT,
    MechError,
    MechService,
    MechSigner,
)
from pearl_connect.server.settings_routes import WHITELIST_FROZEN
from pearl_connect.settings import (
    MAC_FIELDS,
    MODE_RESTRICTED,
    MODE_UNRESTRICTED,
    Protected,
    Settings,
    SettingsStore,
    default_whitelist,
    defaults,
    derive_mac_key,
)
from pearl_connect.signer import Signer, SignerError

from tests.conftest import FakeW3, TEST_PASSWORD, audit_entries, audit_kinds

SAFE = "0x" + "22" * 20
WHITELISTED = "0x" + "aa" * 20
OTHER = "0x" + "bb" * 20

GNOSIS_MARKETPLACE = "0x735faab1c4ec41128c367afb5c3bac73509f70bb"


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
        assert loaded.protected.mode == MODE_RESTRICTED
        assert GNOSIS_MARKETPLACE in loaded.protected.whitelist["gnosis"]
        assert store._path.exists()  # pylint: disable=protected-access

    def test_roundtrip(self, store: SettingsStore) -> None:
        """Saved settings load back identically, immediately (no cache)."""
        store.save(
            Settings(
                protected=Protected(
                    mode=MODE_UNRESTRICTED, whitelist={"gnosis": (OTHER,)}
                ),
                harness="claude_code_cli",
            )
        )
        loaded = store.load()
        assert loaded.protected.mode == MODE_UNRESTRICTED
        assert loaded.protected.whitelist == {"gnosis": (OTHER,)}
        assert loaded.harness == "claude_code_cli"
        # a fresh store defaults to the desktop harness
        assert defaults().harness == "claude_code_desktop"

    def test_every_persisted_field_has_decided_its_mac_coverage(
        self, store: SettingsStore
    ) -> None:
        """A new top-level field must choose: inside the MAC, or outside it.

        The MAC covers an allowlist (MAC_FIELDS), so a field added to the
        canonical shape ships *unprotected* by default, silently. This test is
        the reminder: if it fails because you added a field, decide whether it
        belongs under "protected" (integrity-checked, password-gated) or is a
        preference like the harness (freely editable, survives a reset), then
        pin that choice here.
        """
        store.load()  # writes the defaults
        payload = json.loads(
            store._path.read_text()
        )  # pylint: disable=protected-access
        assert set(payload) == set(MAC_FIELDS) | {"harness", "mac"}

    def test_concurrent_patches_lose_no_update(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """One lock spans read-merge-write: parallel patches both persist.

        Without it, two patches reading the same snapshot would each write
        back only their own change — the second save silently undoing the
        first (e.g. a harness save erasing a just-applied mode restriction).
        """
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        original = Settings.merged

        def merged_slowly(self: Settings, patch: t.Mapping) -> Settings:
            time.sleep(0.05)  # widen the read-to-write window
            return original(self, patch)

        monkeypatch.setattr(Settings, "merged", merged_slowly)
        threads = [
            threading.Thread(
                target=store.patch, args=({"protected": {"mode": MODE_RESTRICTED}},)
            ),
            threading.Thread(
                target=store.patch, args=({"harness": "claude_code_cli"},)
            ),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        final = store.load()
        assert final.protected.mode == MODE_RESTRICTED
        assert final.harness == "claude_code_cli"

    def test_invalid_patch_persists_nothing(self, store: SettingsStore) -> None:
        """A patch that fails validation leaves the stored settings untouched."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        with pytest.raises(ValueError, match="mode must be"):
            store.patch({"protected": {"mode": "yolo"}})
        assert store.load().protected.mode == MODE_UNRESTRICTED

    def test_malformed_whitelist_addresses_are_rejected(
        self, store: SettingsStore
    ) -> None:
        """The store still validates addresses, though the API cannot send any.

        Whitelist writes are frozen at the HTTP surface, but defaults() and any
        future editing path come through here — the check must not rot away
        with the endpoint that used to exercise it.
        """
        with pytest.raises(ValueError, match="not-an-address"):
            store.patch({"protected": {"whitelist": {"testchain": ["not-an-address"]}}})

    def test_patch_with_explicit_nones_keeps_current_values(
        self, store: SettingsStore
    ) -> None:
        """None means "keep", at both levels — for every caller.

        The store owns this rule alone: the route hands the request body
        through as dumped, Nones and all, so HTTP callers and direct store
        callers cannot drift onto two different merge semantics.
        """
        store.save(
            Settings(
                protected=Protected(
                    mode=MODE_UNRESTRICTED, whitelist={"gnosis": (OTHER,)}
                ),
                harness="claude_code_cli",
            )
        )
        previous, updated = store.patch(
            {"protected": {"mode": None, "whitelist": None}, "harness": None}
        )
        assert updated.protected.mode == MODE_UNRESTRICTED
        assert updated.protected.whitelist == {"gnosis": (OTHER,)}
        assert updated.harness == "claude_code_cli"
        # nothing moved, and the caller can see that: it is what lets the
        # route audit only real changes
        assert previous == updated

    def test_patch_reports_what_moved(self, store: SettingsStore) -> None:
        """The patch result carries both sides, so a no-op is recognizable."""
        store.save(Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={})))
        previous, updated = store.patch({"protected": {"mode": MODE_UNRESTRICTED}})
        assert previous.protected.mode == MODE_RESTRICTED
        assert updated.protected.mode == MODE_UNRESTRICTED

    def test_an_unreadable_file_is_not_a_persist_failure(
        self,
        store_path: Path,
        store: SettingsStore,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A read that fails restricts; it is never reported as a failed write.

        Every guarded decision loads the settings, so an unreadable file must
        fail closed in memory rather than raise — and it must not masquerade
        as a persist failure to the operator, who would go looking at a write
        that was never attempted.
        """
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))

        def refuse(self: Path, **kwargs: object) -> str:
            raise PermissionError("locked")

        monkeypatch.setattr(Path, "read_text", refuse)
        assert store.load().protected.mode == MODE_RESTRICTED  # fails closed
        assert "settings_persist_failed" not in audit_kinds(store_path)

    def test_failed_write_leaves_no_temp_file(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed atomic replace cleans up its temp file and propagates."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))

        def refuse(self: Path, target: Path) -> None:
            raise OSError("disk full")

        monkeypatch.setattr(Path, "replace", refuse)
        with pytest.raises(OSError, match="disk full"):
            store.save(
                Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
            )
        tmp = store._path.with_suffix(".json.tmp")  # pylint: disable=protected-access
        assert not tmp.exists()
        # the previously persisted settings are intact
        assert store.load().protected.mode == MODE_UNRESTRICTED

    @pytest.mark.parametrize(
        "corrupt",
        [
            "not json at all",
            "[]",
            json.dumps({"version": 1, "mode": "unrestricted", "whitelist": {}}),
        ],
    )
    def test_tampered_content_restores_defaults(
        self,
        store_path: Path,
        store: SettingsStore,
        activity: ActivityLog,
        corrupt: str,
    ) -> None:
        """Unverifiable content is replaced with defaults and audited."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        store._path.write_text(corrupt)  # pylint: disable=protected-access
        loaded = store.load()
        assert loaded.protected.mode == MODE_RESTRICTED
        assert "settings_tampered" in audit_kinds(store_path)
        # the rewritten file verifies again
        assert store.load().protected.mode == MODE_RESTRICTED

    def test_edited_field_fails_mac(self, store: SettingsStore) -> None:
        """Flipping the mode in the JSON without the key fails verification."""
        store.save(Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={})))
        path = store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["protected"][
            "mode"
        ] = "unrestricted"  # the attack this file exists to stop
        path.write_text(json.dumps(payload))
        assert store.load().protected.mode == MODE_RESTRICTED

    def test_harness_edit_applies_without_the_key(self, store: SettingsStore) -> None:
        """The harness is a preference: a plain file edit simply takes effect."""
        store.save(Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={})))
        path = store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["harness"] = "claude_code_cli"
        path.write_text(json.dumps(payload))
        loaded = store.load()
        assert loaded.harness == "claude_code_cli"
        assert loaded.protected.mode == MODE_RESTRICTED  # protected fields untouched

    def test_invalid_harness_falls_back_without_tamper(
        self, store_path: Path, store: SettingsStore, activity: ActivityLog
    ) -> None:
        """A bad harness value is not an integrity event."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        path = store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["harness"] = "cursor"
        path.write_text(json.dumps(payload))
        loaded = store.load()
        assert loaded.harness == "claude_code_desktop"
        assert (
            loaded.protected.mode == MODE_UNRESTRICTED
        )  # protected fields still verify
        assert "settings_tampered" not in audit_kinds(store_path)

    def test_tampered_mode_preserves_the_harness_preference(
        self, store: SettingsStore
    ) -> None:
        """A guardrail reset must not discard the unprotected preference."""
        store.save(
            Settings(
                protected=Protected(mode=MODE_RESTRICTED, whitelist={}),
                harness="claude_code_cli",
            )
        )
        path = store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["protected"][
            "mode"
        ] = "unrestricted"  # the attack: protected field edited
        path.write_text(json.dumps(payload))
        loaded = store.load()
        assert loaded.protected.mode == MODE_RESTRICTED  # fails closed
        assert loaded.harness == "claude_code_cli"  # preference survives

    def test_valid_mac_but_bad_mode_rejected(self, store: SettingsStore) -> None:
        """A MAC'd payload with an unknown mode still falls back to defaults."""
        payload: dict = {"version": 1, "protected": {"mode": "yolo", "whitelist": {}}}
        payload["mac"] = store._mac(payload)  # pylint: disable=protected-access
        store._path.write_text(json.dumps(payload))  # pylint: disable=protected-access
        assert store.load().protected.mode == MODE_RESTRICTED

    def test_mac_key_requires_the_private_key(
        self, store: SettingsStore, activity: ActivityLog
    ) -> None:
        """A store keyed by a different account rejects the file."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        other = SettingsStore(
            store._path,  # pylint: disable=protected-access
            derive_mac_key(Account.create()),
            activity,
        )
        assert other.load().protected.mode == MODE_RESTRICTED

    def test_replayed_old_file_is_rejected(
        self, store_path: Path, store: SettingsStore, activity: ActivityLog
    ) -> None:
        """Putting back an old validly-MAC'd file fails like any other tamper."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        path = store._path  # pylint: disable=protected-access
        unrestricted_file = path.read_bytes()  # captured while unrestricted
        store.save(Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={})))
        path.write_bytes(unrestricted_file)  # the rollback attack
        assert store.load().protected.mode == MODE_RESTRICTED
        assert "settings_tampered" in audit_kinds(store_path)

    def test_fresh_process_accepts_any_valid_mac(
        self, store: SettingsStore, account: LocalAccount, activity: ActivityLog
    ) -> None:
        """A new store instance (a restart) pins the first valid file it sees."""
        store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
        restarted = SettingsStore(
            store._path,  # pylint: disable=protected-access
            derive_mac_key(account),
            activity,
        )
        assert restarted.load().protected.mode == MODE_UNRESTRICTED

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
        assert store.load().protected.mode == MODE_RESTRICTED


class TestDefaults:
    """Default whitelist composition."""

    def test_only_the_marketplace_ships_whitelisted(self) -> None:
        """The default whitelist is exactly the marketplace contract per chain.

        Trackers (deposits: an off-chain/unrestricted concern) and payment
        tokens (address-level whitelisting would permit arbitrary transfers)
        must NOT be whitelisted by default.
        """
        whitelist = default_whitelist()
        assert whitelist["gnosis"] == (GNOSIS_MARKETPLACE,)
        # native balance tracker on gnosis stays out
        assert "0x21ce6799a22a3da84b7c44a814a9c79ab1d2a50d" not in whitelist["gnosis"]
        # OLAS token on gnosis stays out
        assert "0xce11e14225575945b8e6dc0d4f2dd4c570f79d9f" not in whitelist["gnosis"]
        assert set(whitelist) >= {"gnosis", "base", "polygon", "optimism"}
        assert all(len(addresses) == 1 for addresses in whitelist.values())

    def test_extra_default_whitelist_merged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Operator-provided extras land next to the mech addresses."""
        monkeypatch.setattr(
            settings_module,
            "EXTRA_DEFAULT_WHITELIST",
            {"gnosis": ("0x" + "CC" * 20,), "testchain": ("0x" + "dd" * 20,)},
        )
        whitelist = default_whitelist()
        assert "0x" + "cc" * 20 in whitelist["gnosis"]
        assert whitelist["testchain"] == ("0x" + "dd" * 20,)
        assert defaults().protected.mode == MODE_RESTRICTED

    def test_broken_mech_client_degrades_to_empty_whitelist(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing mechs.json must not take every guarded decision down."""
        monkeypatch.setattr(
            "mech_client.infrastructure.config.constants.MECH_CONFIGS",
            "/nonexistent/mechs.json",
        )
        assert default_whitelist() == {}
        assert defaults().protected.mode == MODE_RESTRICTED


def make_guard(
    store: SettingsStore, mode: str, whitelist: dict[str, tuple[str, ...]] | None = None
) -> Guard:
    """Save the given state and return a guard over it."""
    store.save(Settings(protected=Protected(mode=mode, whitelist=whitelist or {})))
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

        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
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
        self,
        store_path: Path,
        restricted_signer: Signer,
        activity: ActivityLog,
        fake_w3: FakeW3,
    ) -> None:
        """A denied send raises SignerError, records 'blocked', broadcasts nothing."""
        with pytest.raises(SignerError, match="restricted mode"):
            restricted_signer.send("testchain", OTHER, value=1)
        assert "blocked" in audit_kinds(store_path)
        assert not fake_w3.eth.sent

    def test_sweep_passes_the_gate(
        self, restricted_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """EOA -> safe sweep broadcasts even in restricted mode."""
        tx_hash = restricted_signer.send("testchain", SAFE, value=5)
        assert tx_hash.startswith("0x")
        assert fake_w3.eth.sent

    def test_blocked_sign_digest_is_audited(
        self, store_path: Path, restricted_signer: Signer, activity: ActivityLog
    ) -> None:
        """A denied digest signing raises SignerError and records 'blocked'."""
        with pytest.raises(SignerError, match="digest signing is disabled"):
            restricted_signer.sign_digest(b"\x11" * 32)
        assert any(
            e["kind"] == "blocked" and e.get("action") == "sign_digest"
            for e in audit_entries(store_path)
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
        settings_store.save(
            Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}))
        )
        tx_hash = restricted_signer.send("testchain", OTHER, value=1, request_id="r1")
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        assert (
            restricted_signer.send("testchain", OTHER, value=1, request_id="r1")
            == tx_hash
        )
        assert len(fake_w3.eth.sent) == 1  # no second broadcast
        with pytest.raises(SignerError, match="restricted mode"):
            restricted_signer.send("testchain", OTHER, value=1, request_id="r2")


class FakeMarketplaceService:
    """Captures send_request kwargs and serves canned mech info."""

    def __init__(self) -> None:
        """Initialize."""
        self.calls: list[dict] = []
        self.result: dict = {"tx_hash": "0x" + "11" * 32, "request_ids": ["ab"]}
        self.raises: Exception | None = None
        self.mech_info = (SimpleNamespace(name="NATIVE"), 42, 10**16)
        self.tool_manager = SimpleNamespace(
            get_tools=lambda service_id: SimpleNamespace(
                tools=[SimpleNamespace(tool_name="prediction-online")]
            )
        )

    def _fetch_mech_info(self, mech: str) -> tuple:
        """Return the canned (payment_type, service_id, max_delivery_rate)."""
        return self.mech_info

    async def send_request(self, **kwargs: object) -> dict:
        """Record the call and return the canned result."""
        self.calls.append(kwargs)
        if self.raises is not None:
            raise self.raises
        return self.result


class TestMech:
    """MechSigner adapter and MechService orchestration."""

    def test_mech_signer_maps_transaction_fields(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Bytes data, missing value/gas and address pass through correctly."""
        mech_signer = MechSigner(test_signer, "testchain")
        assert mech_signer.address == test_signer.address
        tx_hash = mech_signer.send_transaction(
            {"to": OTHER, "data": b"\x01\x02", "value": None}
        )
        assert tx_hash.startswith("0x")
        assert fake_w3.eth.sent

    def test_mech_signer_signs_digests(self, test_signer: Signer) -> None:
        """sign_message returns the raw 65-byte signature."""
        signature = MechSigner(test_signer, "testchain").sign_message(b"\x22" * 32)
        assert len(signature) == 65

    @pytest.fixture(name="patched_mech")
    def patched_mech_fixture(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> FakeMarketplaceService:
        """Route MechService._service construction to the fake."""
        import mech_client.services.marketplace_service as ms
        import safe_eth.eth as se

        fake = FakeMarketplaceService()
        monkeypatch.setattr(ms, "MarketplaceService", lambda **kwargs: fake)
        monkeypatch.setattr(se, "EthereumClient", lambda uri: object())
        return fake

    def test_request_maps_arguments(
        self,
        store_path: Path,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        activity: ActivityLog,
    ) -> None:
        """legacy_on_chain inverts use_offchain; prompts/tools become tuples."""
        result = mech_service.request(
            "what is the answer",
            "prediction",
            chain="testchain",
            legacy_on_chain=True,
            priority_mech=OTHER,
            auto_deposit=False,
            timeout=42,
        )
        assert result == patched_mech.result
        call = patched_mech.calls[0]
        assert call["prompts"] == ("what is the answer",)
        assert call["tools"] == ("prediction",)
        assert call["use_offchain"] is False
        assert call["priority_mech"] == OTHER
        assert call["auto_deposit"] is False
        assert call["timeout"] == 42
        assert "mech_request" in audit_kinds(store_path)
        # the service is cached per chain
        mech_service.request(
            "again",
            "prediction",
            chain="testchain",
            legacy_on_chain=True,
            priority_mech=OTHER,
        )
        assert len(patched_mech.calls) == 2

    def test_request_offchain_denied_in_restricted(
        self,
        mech_service: MechService,
        settings_store: SettingsStore,
        patched_mech: FakeMarketplaceService,
    ) -> None:
        """The off-chain preflight names the escape hatch."""
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        with pytest.raises(MechError, match="legacy_on_chain=true"):
            mech_service.request("q", "tool", chain="testchain")
        assert not patched_mech.calls

    def test_request_wraps_mech_client_errors(
        self,
        store_path: Path,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        activity: ActivityLog,
    ) -> None:
        """mech-client exceptions surface as structured MechError + audit entry."""
        patched_mech.raises = RuntimeError("subgraph down")
        with pytest.raises(MechError, match="subgraph down"):
            mech_service.request(
                "q",
                "tool",
                chain="testchain",
                legacy_on_chain=True,
                priority_mech=OTHER,
            )
        assert "mech_request_failed" in audit_kinds(store_path)

    def test_request_passes_signer_errors_through(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
    ) -> None:
        """Guard denials inside the flow keep their message."""
        patched_mech.raises = SignerError("restricted mode: nope")
        with pytest.raises(SignerError, match="restricted mode"):
            mech_service.request(
                "q",
                "tool",
                chain="testchain",
                legacy_on_chain=True,
                priority_mech=OTHER,
            )

    def test_tools_lists_mechs(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The listing maps subgraph entries and appends the follow-up note."""
        import mech_client.infrastructure.subgraph.queries as queries

        monkeypatch.setattr(
            queries,
            "query_mm_mechs_info",
            lambda chain: [
                {
                    "address": OTHER,
                    "service": {"id": "42"},
                    "totalDeliveriesTransactions": "7",
                    "mech_type": "Fixed price",
                }
            ],
        )
        listing = mech_service.tools(chain="testchain")
        assert listing["mechs"] == [
            {
                "address": OTHER,
                "service_id": "42",
                "total_deliveries": 7,
                "mech_type": "Fixed price",
            }
        ]
        assert listing["total"] == 1
        assert listing["offset"] == 0
        assert "priority_mech" in listing["note"]

    def test_tools_listing_paginates(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """limit/offset slice the listing; out-of-range values are clamped."""
        import mech_client.infrastructure.subgraph.queries as queries

        entries = [
            {
                "address": f"0x{i:040x}",
                "service": {"id": str(i)},
                "totalDeliveriesTransactions": str(100 - i),
                "mech_type": "Fixed price",
            }
            for i in range(5)
        ]
        monkeypatch.setattr(queries, "query_mm_mechs_info", lambda chain: entries)

        page = mech_service.tools(chain="testchain", limit=2, offset=2)
        assert [m["service_id"] for m in page["mechs"]] == ["2", "3"]
        assert page["total"] == 5
        assert (page["offset"], page["limit"]) == (2, 2)

        # past the end -> empty page, total still tells the caller to stop
        assert mech_service.tools(chain="testchain", offset=99)["mechs"] == []
        # nonsense values are clamped instead of erroring
        clamped = mech_service.tools(chain="testchain", limit=-3, offset=-1)
        assert (clamped["offset"], clamped["limit"]) == (0, 1)
        assert len(clamped["mechs"]) == 1

    def test_tools_listing_failure_wraps(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A subgraph failure surfaces as a structured MechError."""
        import mech_client.infrastructure.subgraph.queries as queries

        monkeypatch.setattr(
            queries,
            "query_mm_mechs_info",
            lambda chain: (_ for _ in ()).throw(RuntimeError("subgraph down")),
        )
        with pytest.raises(MechError, match="subgraph down"):
            mech_service.tools(chain="testchain")

    def test_tools_for_one_mech(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """With priority_mech, payment info and tool names are returned."""
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert info["mech"] == OTHER
        assert info["payment_type"] == "NATIVE"
        assert info["service_id"] == 42
        assert info["tools"] == ["prediction-online"]

    def test_tools_degrade_without_metadata(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A slow/absent IPFS gateway yields a note, not an error."""
        patched_mech.tool_manager = SimpleNamespace(
            get_tools=lambda service_id: (_ for _ in ()).throw(TimeoutError("slow"))
        )
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "tools" not in info
        assert "unavailable" in info["tools_note"]

    def test_service_requires_safe_and_known_chain(
        self, mech_service: MechService
    ) -> None:
        """Chains without a safe (or unknown) are rejected before any network IO."""
        # pylint: disable=protected-access
        mech_service._config.chains["testchain"].safe_address = None
        with pytest.raises(MechError, match="no service safe"):
            mech_service._service("testchain")
        with pytest.raises(ValueError, match="unknown chain"):
            mech_service._service("atlantis")

    def test_tools_listing_needs_no_safe(
        self, mech_service: MechService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovery is a pure subgraph query — no safe, no service build."""
        import mech_client.infrastructure.subgraph.queries as queries

        monkeypatch.setattr(queries, "query_mm_mechs_info", lambda chain: [])
        # pylint: disable=protected-access
        mech_service._config.chains["testchain"].safe_address = None
        assert mech_service.tools(chain="testchain")["mechs"] == []
        assert not mech_service._services  # nothing was constructed
        with pytest.raises(ValueError, match="unknown chain"):
            mech_service.tools(chain="atlantis")

    def test_request_rejects_overpriced_mech(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A mech pricing above max_payment is refused before any work."""
        patched_mech.mech_info = (SimpleNamespace(name="NATIVE"), 42, 10**18)
        with pytest.raises(MechError, match="max_payment"):
            mech_service.request(
                "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
            )
        assert not patched_mech.calls
        # an explicitly raised cap accepts the same price
        mech_service.request(
            "q",
            "t",
            chain="testchain",
            legacy_on_chain=True,
            priority_mech=OTHER,
            max_payment=10**19,
        )
        assert len(patched_mech.calls) == 1

    def test_request_wraps_pricing_failures(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A failing price lookup surfaces as MechError, not a raw exception."""
        monkeypatch.setattr(
            patched_mech,
            "_fetch_mech_info",
            lambda mech: (_ for _ in ()).throw(RuntimeError("rpc down")),
        )
        with pytest.raises(MechError, match="could not price"):
            mech_service.request(
                "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
            )
        assert not patched_mech.calls

    def test_request_resolves_mech_when_unspecified(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without priority_mech the top listed mech is priced and used."""
        import mech_client.infrastructure.subgraph.queries as queries

        monkeypatch.setattr(
            queries,
            "query_mm_mechs_info",
            lambda chain: [
                {
                    "address": OTHER,
                    "service": {"id": "42"},
                    "totalDeliveriesTransactions": "7",
                    "mech_type": "Fixed price",
                }
            ],
        )
        mech_service.request("q", "t", chain="testchain", legacy_on_chain=True)
        assert patched_mech.calls[0]["priority_mech"] == OTHER
        # an empty listing is a structured error, not an opaque one
        monkeypatch.setattr(queries, "query_mm_mechs_info", lambda chain: [])
        with pytest.raises(MechError, match="no live mechs"):
            mech_service.request("q", "t", chain="testchain", legacy_on_chain=True)

    def test_tools_listing_wraps_malformed_entries(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A subgraph entry missing fields surfaces as MechError, not KeyError."""
        import mech_client.infrastructure.subgraph.queries as queries

        monkeypatch.setattr(
            queries, "query_mm_mechs_info", lambda chain: [{"address": OTHER}]
        )
        with pytest.raises(MechError, match="could not list mechs"):
            mech_service.tools(chain="testchain")

    def test_request_timeout_is_clamped(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A huge or non-positive timeout cannot pin the worker thread."""
        mech_service.request(
            "q",
            "t",
            chain="testchain",
            legacy_on_chain=True,
            timeout=10**9,
            priority_mech=OTHER,
        )
        assert patched_mech.calls[-1]["timeout"] == MAX_DELIVERY_TIMEOUT
        mech_service.request(
            "q",
            "t",
            chain="testchain",
            legacy_on_chain=True,
            timeout=-5,
            priority_mech=OTHER,
        )
        assert patched_mech.calls[-1]["timeout"] == 1.0


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
            "protected": {"mode": "unrestricted", "whitelist": {}},
            "harness": "claude_code_desktop",
        }

    def test_wrong_password_is_throttled_401(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Bad passwords burn a second and reveal nothing."""
        from pearl_connect.server import settings_routes

        sleeps: list[float] = []
        monkeypatch.setattr(settings_routes.time, "sleep", sleeps.append)
        response = client.patch(
            "/settings",
            json={
                "password": "nope",
                "protected": {"mode": "restricted"},
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
            response = client.patch(
                "/settings",
                json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
            )
        assert response.status_code == 401

    def test_valid_password_applies_live(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """A mode flip takes effect on the very next signing request."""
        response = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
        )
        assert response.status_code == 200
        assert response.json()["protected"]["mode"] == "restricted"
        assert "settings_changed" in audit_kinds(store_path)

        blocked = client.post(
            "/sign-and-send",
            json={"chain": "testchain", "to": OTHER, "value": 1},
            headers={"Authorization": "Bearer tok"},
        )
        assert blocked.status_code == 400
        assert "restricted mode" in blocked.json()["detail"]

    def test_harness_updates_and_validates(self, client: TestClient) -> None:
        """The harness is updatable from the UI endpoint and validated."""
        flipped = client.patch("/settings", json={"harness": "claude_code_cli"})
        assert flipped.status_code == 200
        assert flipped.json()["harness"] == "claude_code_cli"
        assert client.get("/settings").json()["harness"] == "claude_code_cli"
        # the UI's Open button now targets the CLI deep link
        page = client.get("/").text
        assert "claude-cli://open?cwd=" in page
        assert 'value="claude_code_cli"' in page

        bad = client.patch("/settings", json={"harness": "cursor"})
        assert bad.status_code == 400
        assert "harness" in bad.json()["detail"]

    def test_whitelist_editing_is_refused(self, client: TestClient) -> None:
        """The whitelist is frozen at the API: an attempt is loud, not ignored.

        A patch replaces the whitelist wholesale across all chains, and only
        the address format can be checked here — so until those semantics are
        specced, writing one is a 422 naming the reason. Silently dropping the
        field would let a caller believe an edit landed.
        """
        store = client.app.state.settings_store  # type: ignore[attr-defined]
        store.patch({"protected": {"whitelist": {"testchain": [WHITELISTED]}}})

        for whitelist in ({"testchain": [OTHER]}, {}):  # replacing and clearing
            refused = client.patch(
                "/settings",
                json={
                    "password": TEST_PASSWORD,
                    "protected": {"whitelist": whitelist},
                },
            )
            assert refused.status_code == 422
            assert WHITELIST_FROZEN in refused.text

        # an explicit null is not an edit — it is the merge-patch "keep"
        kept = client.patch(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "protected": {"mode": "restricted", "whitelist": None},
            },
        )
        assert kept.status_code == 200

        # the stored whitelist is untouched throughout
        assert client.get("/settings").json()["protected"]["whitelist"] == {
            "testchain": [WHITELISTED.lower()]
        }

    def test_harness_patch_needs_no_password(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """The harness is a preference: changing it never asks for the password."""
        response = client.patch("/settings", json={"harness": "claude_code_cli"})
        assert response.status_code == 200
        assert response.json()["harness"] == "claude_code_cli"
        loaded = client.get("/settings").json()
        assert loaded["harness"] == "claude_code_cli"
        # protected fields untouched
        assert loaded["protected"]["mode"] == "unrestricted"
        assert "harness_changed" in audit_kinds(store_path)
        # still validated: unknown harnesses are rejected
        bad = client.patch("/settings", json={"harness": "cursor"})
        assert bad.status_code == 400

    def test_protected_patch_requires_the_password(self, client: TestClient) -> None:
        """Touching the protected object without a password is a clean 401."""
        response = client.patch("/settings", json={"protected": {"mode": "restricted"}})
        assert response.status_code == 401
        assert "password" in response.json()["detail"]
        # nothing changed, and the missing password did not feed the brake
        assert client.get("/settings").json()["protected"]["mode"] == "unrestricted"

    def test_missing_password_is_audited_but_never_brakes(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """Password-less probes are visible in the log but cost no brake count.

        No guess was made, so feeding the brake would let any local process
        429-lock every authenticated surface with free requests.
        """
        from pearl_connect.server import auth as auth_module

        for _ in range(auth_module.MAX_AUTH_FAILURES * 2):
            response = client.patch(
                "/settings", json={"protected": {"mode": "restricted"}}
            )
            assert response.status_code == 401  # never 429
        reasons = [
            e["reason"] for e in audit_entries(store_path) if e["kind"] == "auth_failed"
        ]
        assert "missing password" in reasons
        # the real password still works immediately
        flipped = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
        )
        assert flipped.status_code == 200

    def test_empty_patch_is_rejected(self, client: TestClient) -> None:
        """A patch with nothing to update is an explicit 400, not a silent 200."""
        assert client.patch("/settings", json={}).status_code == 400

    def test_partial_protected_patch_keeps_other_fields(
        self, client: TestClient
    ) -> None:
        """Merge-patch semantics: omitted fields keep their current values."""
        store = client.app.state.settings_store  # type: ignore[attr-defined]
        store.patch({"protected": {"whitelist": {"testchain": [WHITELISTED]}}})
        client.patch("/settings", json={"harness": "claude_code_cli"})
        # mode-only patch: the whitelist and the harness survive it
        response = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["protected"]["mode"] == "restricted"
        assert body["protected"]["whitelist"] == {"testchain": [WHITELISTED.lower()]}
        assert body["harness"] == "claude_code_cli"  # preference not reset

    def test_a_patch_that_changes_nothing_is_audited_as_nothing(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """Restating the stored values records no change — it made none.

        An audit trail that reports guardrail changes which never happened is
        worse than one that stays quiet: it is the record an operator reaches
        for when something has gone wrong.
        """
        assert client.get("/settings").json()["harness"] == "claude_code_desktop"
        noop = client.patch(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "protected": {},  # every field None: merges nothing
                "harness": "claude_code_desktop",  # already the stored value
            },
        )
        assert noop.status_code == 200
        kinds = audit_kinds(store_path)
        assert "settings_changed" not in kinds
        assert "harness_changed" not in kinds

        # a real change still lands
        client.patch("/settings", json={"harness": "claude_code_cli"})
        assert "harness_changed" in audit_kinds(store_path)

    def test_host_header_is_validated(self, client: TestClient) -> None:
        """A rebound (non-loopback) Host header is refused app-wide."""
        response = client.get("/healthcheck", headers={"host": "evil.example:8716"})
        assert response.status_code == 400

    def test_settings_routes_reject_cross_origin(self, client: TestClient) -> None:
        """All settings routes refuse browser cross-origin requests."""
        headers = {"Origin": "https://evil.example"}
        assert client.get("/settings", headers=headers).status_code == 403
        response = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
            headers=headers,
        )
        assert response.status_code == 403
        harness = client.patch(
            "/settings", json={"harness": "claude_code_cli"}, headers=headers
        )
        assert harness.status_code == 403

    def test_auth_failures_are_audited_and_braked(
        self,
        store_path: Path,
        client: TestClient,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Probing is recorded and, past the threshold, answered with 429."""
        from pearl_connect.server import auth as auth_module
        from pearl_connect.server import settings_routes

        monkeypatch.setattr(settings_routes.time, "sleep", lambda _: None)

        # a failed token and a failed password both land in the audit log
        assert client.get("/wallet").status_code == 401
        client.patch(
            "/settings",
            json={
                "password": "wrong",
                "protected": {"mode": "restricted"},
            },  # nosec B105
        )
        reasons = [
            e["reason"] for e in audit_entries(store_path) if e["kind"] == "auth_failed"
        ]
        assert "bad token" in reasons
        assert "bad password" in reasons

        # cross the threshold: every authenticated surface goes 429
        for _ in range(auth_module.MAX_AUTH_FAILURES):
            client.get("/wallet")
        assert client.get("/wallet").status_code == 429
        assert (
            client.get("/wallet", headers={"Authorization": "Bearer tok"}).status_code
            == 429
        )
        assert (
            client.patch(
                "/settings",
                json={
                    "password": TEST_PASSWORD,
                    "protected": {"mode": "restricted"},
                },
            ).status_code
            == 429
        )
        assert client.post("/mcp/", json={}).status_code == 429

        # the brake releases once the window drains
        real_monotonic = auth_module.time.monotonic
        monkeypatch.setattr(
            auth_module.time,
            "monotonic",
            lambda: real_monotonic() + auth_module.AUTH_FAILURE_WINDOW_SECONDS + 1,
        )
        assert client.get("/healthcheck").status_code == 200
        assert (
            client.get("/wallet", headers={"Authorization": "Bearer tok"}).status_code
            == 200
        )

    def test_cross_origin_failures_do_not_engage_the_brake(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """Origin failures need no secret; they must never lock the agent out.

        A webpage's simple requests arrive with a foreign Origin at will — if
        they fed the limiter, a background tab could hold every authenticated
        surface at 429 indefinitely (including the settings UI).
        """
        from pearl_connect.server import auth as auth_module

        headers = {"Origin": "https://evil.example"}
        for _ in range(auth_module.MAX_AUTH_FAILURES * 2):
            assert client.get("/wallet", headers=headers).status_code == 403
            assert client.post("/mcp/", json={}, headers=headers).status_code == 403
        # loud in the audit log...
        reasons = [
            e["reason"] for e in audit_entries(store_path) if e["kind"] == "auth_failed"
        ]
        assert "cross-origin" in reasons
        # ...but the brake never engages: legitimate access keeps working
        assert (
            client.get("/wallet", headers={"Authorization": "Bearer tok"}).status_code
            == 200
        )

    def test_invalid_mode_is_400(self, client: TestClient) -> None:
        """Validation errors name the offending value."""
        bad_mode = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "yolo"}},
        )
        assert bad_mode.status_code == 400
        assert "yolo" in bad_mode.json()["detail"] or "mode must be" in (
            bad_mode.json()["detail"]
        )

    def test_a_blank_password_never_brakes(
        self,
        store_path: Path,
        client: TestClient,
        activity: ActivityLog,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An empty password is no guess: it costs no decrypt, delay or brake.

        The UI's form always sends the field, so a blank submit arrives as ""
        rather than as an omission. Treating that as a wrong guess would let a
        handful of stray clicks (or any local process, for free) trip the
        global limiter and 429-lock every authenticated surface.
        """
        from pearl_connect.server import auth as auth_module
        from pearl_connect.server import settings_routes

        slept: list[float] = []
        monkeypatch.setattr(settings_routes.time, "sleep", slept.append)

        blank = {"password": "", "protected": {"mode": "restricted"}}  # nosec B105
        for _ in range(auth_module.MAX_AUTH_FAILURES * 2):
            response = client.patch("/settings", json=blank)
            assert response.status_code == 401  # never 429
        assert slept == []  # no throttle burned either
        reasons = [
            e["reason"] for e in audit_entries(store_path) if e["kind"] == "auth_failed"
        ]
        assert "missing password" in reasons
        assert "bad password" not in reasons

        # and the real password still works immediately
        flipped = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
        )
        assert flipped.status_code == 200

    def test_the_patch_models_cover_the_whole_settings_shape(self) -> None:
        """The API's shape tracks the persisted one, field for field.

        The patch models mirror the dataclasses by hand, so a field added to
        Settings/Protected would be enforced and MAC'd but unsettable over the
        API — a 422 the operator cannot explain. If this fails, add the field
        to the matching patch model (or freeze it deliberately, as the
        whitelist is).
        """
        from dataclasses import fields

        from pearl_connect.server.settings_routes import ProtectedPatch, SettingsPatch

        assert set(SettingsPatch.model_fields) - {"password"} == {
            f.name for f in fields(Settings)
        }
        assert set(ProtectedPatch.model_fields) == {f.name for f in fields(Protected)}

    def test_failed_patch_changes_nothing(self, client: TestClient) -> None:
        """A patch is atomic: an invalid protected half also drops the harness half."""
        before = client.get("/settings").json()
        assert before["harness"] != "claude_code_cli"
        response = client.patch(
            "/settings",
            json={
                "password": TEST_PASSWORD,
                "protected": {"mode": "yolo"},
                "harness": "claude_code_cli",
            },
        )
        assert response.status_code == 400
        assert client.get("/settings").json() == before

    def test_unknown_patch_fields_are_rejected(self, client: TestClient) -> None:
        """A typo'd field name is a 422, not a silently-dropped no-op."""
        typoed_protected = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mdoe": "restricted"}},
        )
        assert typoed_protected.status_code == 422
        typoed_top_level = client.patch("/settings", json={"harnes": "cursor"})
        assert typoed_top_level.status_code == 422

    def test_patch_over_tampered_file_merges_onto_defaults(
        self,
        store_path: Path,
        client: TestClient,
        settings_store: SettingsStore,
        activity: ActivityLog,
    ) -> None:
        """A patch lands on the post-reset defaults, never the forged payload.

        An unauthenticated harness-only patch must not launder a hand-edited
        mode back to disk under a fresh valid MAC.
        """
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        path = settings_store._path  # pylint: disable=protected-access
        payload = json.loads(path.read_text())
        payload["protected"]["mode"] = "unrestricted"  # forged without the key
        path.write_text(json.dumps(payload))
        response = client.patch("/settings", json={"harness": "claude_code_cli"})
        assert response.status_code == 200
        body = response.json()
        assert body["protected"]["mode"] == "restricted"  # reset, not merged
        assert body["harness"] == "claude_code_cli"
        assert "settings_tampered" in audit_kinds(store_path)

    def test_unpersistable_patch_is_a_clear_error(
        self, store_path: Path, client: TestClient, activity: ActivityLog
    ) -> None:
        """A disk-refused write is an audited 503, not an opaque 500."""
        # a scoped context, NOT the shared monkeypatch fixture: undoing that
        # one would also undo the client fixture's chdir to the keystore
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                SettingsStore,
                "_save",
                lambda self, settings: (_ for _ in ()).throw(OSError("disk full")),
            )
            response = client.patch("/settings", json={"harness": "claude_code_cli"})
        assert response.status_code == 503
        assert "persisted" in response.json()["detail"]
        assert "settings_persist_failed" in audit_kinds(store_path)
        # nothing changed on disk
        assert client.get("/settings").json()["harness"] == "claude_code_desktop"

    def test_index_shows_mode_and_whitelist(
        self, client: TestClient, settings_store: SettingsStore
    ) -> None:
        """The agent UI renders the mode and the whitelist entries."""
        settings_store.save(
            Settings(
                protected=Protected(
                    mode=MODE_RESTRICTED, whitelist={"testchain": (WHITELISTED,)}
                )
            )
        )
        page = client.get("/").text
        assert "restricted" in page
        assert f"testchain:{WHITELISTED}" in page
        assert "Guardrail settings" in page


class TestMcpGuardrailTools:
    """New MCP tools: mech_request and settings."""

    @pytest.fixture(name="tools")
    def tools_fixture(  # pylint: disable=too-many-arguments
        self,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        guard: Guard,
        mech_service: MechService,
        settings_store: SettingsStore,
    ) -> dict[str, t.Callable]:
        """Return the registered tool functions keyed by name."""
        from pearl_connect.server.mcp_tools import build_mcp

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

    def test_no_settings_write_tool_exists(self, tools: dict[str, t.Callable]) -> None:
        """The MCP surface must not be able to change the guardrail."""
        writers = [name for name in tools if "settings" in name and name != "settings"]
        assert not writers
        assert set(tools) >= {"settings", "mech_request", "wallet_info"}

    async def test_settings_reports_enforced_state(
        self, tools: dict[str, t.Callable], settings_store: SettingsStore
    ) -> None:
        """The tool reflects the post-verification settings."""
        assert await tools["settings"]() == {
            "protected": {"mode": "unrestricted", "whitelist": {}},
            "harness": "claude_code_desktop",
        }
        # tampering is not visible through the tool — only the enforced defaults
        settings_store._path.write_text("garbage")  # pylint: disable=protected-access
        assert (await tools["settings"]())["protected"]["mode"] == "restricted"

    async def test_wallet_info_reports_mode(self, tools: dict[str, t.Callable]) -> None:
        """wallet_info carries the mode for quick agent orientation."""
        assert (await tools["wallet_info"]())["mode"] == "unrestricted"

    async def test_mech_tools_tool_delegates(
        self,
        tools: dict[str, t.Callable],
        mech_service: MechService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The discovery tool passes its arguments through, off the event loop."""
        calls: list[dict] = []

        def fake_tools(**kwargs: object) -> dict:
            with pytest.raises(RuntimeError):
                asyncio.get_running_loop()  # must run in a worker thread
            calls.append(dict(kwargs))
            return {"mechs": []}

        monkeypatch.setattr(mech_service, "tools", fake_tools)
        assert await tools["mech_tools"](
            "testchain", priority_mech=OTHER, limit=5, offset=10
        ) == {"mechs": []}
        assert calls == [
            {"chain": "testchain", "priority_mech": OTHER, "limit": 5, "offset": 10}
        ]

    async def test_mech_request_tool_delegates(
        self,
        tools: dict[str, t.Callable],
        mech_service: MechService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The tool passes its arguments through to MechService.request."""
        calls: list[dict] = []

        def fake_request(prompt: str, tool: str, **kwargs: object) -> dict:
            calls.append({"prompt": prompt, "tool": tool, **kwargs})
            return {"ok": True}

        monkeypatch.setattr(mech_service, "request", fake_request)
        result = await tools["mech_request"](
            "p", "t", chain="testchain", legacy_on_chain=True, timeout=7
        )
        assert result == {"ok": True}
        assert calls[0]["legacy_on_chain"] is True
        assert calls[0]["chain"] == "testchain"
        assert calls[0]["timeout"] == 7

    async def test_mech_request_tool_runs_off_the_event_loop(
        self, tools: dict[str, t.Callable], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MechService.request calls asyncio.run, which raises on a running loop.

        The MCP SDK executes tools on the server's event loop, so the tool must
        push the whole mech flow to a worker thread. Awaiting the tool under
        pytest's loop reproduces the server condition end to end.
        """
        import mech_client.services.marketplace_service as ms
        import safe_eth.eth as se

        fake = FakeMarketplaceService()
        monkeypatch.setattr(ms, "MarketplaceService", lambda **kwargs: fake)
        monkeypatch.setattr(se, "EthereumClient", lambda uri: object())
        result = await tools["mech_request"](
            "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
        )
        assert result == fake.result
