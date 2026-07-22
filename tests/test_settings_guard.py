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
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from connect import settings as settings_module
from connect import workspace as workspace_module
from connect.activity import ActivityLog
from connect.config import AppConfig, ChainConfig
from connect.guard import Guard, GuardError
from connect.mech import (
    DEFAULT_MECH_CHAIN,
    MAX_DELIVERY_TIMEOUT,
    MechError,
    MechService,
    MechSigner,
)
from connect.safe import (
    APPROVE_SELECTOR,
    EXEC_TRANSACTION_SELECTOR,
    EXEC_TRANSACTION_TYPES,
    decode_approve,
)
from connect.server.settings_routes import WHITELIST_FROZEN
from connect.settings import (
    MAC_FIELDS,
    MODE_RESTRICTED,
    MODE_UNRESTRICTED,
    Protected,
    Settings,
    SettingsStore,
    default_whitelist,
    defaults,
    derive_mac_key,
    token_approve_targets,
)
from connect.signer import Signer, SignerError

from tests.conftest import FakeW3, TEST_PASSWORD, audit_entries, audit_kinds

SAFE = "0x" + "22" * 20
WHITELISTED = "0x" + "aa" * 20
OTHER = "0x" + "bb" * 20
PAYMENT_TOKEN = "0x" + "cc" * 20
TRACKER = "0x" + "ee" * 20

GNOSIS_MARKETPLACE = "0x735faab1c4ec41128c367afb5c3bac73509f70bb"


def approve_data(spender: str, amount: int = 10**6) -> bytes:
    """Encode ERC-20 approve(spender, amount) calldata."""
    return bytes.fromhex(APPROVE_SELECTOR) + abi_encode(
        ["address", "uint256"], [spender, amount]
    )


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

    def test_unreadable_file_fails_closed(
        self, account: LocalAccount, activity: ActivityLog, tmp_path: Path
    ) -> None:
        """An unreadable settings file restricts, it does not crash the agent.

        A missing file is not the only way a read fails: the store path may
        not even be a directory. Every guarded action loads settings, so
        raising here would kill the process instead of the read.
        """
        blocker = tmp_path / "not-a-directory"
        blocker.write_text("a file where the store should be")
        store = SettingsStore(
            blocker / "pearl-connect.settings.json", derive_mac_key(account), activity
        )
        assert store.load().protected.mode == MODE_RESTRICTED

    def test_an_unreadable_file_is_never_overwritten(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A read that fails must not destroy the settings it could not read.

        A missing file is safe to re-create; a momentarily unreadable one is
        not — a virus scanner or a backup tool holding it raises here, and
        resetting would permanently clobber the operator's mode, whitelist and
        harness over a condition that clears by itself. Restrict in memory,
        leave the file alone.
        """
        store.save(
            Settings(
                protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}),
                harness="claude_code_cli",
            )
        )
        before = store._path.read_bytes()  # pylint: disable=protected-access

        def refuse(self: Path, **kwargs: object) -> str:
            raise PermissionError("held by another process")

        monkeypatch.setattr(Path, "read_text", refuse)
        assert store.load().protected.mode == MODE_RESTRICTED  # fails closed
        monkeypatch.undo()

        # the file survived untouched, and so did everything in it — including
        # the MAC pin, so the surviving file is not then rejected as a replay
        assert store._path.read_bytes() == before  # pylint: disable=protected-access
        restored = store.load()
        assert restored.protected.mode == MODE_UNRESTRICTED
        assert restored.harness == "claude_code_cli"

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

    def test_token_approve_targets_maps_tokens_to_trackers(self) -> None:
        """Each configured payment token maps to its mech balance tracker."""
        usdc = "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"
        usdc_tracker = "0x5c50ebc17d002a4484585c8fbf62f51953493c0b"
        polygon = token_approve_targets("polygon")
        assert polygon[usdc] == usdc_tracker
        assert len(polygon) == 2  # USDC and OLAS
        # gnosis has an OLAS tracker but no USDC one: only the funded token maps
        olas = "0xce11e14225575945b8e6dc0d4f2dd4c570f79d9f"
        gnosis = token_approve_targets("gnosis")
        assert olas in gnosis
        assert usdc not in gnosis

    def test_token_approve_targets_unknown_chain_is_empty(self) -> None:
        """A chain mech-client does not know yields no targets."""
        assert token_approve_targets("testchain") == {}

    def test_token_approve_targets_broken_mech_client_is_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A broken mech-client fails closed rather than taking the guard down."""
        monkeypatch.setattr("mech_client.utils.constants.CHAIN_NAME_TO_ID", None)
        assert token_approve_targets("polygon") == {}

    def test_decode_approve_returns_none_on_undecodable(self) -> None:
        """The approve selector with unparseable args decodes to no spender."""
        assert decode_approve("0x" + APPROVE_SELECTOR + "ff") is None


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

    def test_restricted_refuses_a_bare_transfer_to_the_safe(
        self, store: SettingsStore
    ) -> None:
        """Even an EOA -> safe transfer is not a shape restricted mode allows.

        Funding the safe is the operator's job, through Pearl. A permission the
        agent never needed is one the gate should not carry.
        """
        guard = make_guard(store, MODE_RESTRICTED)
        with pytest.raises(GuardError, match="must be execTransaction"):
            guard.check_transaction("testchain", SAFE, 10**18, "0x")

    def test_the_floor_holds_in_every_mode(self, store: SettingsStore) -> None:
        """Delegatecall and safe-self-calls are refused even when unrestricted.

        Both change what the safe *is* — its modules, owners, guard — and what
        they install keeps moving funds after this signer stops signing. An
        unrestricted session could otherwise leave a door open that survives
        the operator switching back, which would make the switch a lie.
        """
        for mode in (MODE_RESTRICTED, MODE_UNRESTRICTED):
            guard = make_guard(store, mode, {"testchain": (WHITELISTED.lower(),)})
            delegatecall = exec_transaction_calldata(WHITELISTED, operation=1)
            with pytest.raises(GuardError, match="may not delegatecall"):
                guard.check_transaction("testchain", SAFE, 0, delegatecall)
            # enableModule/addOwnerWithThreshold/setGuard are all self-calls
            self_call = exec_transaction_calldata(SAFE, data=b"\x61\x0b\x59\x25")
            with pytest.raises(GuardError, match="may not call itself"):
                guard.check_transaction("testchain", SAFE, 0, self_call)

    def test_the_floor_holds_where_no_safe_is_configured(
        self, store: SettingsStore
    ) -> None:
        """A chain with no configured safe is not a bypass around the floor.

        The floor protects any safe the agent reaches, not only the one we
        configured. If the EOA owns a Safe on a chain we left unconfigured, an
        execTransaction to it is still refused delegatecall and self-admin —
        otherwise unrestricted mode would have a door the docstring denies.
        """
        guard = make_guard(store, MODE_UNRESTRICTED)  # "nosafe" has safe_address=None
        other_safe = "0x" + "dd" * 20
        delegatecall = exec_transaction_calldata(WHITELISTED, operation=1)
        with pytest.raises(GuardError, match="may not delegatecall"):
            guard.check_transaction("nosafe", other_safe, 0, delegatecall)
        self_call = exec_transaction_calldata(other_safe)  # inner to == outer to
        with pytest.raises(GuardError, match="may not call itself"):
            guard.check_transaction("nosafe", other_safe, 0, self_call)

    def test_unrestricted_still_signs_everything_else(
        self, store: SettingsStore
    ) -> None:
        """The floor narrows unrestricted mode; it does not replace it."""
        guard = make_guard(store, MODE_UNRESTRICTED)
        # an arbitrary EOA call to an address no whitelist ever saw
        guard.check_transaction("testchain", WHITELISTED, 10**18, "0xdeadbeef")
        # and the safe calling a non-whitelisted address
        guard.check_transaction(
            "testchain", SAFE, 0, exec_transaction_calldata(OTHER, value=10**18)
        )

    def test_the_floor_passes_a_plain_exec_transaction_to_any_target(
        self, store: SettingsStore
    ) -> None:
        """Widening the floor to every execTransaction must not over-block.

        An execTransaction to some third-party address — a CALL whose inner
        target is not that address — is a legitimate unrestricted-mode action.
        The floor only refuses delegatecall and self-calls; this must still pass,
        or a later tightening could silently break every safe-to-safe call.
        """
        guard = make_guard(store, MODE_UNRESTRICTED)
        third_party = "0x" + "99" * 20
        legit = exec_transaction_calldata(WHITELISTED, value=10**18)  # inner != outer
        guard.check_transaction("testchain", third_party, 0, legit)

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
                # refused by the floor now, not by the mode
                exec_transaction_calldata(WHITELISTED, operation=1),
                "may not delegatecall",
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

    def test_restricted_allows_token_approve_to_tracker(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A payment token may be approved, but only for its mech tracker."""
        monkeypatch.setattr(
            "connect.guard.token_approve_targets",
            lambda chain: {PAYMENT_TOKEN.lower(): TRACKER.lower()},
        )
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(PAYMENT_TOKEN, data=approve_data(TRACKER))
        guard.check_transaction("testchain", SAFE, 0, calldata)

    @pytest.mark.parametrize(
        "data",
        [
            approve_data(OTHER),  # approve, but to a spender that is not the tracker
            bytes.fromhex("a9059cbb") + b"\x00" * 64,  # transfer, not approve
        ],
    )
    def test_restricted_denies_non_tracker_token_calls(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch, data: bytes
    ) -> None:
        """On a payment token, only approve(spender=tracker) is allowed."""
        monkeypatch.setattr(
            "connect.guard.token_approve_targets",
            lambda chain: {PAYMENT_TOKEN.lower(): TRACKER.lower()},
        )
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        calldata = exec_transaction_calldata(PAYMENT_TOKEN, data=data)
        with pytest.raises(GuardError, match="payment token"):
            guard.check_transaction("testchain", SAFE, 0, calldata)

    def test_restricted_token_rule_does_not_leak_to_other_targets(
        self, store: SettingsStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An address absent from the token map still goes through the whitelist."""
        monkeypatch.setattr(
            "connect.guard.token_approve_targets",
            lambda chain: {PAYMENT_TOKEN.lower(): TRACKER.lower()},
        )
        guard = make_guard(
            store, MODE_RESTRICTED, {"testchain": (WHITELISTED.lower(),)}
        )
        # OTHER is not the payment token, so its approve is judged by the
        # whitelist (which does not contain OTHER), not the token rule
        calldata = exec_transaction_calldata(OTHER, data=approve_data(TRACKER))
        with pytest.raises(GuardError, match="not in the testchain whitelist"):
            guard.check_transaction("testchain", SAFE, 0, calldata)


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

        from connect.signer import _ChainState

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

    def test_the_server_composes_what_the_agent_no_longer_has_to(  # pylint: disable=too-many-arguments
        self,
        restricted_signer: Signer,
        fake_w3: FakeW3,
        settings_store: SettingsStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """send_via_safe wraps the inner call, and the wrapper passes the gate.

        The agent names only the call it wants the safe to make. What reaches
        the chain is an execTransaction to the safe carrying it — composed
        here, and judged by the same guard as if the agent had hand-rolled it.
        """
        settings_store.save(
            Settings(
                protected=Protected(
                    mode=MODE_RESTRICTED,
                    whitelist={"testchain": (WHITELISTED.lower(),)},
                )
            )
        )
        sent: dict = {}
        original = restricted_signer.send
        monkeypatch.setattr(
            restricted_signer,
            "send",
            lambda chain, to, **kw: (
                sent.update({"chain": chain, "to": to, **kw}),
                original(chain, to, **kw),
            )[1],
        )
        tx_hash = restricted_signer.send_via_safe(
            "testchain", WHITELISTED, value=10**18, data="0xabcd"
        )

        assert tx_hash.startswith("0x")
        assert fake_w3.eth.sent  # it really was broadcast
        assert sent["to"].lower() == SAFE.lower()  # the outer call goes to the safe
        assert sent["value"] == 0  # ...carrying nothing: the safe pays
        # and the inner call is the one the agent actually asked for
        calldata = sent["data"].removeprefix("0x")
        assert calldata.startswith(EXEC_TRANSACTION_SELECTOR)
        inner = abi_decode(EXEC_TRANSACTION_TYPES, bytes.fromhex(calldata[8:]))
        assert inner[0].lower() == WHITELISTED.lower()  # to
        assert inner[1] == 10**18  # value, out of the safe
        assert inner[2] == b"\xab\xcd"  # data
        assert inner[3] == 0  # a CALL, never a delegatecall

    def test_the_composer_is_not_a_way_around_the_gate(
        self, restricted_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A composed call to a non-whitelisted address is refused like any other.

        The composer is a caller of the gate, not a second gate. If it could
        reach targets the whitelist never saw, it would be the bypass this
        design exists to not have.
        """
        with pytest.raises(SignerError, match="not in the testchain whitelist"):
            restricted_signer.send_via_safe("testchain", OTHER, value=1)
        assert not fake_w3.eth.sent

    def test_the_composer_cannot_open_the_safe_to_itself(
        self, restricted_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """The floor holds even though the server wrote the calldata.

        `to` is still the agent's to choose, so it can name the safe — and
        enableModule would outlive the guardrail. The floor is in the gate for
        exactly this reason, not in the composer.
        """
        with pytest.raises(SignerError, match="may not call itself"):
            restricted_signer.send_via_safe("testchain", SAFE, data="0x610b5925")
        assert not fake_w3.eth.sent

    def test_send_via_safe_needs_a_safe(
        self,
        account: LocalAccount,
        activity: ActivityLog,
        store_path: Path,
        settings_store: SettingsStore,
    ) -> None:
        """A chain with no service safe has nothing to spend from."""
        config = AppConfig(
            chains={"safeless": ChainConfig(rpc_url="http://127.0.0.1:9")},
            store_path=store_path,
        )
        signer = Signer(
            account=account,
            config=config,
            activity=activity,
            guard=Guard(settings_store, config),
        )
        with pytest.raises(SignerError, match="no service safe is configured"):
            signer.send_via_safe("safeless", WHITELISTED, value=1)

    def test_a_malformed_inner_call_is_a_clean_error_not_a_crash(
        self, restricted_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """Bad compose input fails as a SignerError (a 400), not an eth_abi 500.

        The calldata is composed before the send, outside send()'s error
        handling, so the compose has to map its own input errors — a malformed
        target or an oversized value — the way the EOA path already does.
        """
        with pytest.raises(SignerError, match="cannot compose"):
            restricted_signer.send_via_safe("testchain", "0x1234", value=1)
        with pytest.raises(SignerError, match="cannot compose"):
            restricted_signer.send_via_safe("testchain", WHITELISTED, value=2**256)
        assert not fake_w3.eth.sent

    def test_the_safe_path_has_its_own_idempotency_namespace(
        self,
        restricted_signer: Signer,
        settings_store: SettingsStore,
        fake_w3: FakeW3,
    ) -> None:
        """One request_id on the EOA path and the safe path is two actions.

        The two endpoints share a body model, so a client generating one id per
        logical action could reuse it across them; the shared cache must not
        then hand back the first path's tx_hash for the other's call.
        """
        settings_store.save(
            Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}))
        )
        eoa = restricted_signer.send(
            "testchain", WHITELISTED, value=1, request_id="dup"
        )
        via_safe = restricted_signer.send_via_safe(
            "testchain", WHITELISTED, value=1, request_id="dup"
        )
        assert eoa != via_safe
        assert len(fake_w3.eth.sent) == 2  # no cross-path collision
        # ...but a real retry on the safe path with the same id is still deduped
        again = restricted_signer.send_via_safe(
            "testchain", WHITELISTED, value=1, request_id="dup"
        )
        assert again == via_safe
        assert len(fake_w3.eth.sent) == 2

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
        # A mech that publishes both a tool list and an off-chain endpoint —
        # the rare healthy case; tests that need a blocker override `metadata`.
        self.metadata: dict | None = {
            "tools": ["prediction-online"],
            "url": "https://mech.example/offchain",
        }
        self.tool_manager = SimpleNamespace(
            fetch_tools_metadata=lambda service_id: self.metadata
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
        """Route MechService._service construction to the fake.

        Patched on `connect.mech`, the name that module actually calls —
        patching mech-client's own module would miss the import-time binding.
        """
        import safe_eth.eth as se

        from connect import mech as mech_module

        fake = FakeMarketplaceService()
        monkeypatch.setattr(mech_module, "MarketplaceService", lambda **kwargs: fake)
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
        # the resolved chain travels with the result, so a caller that omitted
        # it can still tell which chain was paid
        assert result == {"chain": "testchain", **patched_mech.result}
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

    def test_delivered_request_survives_an_unwritable_audit_log(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A paid-for delivery must not be lost to a failing audit write.

        The audit runs after the mech answered: raising would discard a
        result the operator already paid for, and invite paying again.
        """
        monkeypatch.setattr(
            ActivityLog,
            "_append",
            lambda self, entry: (_ for _ in ()).throw(OSError("read-only fs")),
        )
        result = mech_service.request(
            "what is the answer",
            "prediction",
            chain="testchain",
            legacy_on_chain=True,
            priority_mech=OTHER,
        )
        assert result == {"chain": "testchain", **patched_mech.result}

    def test_request_offchain_denied_in_restricted(
        self,
        mech_service: MechService,
        settings_store: SettingsStore,
        patched_mech: FakeMarketplaceService,
    ) -> None:
        """The off-chain preflight points at the route that still works."""
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        with pytest.raises(MechError, match="retry it on-chain"):
            mech_service.request("q", "tool", chain="testchain")
        assert not patched_mech.calls

    def test_request_refuses_an_unreachable_offchain_mech(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """An off-chain request to a mech with no endpoint fails before paying.

        mech-client would discover this mid-flow and report it as a metadata
        problem, which reads as a slow gateway; the operator needs to know the
        mech is simply on-chain-only, before any deposit happens.
        """
        patched_mech.metadata = {"tools": ["prediction-online"]}
        with pytest.raises(MechError, match="cannot serve off-chain requests"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        assert not patched_mech.calls
        # the same mech is fine on-chain, which is what the error recommends
        mech_service.request(
            "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
        )
        assert len(patched_mech.calls) == 1

    def test_request_allows_a_mech_that_published_an_endpoint(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """The pre-flight passes a healthy mech straight through to the flow."""
        mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        assert patched_mech.calls[0]["use_offchain"] is True

    def test_unreadable_metadata_blocks_the_offchain_flow(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A mech that never published metadata cannot be reached off-chain."""
        patched_mech.metadata = None
        with pytest.raises(MechError, match="metadata unreadable"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        assert not patched_mech.calls

    def test_chain_defaults_to_one_holding_a_safe(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """Omitting `chain` picks a chain the safe can actually pay from.

        A fixed default strands an agent deployed elsewhere: it would list
        mechs it can never pay and only learn that from a failed request.
        """
        # pylint: disable=protected-access
        # function-scoped fixtures: this dict is rebuilt per test, so mutating
        # it here cannot leak. Widening their scope would break that.
        chains = mech_service._config.chains
        assert "gnosis" not in chains  # the preferred default is not configured
        mech_service.request("q", "t", legacy_on_chain=True, priority_mech=OTHER)
        assert patched_mech.calls  # resolved to testchain, the only funded chain

        chains["testchain"].safe_address = None
        with pytest.raises(MechError, match="no configured chain has a service safe"):
            mech_service.request("q", "t", legacy_on_chain=True, priority_mech=OTHER)

    def test_listing_still_works_with_no_safe_anywhere(
        self, mech_service: MechService, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Discovery is a subgraph query, so it must not demand a safe.

        Only paying needs one. Refusing to list left an agent on a deployment
        with no safe configured unable to see mechs it could previously browse.
        """
        import mech_client.infrastructure.subgraph.queries as queries

        asked: list[str] = []

        def record(chain: str) -> list:
            asked.append(chain)
            return []

        monkeypatch.setattr(queries, "query_mm_mechs_info", record)
        # pylint: disable=protected-access
        chains = mech_service._config.chains
        chains["testchain"].safe_address = None
        assert DEFAULT_MECH_CHAIN not in chains  # the default is not configured
        assert mech_service.tools()["mechs"] == []
        # fell back to a chain this deployment actually configured: the default
        # would raise "unknown chain" and answer nothing
        assert asked == ["testchain"]

        # with the default configured — still unfunded — discovery prefers it
        # over the alphabetically first chain
        chains[DEFAULT_MECH_CHAIN] = ChainConfig(rpc_url="http://127.0.0.1:9")
        assert mech_service.tools()["mechs"] == []
        assert asked == ["testchain", DEFAULT_MECH_CHAIN]
        assert not mech_service._services  # and built no paying service

    def test_default_chain_prefers_gnosis_over_alphabetical_order(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A funded `gnosis` wins over an alphabetically earlier funded chain.

        The preference must apply to *funded* chains only. Checking membership
        in the configured chains instead would resolve to a `gnosis` with no
        safe and fail later with an unrelated "no service safe" message.
        """
        # pylint: disable=protected-access
        chains = mech_service._config.chains
        chains["arbitrum"] = ChainConfig(
            rpc_url="http://127.0.0.1:9", safe_address=SAFE
        )
        chains["gnosis"] = ChainConfig(rpc_url="http://127.0.0.1:9", safe_address=SAFE)
        assert mech_service._resolve_chain(None) == "gnosis"

        # gnosis configured but unfunded -> fall through to the funded chains
        chains["gnosis"].safe_address = None
        assert mech_service._resolve_chain(None) == "arbitrum"

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

    def test_policy_refusals_are_audited_before_they_raise(
        self,
        store_path: Path,
        mech_service: MechService,
        settings_store: SettingsStore,
        patched_mech: FakeMarketplaceService,
        activity: ActivityLog,
    ) -> None:
        """Each pre-flight refusal leaves a trail naming which rule fired.

        The activity log is what an operator reconstructs an incident from. A
        request blocked by policy must not look there like one that was never
        attempted, and the three rules must be distinguishable from each other.
        """
        # 1. price cap
        patched_mech.mech_info = (SimpleNamespace(name="NATIVE"), 42, 10**18)
        with pytest.raises(MechError, match="max_payment"):
            mech_service.request(
                "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
            )
        # 2. mech unreachable off-chain
        patched_mech.mech_info = (SimpleNamespace(name="NATIVE"), 42, 10**16)
        patched_mech.metadata = {"tools": ["prediction-online"]}
        with pytest.raises(MechError, match="cannot serve off-chain requests"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        # 3. restricted mode
        settings_store.save(
            Settings(protected=Protected(mode=MODE_RESTRICTED, whitelist={}))
        )
        with pytest.raises(MechError, match="restricted"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)

        blocked = [
            entry
            for entry in audit_entries(store_path)
            if entry["kind"] == "mech_request_blocked"
        ]
        assert [entry["reason"] for entry in blocked] == [
            "over-max-payment",
            "offchain-unreachable",
            "restricted-mode",
        ]
        assert all(entry["chain"] == "testchain" for entry in blocked)
        assert not patched_mech.calls  # nothing was ever sent

    def test_price_cap_binds_the_offchain_flow_too(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """The cap is checked for the default flow, before any metadata read.

        Ordering matters: an over-priced mech is disqualified on price alone,
        so the pre-flight's network fetch is never reached.
        """
        patched_mech.mech_info = (SimpleNamespace(name="NATIVE"), 42, 10**18)
        patched_mech.tool_manager = SimpleNamespace(
            fetch_tools_metadata=lambda service_id: pytest.fail(
                "priced out already; the metadata fetch should not be reached"
            )
        )
        with pytest.raises(MechError, match="max_payment"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        assert not patched_mech.calls

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
        # this mech published an endpoint, so nothing bars the default flow
        assert info["offchain_capable"] is True
        assert "offchain_note" not in info

    def test_tools_degrade_without_metadata(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """An unreadable metadata document yields notes, not an error.

        The mech stays usable on-chain, so the report must not read as a
        total failure — but it must also stop claiming, as it once did, that
        the off-chain flow will go through with a known tool name.
        """
        patched_mech.tool_manager = SimpleNamespace(
            fetch_tools_metadata=lambda service_id: (_ for _ in ()).throw(
                TimeoutError("slow")
            )
        )
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "tools" not in info
        assert "unreadable" in info["tools_note"]
        assert info["offchain_capable"] is False
        # the cause travels with the verdict, and the verdict does not claim
        # a transient timeout is permanent
        assert "TimeoutError: slow" in info["offchain_note"]
        assert "may be transient" in info["offchain_note"]
        # an unreadable fetch may clear on its own, so paying for gas is the
        # second move, not the first
        assert "retry before paying" in info["offchain_note"]

    def test_the_two_blockers_advise_differently(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A mech with no endpoint goes on-chain; an unreadable fetch retries.

        Sending the unreadable case on-chain spends real gas to avoid a retry
        that may well have worked, so the two must not share one imperative.
        """
        patched_mech.metadata = {"tools": ["prediction-online"]}  # readable, no url
        published = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "on-chain requests only" in published["offchain_note"]
        assert "retry" not in published["offchain_note"]

        patched_mech.metadata = None  # unreadable
        unreadable = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "retry before paying" in unreadable["offchain_note"]

    def test_unreadable_metadata_verdict_never_claims_permanence(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A miss with no cause must not be reported as a permanent one.

        mech-client swallows the common transport failures and returns a bare
        None, so nothing here knows whether the mech never published metadata
        or the gateway simply timed out. An earlier version asserted the
        former outright, which sends an operator on-chain for good over what
        may be a blip.
        """
        patched_mech.metadata = None
        note = mech_service.tools(chain="testchain", priority_mech=OTHER)[
            "offchain_note"
        ]
        assert "no cause reported" in note  # stands in for the absent cause
        # hedged, not asserted: "may be" is what keeps this honest
        assert "may be transient or never published" in note

    def test_tools_separates_no_metadata_from_no_tools_published(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """Readable metadata listing no tools is not "metadata unavailable"."""
        patched_mech.metadata = {"url": "https://mech.example/offchain"}
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "tools" not in info
        assert "lists no tools" in info["tools_note"]
        assert info["offchain_capable"] is True  # the endpoint is still there

    @pytest.mark.parametrize("published", [5, "abc", {"a": 1}, None])
    def test_tools_refuses_to_iterate_a_malformed_tools_field(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        published: object,
    ) -> None:
        """A non-list `tools` degrades to a note instead of being iterated.

        The document comes from the mech operator, so its shape is untrusted.
        A bare string is the dangerous one: iterating it yields one "tool" per
        character — plausible names that no mech serves, which an agent would
        then pass straight to mech_request.
        """
        patched_mech.metadata = {"tools": published, "url": "https://m.example"}
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "tools" not in info
        assert "lists no tools" in info["tools_note"]

    def test_tools_drops_entries_that_are_not_names(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A list of the right type can still hold entries of the wrong one.

        Stringifying them invents the same plausible-but-unservable names the
        non-list case was fixed for, so the untrusted-document rule has to
        apply to the contents too, not just the container.
        """
        patched_mech.metadata = {
            "tools": ["real-tool", {"name": "x"}, 5, "", "  ", None],
            "url": "https://m.example",
        }
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert info["tools"] == ["real-tool"]

    def test_tools_survives_metadata_that_is_not_a_document(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """A non-dict payload degrades like an unreadable one, not a crash."""
        patched_mech.metadata = ["not", "a", "document"]  # type: ignore[assignment]
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert "tools" not in info
        assert info["offchain_capable"] is False

    @pytest.mark.parametrize("url", ["   ", "", 1, ["https://m.example"], None])
    def test_a_url_that_is_not_a_usable_string_blocks_the_offchain_flow(
        self,
        mech_service: MechService,
        patched_mech: FakeMarketplaceService,
        url: object,
    ) -> None:
        """Only a non-empty string endpoint counts as reachable.

        A truthy non-string once passed this check and the pre-flight, then
        failed inside mech-client's `.strip()` mid-flow — the exact confusing
        failure the pre-flight exists to replace.
        """
        patched_mech.metadata = {"tools": ["prediction-online"], "url": url}
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert info["offchain_capable"] is False
        with pytest.raises(MechError, match="cannot serve off-chain requests"):
            mech_service.request("q", "t", chain="testchain", priority_mech=OTHER)
        assert not patched_mech.calls

    def test_tools_report_a_mech_that_published_no_endpoint(
        self, mech_service: MechService, patched_mech: FakeMarketplaceService
    ) -> None:
        """Readable metadata without a `url` is still off-chain-unusable.

        This is the common case — most listed mechs publish tools and no
        endpoint — and the one an earlier version reported as fully healthy.
        """
        patched_mech.metadata = {"tools": ["prediction-online"]}
        info = mech_service.tools(chain="testchain", priority_mech=OTHER)
        assert info["tools"] == ["prediction-online"]  # healthy in every other way
        assert "tools_note" not in info
        assert info["offchain_capable"] is False
        assert "no 'url'" in info["offchain_note"]

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
        from connect.server import settings_routes

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
        monkeypatch.setattr("connect.server.settings_routes.time.sleep", lambda _: None)
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

        bad = client.patch("/settings", json={"harness": "cursor"})
        assert bad.status_code == 400
        assert "harness" in bad.json()["detail"]

    def test_session_opens_the_configured_harness(
        self,
        client: TestClient,
        store_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """POST /session opens a session on demand, in the chosen harness."""
        opened: list[str] = []
        monkeypatch.setattr(
            workspace_module.Workspace,
            "open_session",
            lambda self, harness: opened.append(harness),
        )
        client.patch("/settings", json={"harness": "claude_code_cli"})
        response = client.post("/session")
        assert response.status_code == 200
        assert response.json() == {"launched": True, "harness": "claude_code_cli"}
        assert opened == ["claude_code_cli"]
        assert "session_launched" in audit_kinds(store_path)

    def test_session_launch_failure_is_reported(
        self,
        client: TestClient,
        store_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A deep link that will not open is a 200 the UI can show, not a 500.

        The FE needs the reason to raise a dismissable alert: a harness that
        is not installed is the operator's environment, not a server fault.
        """

        def refuse(self: workspace_module.Workspace, harness: str) -> None:
            raise workspace_module.LaunchError(f"could not open {harness}")

        monkeypatch.setattr(workspace_module.Workspace, "open_session", refuse)
        response = client.post("/session")
        assert response.status_code == 200
        body = response.json()
        assert body["launched"] is False
        assert body["harness"] == "claude_code_desktop"
        assert "could not open claude_code_desktop" in body["error"]
        assert "session_launch_failed" in audit_kinds(store_path)

    def test_session_rejects_cross_origin(self, client: TestClient) -> None:
        """A webpage must not be able to spawn agent sessions."""
        response = client.post("/session", headers={"Origin": "https://evil.example"})
        assert response.status_code == 403

    def test_session_harness_override_does_not_persist(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit harness opens there once, leaving the preference alone."""
        opened: list[str] = []
        monkeypatch.setattr(
            workspace_module.Workspace,
            "open_session",
            lambda self, harness: opened.append(harness),
        )
        response = client.post("/session", json={"harness": "claude_code_cli"})
        assert response.status_code == 200
        assert response.json() == {"launched": True, "harness": "claude_code_cli"}
        assert opened == ["claude_code_cli"]
        # the saved preference is untouched: the next default launch uses it
        assert client.get("/settings").json()["harness"] == "claude_code_desktop"
        client.post("/session")
        assert opened == ["claude_code_cli", "claude_code_desktop"]

    def test_session_survives_an_unwritable_audit_log(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The session opened; a failing audit write must not report otherwise.

        Reporting failure after the deep link already fired would have the
        operator open a second session for work that succeeded.
        """
        opened: list[str] = []
        monkeypatch.setattr(
            workspace_module.Workspace,
            "open_session",
            lambda self, harness: opened.append(harness),
        )
        monkeypatch.setattr(
            ActivityLog,
            "_append",
            lambda self, entry: (_ for _ in ()).throw(OSError("read-only fs")),
        )
        response = client.post("/session")
        assert response.status_code == 200
        assert response.json()["launched"] is True
        assert opened == ["claude_code_desktop"]

    def test_session_rejects_an_unknown_harness(self, client: TestClient) -> None:
        """An unknown harness is a 400, not a deep link nobody can open."""
        response = client.post("/session", json={"harness": "cursor"})
        assert response.status_code == 400
        assert "harness" in response.json()["detail"]
        # and a typo'd field is refused outright
        assert client.post("/session", json={"harnes": "x"}).status_code == 422

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
        from connect.server import auth as auth_module

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
        from connect.server import auth as auth_module
        from connect.server import settings_routes

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
        from connect.server import auth as auth_module

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
        from connect.server import auth as auth_module
        from connect.server import settings_routes

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

        from connect.server.settings_routes import ProtectedPatch, SettingsPatch

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
        from connect.server.mcp_tools import build_mcp

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
        import safe_eth.eth as se

        from connect import mech as mech_module

        fake = FakeMarketplaceService()
        monkeypatch.setattr(mech_module, "MarketplaceService", lambda **kwargs: fake)
        monkeypatch.setattr(se, "EthereumClient", lambda uri: object())
        result = await tools["mech_request"](
            "q", "t", chain="testchain", legacy_on_chain=True, priority_mech=OTHER
        )
        assert result == {"chain": "testchain", **fake.result}
