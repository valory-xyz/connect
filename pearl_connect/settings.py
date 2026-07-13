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

"""Tamper-evident Settings persisted in the agent workspace.

The settings file lives inside STORE_PATH, which is also the Claude session's
workspace — the agent can read it (nothing in it is secret) and could write
it, so every read verifies an HMAC keyed off the agent private key before the
content is trusted. The canonical shape nests the security-critical fields
under "protected" ({"protected": {"mode", "whitelist"}, "harness"}) and the
MAC covers exactly that object (plus the version); a failed verification
fails closed by resetting it to the built-in defaults (restricted mode).
Preference fields (harness) live outside "protected" without integrity
checks: editing them simply applies, and they survive a protected reset.
Legitimate protected changes go through the password-gated settings PATCH,
never through the agent session.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import threading
import typing as t
from dataclasses import dataclass
from pathlib import Path

from eth_account.signers.local import LocalAccount
from web3 import Web3

from pearl_connect.activity import ActivityLog

logger = logging.getLogger("agent")

SETTINGS_FILE = "pearl-connect.settings.json"
SETTINGS_VERSION = 1

# The MAC covers the version and the "protected" object of the canonical
# shape — everything an attacker could profit from editing. The harness is
# deliberately outside it: a preference, and the worst a tampered value can
# do is open the workspace in the other Claude Code. A new top-level field
# ships outside the MAC unless it is named here, so a test pins the file's
# top-level keys against this tuple: adding one fails it until its integrity
# coverage is a decision rather than an oversight.
MAC_FIELDS = ("version", "protected")

MODE_RESTRICTED = "restricted"
MODE_UNRESTRICTED = "unrestricted"
MODES = (MODE_RESTRICTED, MODE_UNRESTRICTED)

HARNESS_CLAUDE_CODE_CLI = "claude_code_cli"
HARNESS_CLAUDE_CODE_DESKTOP = "claude_code_desktop"
HARNESSES = (HARNESS_CLAUDE_CODE_CLI, HARNESS_CLAUDE_CODE_DESKTOP)
DEFAULT_HARNESS = HARNESS_CLAUDE_CODE_DESKTOP

_MAC_KEY_INFO = b"pearl-connect settings hmac v1"

# Operator-provided additions to the default whitelist (chain -> addresses).
# The MechMarketplace contracts are merged in by default_whitelist().
EXTRA_DEFAULT_WHITELIST: dict[str, tuple[str, ...]] = {}


@dataclass
class Protected:
    """The integrity-checked guardrail state (the "protected" object)."""

    mode: str
    # chain -> lowercase addresses the service safe may call in restricted mode
    whitelist: dict[str, tuple[str, ...]]

    def to_dict(self) -> dict:
        """JSON-shaped view: the mode and the whitelist as sorted lists."""
        return {
            "mode": self.mode,
            "whitelist": {c: sorted(a) for c, a in self.whitelist.items()},
        }

    @classmethod
    def from_raw(cls, raw: t.Mapping) -> "Protected":
        """Validate and normalize a raw (JSON-shaped) protected object.

        :raises ValueError: on an unknown mode or a malformed address;
        :raises KeyError: on missing fields.
        """
        mode = raw["mode"]
        if mode not in MODES:
            raise ValueError(f"mode must be one of {list(MODES)}")
        normalized: dict[str, tuple[str, ...]] = {}
        for chain, addresses in raw["whitelist"].items():
            for address in addresses:
                if not Web3.is_address(str(address)):
                    raise ValueError(
                        f"'{address}' is not a valid address (chain '{chain}')"
                    )
            normalized[str(chain).lower()] = tuple(
                sorted(str(a).lower() for a in addresses)
            )
        return cls(mode=str(mode), whitelist=normalized)


def validate_harness(value: object) -> str:
    """Return the harness value, or :raises ValueError: on unknown ones."""
    if value not in HARNESSES:
        raise ValueError(f"harness must be one of {list(HARNESSES)}")
    return str(value)


def _harness_or_default(value: object) -> str:
    """Return a valid harness; warn and fall back on anything else.

    The lenient counterpart of validate_harness, for values read from disk:
    the harness is a preference, so a bad value must not count as tamper.
    """
    try:
        return validate_harness(value)
    except ValueError:
        logger.warning("invalid harness %r in settings; using default", value)
        return DEFAULT_HARNESS


@dataclass
class Settings:
    """The persisted state in its canonical shape: protected + preferences."""

    protected: Protected
    # which Claude Code the server opens the workspace session in (preference)
    harness: str = DEFAULT_HARNESS

    def to_dict(self) -> dict:
        """Canonical nested shape, used everywhere: file, API and MCP tool."""
        return {"protected": self.protected.to_dict(), "harness": self.harness}

    @classmethod
    def from_raw(cls, raw: t.Mapping) -> "Settings":
        """Parse the raw canonical shape: strict protected, lenient harness.

        :raises ValueError:/:raises KeyError: on a malformed protected
        object; an invalid harness only falls back to the default — it is a
        preference, not an integrity boundary.
        """
        return cls(
            protected=Protected.from_raw(raw["protected"]),
            harness=_harness_or_default(raw.get("harness", DEFAULT_HARNESS)),
        )

    def merged(self, patch: t.Mapping) -> "Settings":
        """Return a copy updated by a partial canonical-shaped patch.

        Merge-patch semantics for the settings endpoint: absent (or None)
        fields keep their current values, at both levels of the shape.
        :raises ValueError: on invalid replacements.
        """
        protected = {
            k: v for k, v in (patch.get("protected") or {}).items() if v is not None
        }
        harness = patch.get("harness")
        return Settings(
            protected=Protected.from_raw({**self.protected.to_dict(), **protected}),
            harness=(
                validate_harness(harness) if harness is not None else self.harness
            ),
        )


def _mech_system_addresses() -> dict[str, list[str]]:
    """Collect the MechMarketplace contract per chain from the pinned mech-client.

    The marketplace is the only contract the service safe CALLs in the
    restricted-mode mech flow (`request`/`requestBatch`; native payment rides
    as the inner value). Balance trackers are deliberately NOT whitelisted —
    the safe only calls them for prepaid deposits, which our surface reaches
    only via the off-chain flow (unrestricted mode). Payment token contracts
    are NOT whitelisted either: the whitelist is address-level, so allowing a
    token contract would allow arbitrary `transfer`s of the safe's balance,
    not just the `approve` a token-paid mech needs. Operators can whitelist
    those explicitly when they want token-paid mechs in restricted mode.

    Importing the address (rather than hardcoding a copy) keeps a single
    source of truth for fresh installs and resets. Existing installs keep
    their persisted whitelist as-is — it is operator-owned state, and merging
    defaults at load time would silently re-add an address the operator
    deliberately removed. An upgrade that moves the marketplace reaches them
    only when settings are reset or re-saved.
    """
    # pylint: disable=import-outside-toplevel
    try:
        from mech_client.infrastructure.config.constants import MECH_CONFIGS
        from mech_client.utils.constants import CHAIN_NAME_TO_ID

        zero_address = "0x" + "00" * 20
        mechs = json.loads(Path(MECH_CONFIGS).read_text(encoding="utf-8"))
        result: dict[str, list[str]] = {}
        for chain in CHAIN_NAME_TO_ID:
            marketplace = mechs.get(chain, {}).get("mech_marketplace_contract", "")
            if marketplace and marketplace.lower() != zero_address:
                result[chain] = [marketplace.lower()]
        return result
    except Exception as e:  # pylint: disable=broad-exception-caught
        # A broken mech-client install must not take the guard down with it:
        # every guarded decision loads settings, and a tampered/missing file
        # loads defaults. Fail closed to an empty whitelist instead.
        logger.warning("could not load mech marketplace addresses: %s", e)
        return {}


def default_whitelist() -> dict[str, tuple[str, ...]]:
    """Marketplace contracts merged with the operator's extra defaults."""
    merged: dict[str, set[str]] = {
        chain: set(addresses) for chain, addresses in _mech_system_addresses().items()
    }
    for chain, addresses in EXTRA_DEFAULT_WHITELIST.items():
        merged.setdefault(chain, set()).update(a.lower() for a in addresses)
    return {chain: tuple(sorted(addresses)) for chain, addresses in merged.items()}


def defaults() -> Settings:
    """Return the fail-closed state: restricted, marketplaces whitelisted."""
    return Settings(
        protected=Protected(mode=MODE_RESTRICTED, whitelist=default_whitelist())
    )


def derive_mac_key(account: LocalAccount) -> bytes:
    """Derive the settings MAC key from the agent private key (HKDF-SHA256).

    The agent session never holds the private key, so it cannot forge the MAC;
    the operator never needs the MAC key, because the server re-signs the file
    on every legitimate change.
    """
    prk = hmac.new(_MAC_KEY_INFO, bytes(account.key), hashlib.sha256).digest()
    return hmac.new(prk, _MAC_KEY_INFO + b"\x01", hashlib.sha256).digest()


class SettingsPersistError(OSError):
    """The settings could not be written to disk.

    Distinct from the OSErrors of the read path (which fail closed to the
    defaults in-memory): only this one means the caller's change did not land,
    so only this one may be reported as such.
    """


class PatchResult(t.NamedTuple):
    """The settings on either side of a patch, for callers auditing changes."""

    previous: Settings
    updated: Settings


class SettingsStore:
    """Verified reads and signed writes of the settings file.

    Reads are not cached: the file is tiny and signing operations are seconds
    apart, so re-reading and re-verifying on every enforcement decision costs
    nothing and guarantees a change (or a tamper) is honored immediately.

    Replay defense: the MAC of the last file this process wrote or accepted is
    pinned in memory, so putting back an *old* validly-MAC'd settings file
    (e.g. one captured while the mode was unrestricted) fails verification
    like any other tamper. A rollback staged while the server is not running
    is out of reach of this pin — the first load of a run accepts any file
    with a valid MAC.
    """

    def __init__(self, path: Path, mac_key: bytes, activity: ActivityLog) -> None:
        """Initialize."""
        self._path = path
        self._mac_key = mac_key
        self._activity = activity
        self._lock = threading.Lock()
        self._expected_mac: str | None = None

    def load(self) -> Settings:
        """Return the verified settings, restoring defaults on any problem."""
        with self._lock:
            return self._load()

    def patch(self, patch: t.Mapping) -> PatchResult:
        """Merge a partial canonical-shaped patch and persist the result.

        One lock spans the read-merge-write: concurrent patches (the UI has
        independent protected and harness forms) must not lose an update.
        Returns both sides of the change, so a caller can audit what actually
        moved rather than what was submitted.
        :raises ValueError: on invalid replacements;
        :raises SettingsPersistError: when the merged settings cannot be
        persisted — an explicit change must never claim success while the disk
        disagrees (unlike the load path, which degrades to its in-memory value).
        """
        with self._lock:
            previous = self._load()
            updated = previous.merged(patch)
            try:
                self._save(updated)
            except OSError as e:
                self._activity.record(
                    "settings_persist_failed", path=str(self._path), error=str(e)
                )
                raise SettingsPersistError(str(e)) from e
            return PatchResult(previous=previous, updated=updated)

    def _load(self) -> Settings:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            # not only a missing file: an unreadable one (bad permissions, a
            # store path that is not a directory, a failing disk) must fail
            # closed too. Every guarded action loads settings, so raising here
            # would take the process down rather than merely restrict it.
            return self._reset(defaults())
        payload = self._parse(raw)
        verified = self._verify(payload)
        if verified is not None:
            return verified
        logger.warning(
            "settings file %s failed verification; restoring defaults", self._path
        )
        self._activity.record("settings_tampered", path=str(self._path))
        fallback = defaults()
        # the harness is a preference, not a security control: a tampered
        # mode/whitelist resets those, but must not discard the harness
        fallback.harness = _harness_or_default(payload.get("harness", DEFAULT_HARNESS))
        return self._reset(fallback)

    @staticmethod
    def _parse(raw: str) -> dict:
        """Return the file's payload — empty if it is not even a JSON object.

        The single parse of the file: an unverifiable payload is still read for
        the harness (a preference that survives a guardrail reset), and a
        tampered file is re-read on every guarded decision until the reset
        write lands, so one parse with one error path is worth having.
        """
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return payload if isinstance(payload, dict) else {}

    def save(self, settings: Settings) -> None:
        """Write settings with a fresh MAC, atomically."""
        with self._lock:
            self._save(settings)

    def _reset(self, settings: Settings) -> Settings:
        """Persist settings on the load path, tolerating a failing disk.

        Every guarded decision loads settings; an unwritable store must
        degrade to enforcing the in-memory value, not error every request.
        """
        try:
            self._save(settings)
        except OSError as e:
            logger.warning("could not persist settings to %s: %s", self._path, e)
        return settings

    def _save(self, settings: Settings) -> None:
        payload = {"version": SETTINGS_VERSION, **settings.to_dict()}
        payload["mac"] = self._mac(payload)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self._path)
        except OSError:
            with contextlib.suppress(OSError):  # don't mask the write error
                tmp.unlink()
            raise
        self._expected_mac = payload["mac"]

    def _mac(self, payload: dict) -> str:
        canonical = json.dumps(
            {k: payload.get(k) for k in MAC_FIELDS},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(self._mac_key, canonical.encode(), hashlib.sha256).hexdigest()

    def _verify(self, payload: dict) -> Settings | None:
        mac = str(payload.get("mac", ""))
        if not hmac.compare_digest(mac, self._mac(payload)):
            return None
        if self._expected_mac is not None and mac != self._expected_mac:
            return None  # valid MAC, but not the file we last wrote: replay
        try:
            settings = Settings.from_raw(payload)
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
        self._expected_mac = mac
        return settings
