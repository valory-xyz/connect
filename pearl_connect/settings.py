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
content is trusted. A failed verification fails closed: the file is replaced
with the built-in defaults (restricted mode). Legitimate changes go through
the password-authed settings endpoint, never through the agent session.
"""

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
class Settings:
    """The persisted guardrail state."""

    mode: str
    # chain -> lowercase addresses the service safe may call in restricted mode
    whitelist: dict[str, tuple[str, ...]]
    # which Claude Code the server opens the workspace session in
    harness: str = DEFAULT_HARNESS

    def to_dict(self) -> dict:
        """JSON-shaped view: the mode and the whitelist as sorted lists."""
        return {
            "mode": self.mode,
            "whitelist": {c: sorted(a) for c, a in self.whitelist.items()},
            "harness": self.harness,
        }

    @classmethod
    def from_raw(
        cls, mode: object, whitelist: t.Mapping, harness: object = DEFAULT_HARNESS
    ) -> "Settings":
        """Validate and normalize raw (JSON-shaped) input into Settings.

        :raises ValueError: on an unknown mode/harness or a malformed address.
        """
        if mode not in MODES:
            raise ValueError(f"mode must be one of {list(MODES)}")
        if harness not in HARNESSES:
            raise ValueError(f"harness must be one of {list(HARNESSES)}")
        normalized: dict[str, tuple[str, ...]] = {}
        for chain, addresses in whitelist.items():
            for address in addresses:
                if not Web3.is_address(str(address)):
                    raise ValueError(
                        f"'{address}' is not a valid address (chain '{chain}')"
                    )
            normalized[str(chain).lower()] = tuple(
                sorted(str(a).lower() for a in addresses)
            )
        return cls(mode=str(mode), whitelist=normalized, harness=str(harness))


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
    source of truth: a mech-client upgrade that moves the marketplace updates
    the default whitelist with it.
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
    return Settings(mode=MODE_RESTRICTED, whitelist=default_whitelist())


def derive_mac_key(account: LocalAccount) -> bytes:
    """Derive the settings MAC key from the agent private key (HKDF-SHA256).

    The agent session never holds the private key, so it cannot forge the MAC;
    the operator never needs the MAC key, because the server re-signs the file
    on every legitimate change.
    """
    prk = hmac.new(_MAC_KEY_INFO, bytes(account.key), hashlib.sha256).digest()
    return hmac.new(prk, _MAC_KEY_INFO + b"\x01", hashlib.sha256).digest()


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
            try:
                raw = self._path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return self._reset(defaults())
            verified = self._verify(raw)
            if verified is not None:
                return verified
            logger.warning(
                "settings file %s failed verification; restoring defaults", self._path
            )
            self._activity.record("settings_tampered", path=str(self._path))
            return self._reset(defaults())

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
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._path)
        self._expected_mac = payload["mac"]

    def _mac(self, payload: dict) -> str:
        canonical = json.dumps(
            {k: v for k, v in payload.items() if k != "mac"},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(self._mac_key, canonical.encode(), hashlib.sha256).hexdigest()

    def _verify(self, raw: str) -> Settings | None:
        try:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                return None
            mac = str(payload.get("mac", ""))
            if not hmac.compare_digest(mac, self._mac(payload)):
                return None
            if self._expected_mac is not None and mac != self._expected_mac:
                return None  # valid MAC, but not the file we last wrote: replay
            settings = Settings.from_raw(
                payload["mode"],
                payload["whitelist"],
                payload.get("harness", DEFAULT_HARNESS),
            )
        except (json.JSONDecodeError, ValueError, KeyError, TypeError, AttributeError):
            return None
        self._expected_mac = mac
        return settings
