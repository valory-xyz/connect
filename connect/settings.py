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
MAC covers that object, the harness and the version; a failed verification
resets them to the built-in defaults. Landing on the defaults (rather than a
narrower fail-closed state) is deliberate: a mistaken edit or deletion of
the file must not brick the agent, and the defaults are exactly what a
fresh install ships with — so the reset adds no exposure a new install does
not already accept. Every reset-to-defaults transition is audited once per episode.
The harness is a preference (a harness-only PATCH needs no password), but it
is under the MAC too: with OCB it decides what an unnamed launch installs and
runs, with no fallback, so an edited one must not apply. A version-1 file
(MAC'd before the harness was) verifies its protected object once and keeps
its harness unless it is ocb_cli, which no released version-1 file holds; it
is then rewritten under the current MAC.
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

from connect.activity import ActivityLog
from connect.chains import MECH_CLIENT_CHAIN_NAMES
from connect.safe import ZERO_ADDRESS

logger = logging.getLogger("agent")

SETTINGS_FILE = "pearl-connect.settings.json"
SETTINGS_VERSION = 2

# The MAC covers the version, the "protected" object of the canonical shape
# and the harness — everything an attacker could profit from editing. The
# harness cannot move funds or widen the guardrail, but with OCB a written
# value would make the next unnamed launch install and open OCB, which never
# falls back, so it is covered too. A new top-level field ships outside the
# MAC unless it is named here, so a test pins the file's top-level keys
# against this tuple: adding one fails it until its integrity coverage is a
# decision rather than an oversight.
MAC_FIELDS = ("version", "protected", "harness")
# what a version-1 file's MAC covered, accepted once to migrate it
LEGACY_MAC_FIELDS = ("version", "protected")

MODE_RESTRICTED = "restricted"
MODE_UNRESTRICTED = "unrestricted"
MODES = (MODE_RESTRICTED, MODE_UNRESTRICTED)

# Whether agent-facing surfaces disclose the guardrail mode: the `mode` key in
# wallet_info / GET /wallet and the `settings` MCP tool. Off, the agent is not
# told a mode system exists — the guard still enforces whatever the operator
# chose, and refusals name only the violated rule. Flip to True to restore the
# readouts; the mode sections removed from the bundled workspace brief and
# skills (connect/assets/) are a manual re-add from git history.
# This hiding shapes the agent's prompt, it is NOT a confidentiality boundary:
# the settings file sits readable in the agent's own workspace and the
# operator UI's token-less GET /settings serves the same shape to any local
# caller. Nothing security-relevant may ever depend on the agent not knowing
# the mode — enforcement lives in the guard, which never trusts the agent.
EXPOSE_MODE_TO_AGENT = False

HARNESS_CLAUDE_CODE_CLI = "claude_code_cli"
HARNESS_CLAUDE_CODE_DESKTOP = "claude_code_desktop"
HARNESS_CODEX_CLI = "codex_cli"
HARNESS_CODEX_DESKTOP = "codex_desktop"
HARNESS_OCB_CLI = "ocb_cli"
# display order: the UI lists GET /settings' `harnesses` in this order,
# desktop before CLI within each tool
HARNESSES = (
    HARNESS_CLAUDE_CODE_DESKTOP,
    HARNESS_CLAUDE_CODE_CLI,
    HARNESS_CODEX_DESKTOP,
    HARNESS_CODEX_CLI,
    HARNESS_OCB_CLI,
)
DEFAULT_HARNESS = HARNESS_CLAUDE_CODE_CLI

# OCB's model is a chat mech paid per request through mech_request; the
# budget matches OCB's own per-session cap on mech spending
OCB_MODEL_BUDGET_USD = 1
# chain -> OCB's chat mech (deployed and confirmed on-chain); None would leave
# "OCB CLI" unavailable on that chain rather than unable to think
OCB_CHAT_MECHS: dict[str, str | None] = {
    "gnosis": "0x4a8A3FA1cde489DFec96F8442d65e9526ec3405c",
    "polygon": "0x364b8238C7d9a05e0F68F87cfF364b6aBD926fEc",
    "robinhood": "0xd3f392C8384cAa4D2864ACba826374337d43a100",
    "base": "0x195Fe9d745a92deE64C9Bf75EFDc7779EB7a5C91",
    "optimism": "0x8122Dcd1E271d0F793827D13410333852DBB9dAb",
}
# the only reasons GET /settings may give; connect-ui renders each one
UnavailableReason = t.Literal["windows_unsupported", "model_unavailable"]
UNAVAILABLE_WINDOWS: UnavailableReason = "windows_unsupported"
UNAVAILABLE_MODEL: UnavailableReason = "model_unavailable"

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


def harness_unavailable_reason(
    harness: str, ocb_mech: str | None, platform: str
) -> UnavailableReason | None:
    """Why `harness` cannot be used on this instance, or None when it can.

    OCB runs unsandboxed on native Windows, where a session could read the
    keys under ~/.operate, so Windows is ruled out before the chain is asked.
    """
    if harness != HARNESS_OCB_CLI:
        return None
    if platform == "win32":
        return UNAVAILABLE_WINDOWS
    if ocb_mech is None:
        return UNAVAILABLE_MODEL
    return None


def ocb_chat_mech(
    chain: str | None, overrides: t.Mapping[str, str] | None = None
) -> str | None:
    """Return OCB's chat mech on `chain` — an override first — or None."""
    if chain is None:
        return None
    return (overrides or {}).get(chain) or OCB_CHAT_MECHS.get(chain)


def harness_options(
    unavailable: t.Callable[[str], UnavailableReason | None],
) -> list[dict]:
    """GET /settings' `harnesses`: each harness and why it is unavailable, if so."""
    options = []
    for harness in HARNESSES:
        reason = unavailable(harness)
        option: dict[str, object] = {"id": harness, "available": reason is None}
        if reason is not None:
            option["unavailable_reason"] = reason
        options.append(option)
    return options


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
    # which harness the server opens the workspace session in (preference)
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

    The marketplace is the only contract the safe CALLs to *submit* a mech
    request (`request`/`requestBatch`; native payment rides as the inner
    value); token-paid mechs additionally `approve` the payment token, see
    token_approve_targets(). A marketplace takes only the requests the
    server's mech flow composes, in every mode; the guard reads the
    marketplaces from Connect's own `chains.MECH_MARKETPLACES`, not from
    this read. Balance
    trackers are deliberately NOT whitelisted —
    the safe only calls them for prepaid deposits, which restricted mode
    admits through the guard's one-shot capped deposit allowances (armed per
    off-chain request by the mech flow). Payment token contracts
    are NOT whitelisted either: the whitelist is address-level, so allowing a
    token contract would allow arbitrary `transfer`s of the safe's balance,
    not just the `approve` a token-paid mech needs. Token-paid mechs are
    handled by token_approve_targets() instead, which the guard restricts to
    `approve(spender=tracker)`.

    Importing the address (rather than hardcoding a copy) keeps a single
    source of truth for fresh installs and resets. Existing installs keep
    their persisted whitelist as-is — it is operator-owned state, and merging
    defaults at load time would silently re-add an address the operator
    deliberately removed. An upgrade that moves the marketplace reaches them
    only when settings are reset or re-saved; until then the address they
    hold stays in `chains.MECH_MARKETPLACES`, so it admits no agent call.
    """
    # pylint: disable=import-outside-toplevel
    try:
        from mech_client.infrastructure.config.constants import MECH_CONFIGS
        from mech_client.utils.constants import CHAIN_NAME_TO_ID

        mechs = json.loads(Path(MECH_CONFIGS).read_text(encoding="utf-8"))
        result: dict[str, list[str]] = {}
        for chain in CHAIN_NAME_TO_ID:
            marketplace = mechs.get(chain, {}).get("mech_marketplace_contract", "")
            if marketplace and marketplace.lower() != ZERO_ADDRESS:
                result[chain] = [marketplace.lower()]
        return result
    except Exception as e:  # pylint: disable=broad-exception-caught
        # A broken mech-client install must not take the guard down with it:
        # every guarded decision loads settings, and a tampered/missing file
        # loads defaults. Fail closed to an empty whitelist instead.
        logger.warning("could not load mech marketplace addresses: %s", e)
        return {}


def prepaid_balance_trackers(chain: str) -> dict[str, str]:
    """Return each mech balance tracker on `chain` -> the asset its balance is in.

    The asset is a payment token's lowercase address, or "native". From the
    pinned mech-client (`balance_tracker`, `payment_token`); a payment type
    with no tracker deployed on the chain is left out, and so is every one on
    a chain mech-client does not know.

    :raises ValueError: mech-client cannot resolve the chain id payments use
        (a malformed `MECHX_LEDGER_CHAIN_ID` or `MECHX_GAS_LIMIT`), so the
        table cannot be read; never read as "none deployed".
    """
    # pylint: disable=import-outside-toplevel
    from mech_client import balance_tracker, payment_token
    from mech_client.infrastructure.config import PaymentType
    from mech_client.infrastructure.config.loader import get_chain_id, ledger_chain_id

    name = MECH_CLIENT_CHAIN_NAMES.get(chain.lower(), chain.lower())
    try:
        get_chain_id(name)
    except ValueError:  # a chain mech-client does not know
        return {}
    # the lookups below read the same environment, so past this line their
    # ValueError can only mean "not deployed on this chain"
    ledger_chain_id(name)
    trackers: dict[str, str] = {}
    for payment_type in PaymentType:
        try:
            tracker = balance_tracker(name, payment_type)
            token = payment_token(payment_type, name)
        except ValueError:  # not deployed on this chain
            continue
        if tracker is not None:
            trackers[tracker.lower()] = (token or "native").lower()
    return trackers


def token_approve_targets(chain: str) -> dict[str, str]:
    """Payment token -> its mech balance tracker for one chain, from mech-client.

    In restricted mode the safe may `approve` these tokens, but only with the
    tracker as spender (the guard enforces that). The inverse of
    `prepaid_balance_trackers`' token entries, so the guard's approve targets
    and the intent gate's trackers are one reading of mech-client's table.
    Fail closed to empty, logged, if mech-client cannot be read.
    """
    try:
        trackers = prepaid_balance_trackers(chain)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("could not load mech token payment addresses: %s", e)
        return {}
    return {asset: tracker for tracker, asset in trackers.items() if asset != "native"}


def default_whitelist() -> dict[str, tuple[str, ...]]:
    """Marketplace contracts merged with the operator's extra defaults."""
    merged: dict[str, set[str]] = {
        chain: set(addresses) for chain, addresses in _mech_system_addresses().items()
    }
    for chain, addresses in EXTRA_DEFAULT_WHITELIST.items():
        merged.setdefault(chain, set()).update(a.lower() for a in addresses)
    return {chain: tuple(sorted(addresses)) for chain, addresses in merged.items()}


def defaults() -> Settings:
    """Return the default state: unrestricted, marketplaces whitelisted."""
    return Settings(
        protected=Protected(mode=MODE_UNRESTRICTED, whitelist=default_whitelist())
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

    Distinct from the OSErrors of the read path (which degrade to the
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

    def __init__(
        self,
        path: Path,
        mac_key: bytes,
        activity: ActivityLog,
        unavailable: t.Callable[[str], UnavailableReason | None] = lambda _: None,
    ) -> None:
        """Initialize; `unavailable` names why a harness is unusable here, or None."""
        self._path = path
        self._mac_key = mac_key
        self._activity = activity
        self._unavailable = unavailable
        self._lock = threading.Lock()
        self._expected_mac: str | None = None
        self._degraded: str | None = None
        self._unusable: str | None = None

    def load(self) -> Settings:
        """Return the verified settings, restoring defaults on any problem."""
        with self._lock:
            return self._usable(self._load())

    def unavailable_reason(self, harness: str) -> UnavailableReason | None:
        """Why this instance cannot use `harness`, or None when it can."""
        return self._unavailable(harness)

    def require_available(self, harness: str) -> None:
        """Refuse a harness this instance cannot use.

        :raises ValueError: naming the reason, for PATCH /settings and
            POST /session alike.
        """
        reason = self.unavailable_reason(harness)
        if reason is not None:
            raise ValueError(f"harness {harness} is unavailable: {reason}")

    def harnesses(self) -> list[dict]:
        """Every harness with its availability on this instance."""
        return harness_options(self._unavailable)

    def _usable(self, settings: Settings) -> Settings:
        """Swap a saved harness this instance cannot use for the default.

        A settings file copied from another machine or chain is the usual
        cause. The file keeps its value, so it applies again where it can.
        """
        reason = self.unavailable_reason(settings.harness)
        unusable = None if reason is None else f"{settings.harness}:{reason}"
        # load() runs on every guarded request: say it once per condition
        if unusable is not None and unusable != self._unusable:
            logger.warning(
                "saved harness %s is unavailable here (%s); using %s",
                settings.harness,
                reason,
                DEFAULT_HARNESS,
            )
        self._unusable = unusable
        if reason is None:
            return settings
        return Settings(protected=settings.protected, harness=DEFAULT_HARNESS)

    def patch(self, patch: t.Mapping) -> PatchResult:
        """Merge a partial canonical-shaped patch and persist the result.

        One lock spans the read-merge-write: concurrent patches (the UI has
        independent protected and harness forms) must not lose an update.
        Returns both sides of the change, so a caller can audit what actually
        moved rather than what was submitted.
        :raises ValueError: on invalid replacements, or a harness this
        instance cannot use;
        :raises SettingsPersistError: when the merged settings cannot be
        persisted — an explicit change must never claim success while the disk
        disagrees (unlike the load path, which degrades to its in-memory value).
        """
        harness = patch.get("harness")
        if harness is not None:
            self.require_available(validate_harness(harness))
        with self._lock:
            # merged onto the stored harness, not the usable one: a patch of
            # something else must not overwrite a harness unavailable only here
            stored = self._load()
            updated = stored.merged(patch)
            try:
                self._save(updated)
            except OSError as e:
                self._activity.record(
                    "settings_persist_failed", path=str(self._path), error=str(e)
                )
                raise SettingsPersistError(str(e)) from e
            return PatchResult(
                previous=self._usable(stored), updated=self._usable(updated)
            )

    def _record_once(self, condition: str, kind: str, **fields: object) -> None:
        """Audit a degraded-state transition once per episode, not per read.

        The activity log is history, and an unhealed condition re-entering
        this path on every signing request would bury that history under
        identical records until rotation drops it. One record marks the
        transition in; a verified load re-arms the next one.
        """
        if self._degraded == condition:
            return
        self._degraded = condition
        self._activity.record(kind, **fields)

    def _load(self) -> Settings:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._record_once(
                "missing", "settings_reset", path=str(self._path), reason="missing"
            )
            return self._reset(defaults())  # nothing to lose: create it
        except OSError as e:
            # An unreadable file is NOT a missing one, and must not be written
            # over: another process or a backup tool briefly holding the file
            # raises here, and resetting would destroy the operator's mode and
            # harness — permanently, silently — over a condition that clears by
            # itself. Serve the in-memory defaults instead, until it reads
            # again. Raising is not an option either, since every guarded
            # action loads the settings.
            logger.warning(
                "settings file %s could not be read (%s); using defaults until it can be",
                self._path,
                e,
            )
            self._record_once(
                "unreadable", "settings_unreadable", path=str(self._path), error=str(e)
            )
            return defaults()
        payload = self._parse(raw)
        verified = self._verify(payload)
        if verified is not None:
            self._degraded = None  # healthy again: re-arm transition records
            return verified
        migrated = self._verify_legacy(payload)
        if migrated is not None:
            logger.info(
                "settings file %s predates the harness MAC; migrated with %s",
                self._path,
                migrated.harness,
            )
            return self._reset(migrated)
        logger.warning(
            "settings file %s failed verification; restoring defaults", self._path
        )
        self._record_once("tampered", "settings_tampered", path=str(self._path))
        return self._reset(defaults())

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

    def _mac(self, payload: dict, fields: tuple[str, ...] = MAC_FIELDS) -> str:
        canonical = json.dumps(
            {k: payload.get(k) for k in fields},
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

    def _verify_legacy(self, payload: dict) -> Settings | None:
        """Verify a version-1 file, MAC'd before the harness was; None otherwise.

        Only on the first load of a run, as for any file not written by this
        process. Its harness was never covered, but no released version-1 file
        could hold ocb_cli, so any other harness is kept and ocb_cli (which only
        a write outside Connect can have put there) becomes the default.
        """
        if payload.get("version") != 1 or self._expected_mac is not None:
            return None
        if not hmac.compare_digest(
            str(payload.get("mac", "")), self._mac(payload, LEGACY_MAC_FIELDS)
        ):
            return None
        try:
            protected = Protected.from_raw(payload["protected"])
        except (ValueError, KeyError, TypeError, AttributeError):
            return None
        harness = _harness_or_default(payload.get("harness", DEFAULT_HARNESS))
        if harness == HARNESS_OCB_CLI:
            harness = DEFAULT_HARNESS
        return Settings(protected=protected, harness=harness)
