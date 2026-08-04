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

"""The agent workspace (STORE_PATH): what the Claude session opens into.

STORE_PATH is the persistent_data dir Pearl reserves for this service. The
Workspace owns it: it provisions our MCP entry in .mcp.json (rotating the token
each run) and overwrites our bundled skill, leaving every other file alone; it
knows whether it is fit to open a session into, and re-attempts a failed
provisioning while it is not; and it opens the session itself.

What stays outside the class is what is not about *a* workspace: where the
bundle lives, the MCP URL, the harness-to-deep-link registry, the OS call that
hands a URL to a URL handler, and the environment scrub that keeps our own
packaging out of the session it starts.
"""

import json
import logging
import os
import shutil
import subprocess  # nosec B404
import sys
import threading
import typing as t
from pathlib import Path
from urllib.parse import quote

from connect.config import AGENT_HTTP_PORT, BIND_HOST
from connect.settings import (
    DEFAULT_HARNESS,
    HARNESS_CLAUDE_CODE_CLI,
    HARNESS_CLAUDE_CODE_DESKTOP,
)

logger = logging.getLogger("agent")

MCP_SERVER_NAME = "pearl-connect"
MCP_CONFIG_FILE = ".mcp.json"
# Per-server tool budget, in ms. Three separate harness limits would otherwise
# abort our slowest tool (mech_request) long before it returns: the per-call
# wall clock, the 60s first-byte timer an HTTP MCP server gets, and its
# 5-minute idle window. This one field raises all three, for our server alone —
# a mech request already paid for on-chain must not be abandoned mid-flight.
#
# The budget is TWICE mech.MAX_DELIVERY_TIMEOUT plus margin, because
# mech-client's on-chain watcher spends that timeout twice in sequence: it
# waits for the marketplace to name a delivering mech, then restarts its clock
# to scan that mech's logs. A budget covering only one pass would abort inside
# the second. test_workspace holds the two constants in step.
MCP_TOOL_TIMEOUT_MS = 2_100_000
# where a bundled agent-UI build is dropped in (see docs/agent-ui.md)
UI_SUBDIR = "ui"
UI_INDEX = "index.html"
SKILLS_SUBDIR = Path(".claude") / "skills"
CLAUDE_SETTINGS_FILE = Path(".claude") / "settings.json"
# the harness itself reads .mcp.json; the model never needs to, and reading
# it would put the bearer token into the session transcript
TOKEN_DENY_RULES = ("Read(./.mcp.json)",)
# a `git init` in the workspace must never be able to stage the token
GITIGNORE_ENTRIES = (".mcp.json",)

# Loader variables our PyInstaller bootloader leaks: its extraction directory
# leads LD_LIBRARY_PATH and ships an older libcrypto, so a session inheriting
# them cannot start the distro `node` — killing every node-based hook (loudly)
# and MCP server (silently: it just never appears in the tool list). Restoring
# LD_LIBRARY_PATH_ORIG, PyInstaller's advice, is wrong here: under Pearl the
# AppImage poisons that one too, with the same libcrypto. DYLD_* is the macOS
# spelling of the same leak — we ship mac binaries too, though nothing there
# leans on the scrub: `open` hands the launch to launchd, which gives the app
# its own environment, and SIP strips DYLD_* from protected binaries anyway.
# See OPE-1866.
LOADER_ENV_VARS = (
    "LD_LIBRARY_PATH",
    "LD_LIBRARY_PATH_ORIG",
    "DYLD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH_ORIG",
)
LOADER_ENV_PREFIXES = ("_PYI_",)


class LaunchError(Exception):
    """A Claude Code session could not be opened in the requested harness."""


def assets_dir() -> Path:
    """Bundled assets location — PyInstaller extracts to sys._MEIPASS."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    for candidate in (base / "assets", base / "connect" / "assets"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"bundled assets not found under {base}")


def mcp_url() -> str:
    """Return the MCP endpoint URL for .mcp.json.

    Keep the trailing slash. The server serves MCP at /mcp/, and the agent-UI
    route answers GET on /mcp, so a POST to /mcp (no slash) returns 405 and the
    connection fails. /mcp/ reaches the MCP server directly.
    """
    return f"http://{BIND_HOST}:{AGENT_HTTP_PORT}/mcp/"


def ui_build_dir() -> Path | None:
    """Return the bundled agent UI, or None if no build has been dropped in.

    The UI ships as a static build (index.html + its assets) under
    assets/ui — see docs/agent-ui.md.

    A directory with no index.html is not a decision anyone made. In a packaged
    binary it is a packaging failure, and answering None for it as quietly as
    for "no UI was intended" would take the operator's only guardrail control
    surface off the air while the server went on reporting itself healthy.
    """
    try:
        candidate = assets_dir() / UI_SUBDIR
    except FileNotFoundError:  # no bundle at all (a source checkout under test)
        return None
    if not candidate.is_dir():
        return None  # no UI: the API serves on its own, as designed
    if (candidate / UI_INDEX).is_file():
        return candidate
    logger.warning(
        "the agent UI directory %s has no %s — serving the API without a UI. "
        "In a packaged build this is a packaging bug, not a configuration",
        candidate,
        UI_INDEX,
    )
    return None


def load_ui_bundle() -> dict[str, bytes] | None:
    """Read the agent UI into memory once, at boot, or None if there is none.

    Serving the files from disk would re-read them on every request, and in the
    packaged binary they live in PyInstaller's extraction directory — writable
    by the same OS user the agent session runs as. That page is where the
    operator types the keystore password: the one secret this whole design
    keeps from the agent. A session that rewrote index.html between two visits
    would harvest it, with no restart to notice.

    Reading the bundle before any session exists is what makes the page the
    operator sees the page we shipped. It does not make a compromised session
    harmless — one that can write there can also replace the binary — but it
    closes the cheapest version of that attack, the one needing no restart.
    """
    directory = ui_build_dir()
    if directory is None:
        return None
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


# Pre-filled into the prompt box of a freshly opened session. A deep link only
# fills the box — the operator reads it and presses Enter — so this reads as the
# operator's own opening question, not something we sent. CLAUDE.md tells the
# agent how to answer it: with a short, concrete tour of what it can be asked.
FIRST_PROMPT = "hi, what can you do?"


def desktop_deep_link(store_path: Path) -> str:
    """Claude Code desktop-app deep link, opening prompt pre-filled."""
    return f"claude://code/new?folder={quote(str(store_path))}&q={quote(FIRST_PROMPT)}"


def cli_deep_link(store_path: Path) -> str:
    """Claude Code CLI deep link, opening prompt pre-filled."""
    return f"claude-cli://open?cwd={quote(str(store_path))}&q={quote(FIRST_PROMPT)}"


# The one place a harness gets a way to be opened. settings.HARNESSES says
# which harnesses the operator may choose; a test pins these keys against it,
# because a harness that can be chosen but never opened is a dead end the
# operator only discovers when a session refuses to start.
DEEP_LINKS: dict[str, t.Callable[[Path], str]] = {
    HARNESS_CLAUDE_CODE_DESKTOP: desktop_deep_link,
    HARNESS_CLAUDE_CODE_CLI: cli_deep_link,
}


class Workspace:
    """The agent's workspace: provisioned, kept usable, and opened into.

    Readiness is not a flag someone sets — it is whether provisioning has
    succeeded. Everything that needs the store path and the run's token lives
    here with it, so no caller has to thread them around, and none of them can
    provision the workspace behind the back of the answer we give Pearl about
    our health.
    """

    def __init__(self, store_path: Path, token: str) -> None:
        """Start unprovisioned: the first ensure() is what makes it real."""
        self.path = store_path
        self._token = token
        self._lock = threading.Lock()
        self._reason: str | None = "the workspace has not been provisioned yet"

    @property
    def reason(self) -> str | None:
        """Why a session cannot be opened here, or None when one can.

        Reading it never provisions: whoever decides what to *report* should not
        be the one who changes what is true.
        """
        return self._reason

    def ensure(self) -> bool:
        """Whether the workspace is usable, re-attempting a failed provisioning.

        A boot-time failure is often transient — a store volume mounting late, a
        previous run still holding .mcp.json — and provisioning is idempotent.
        Retrying while unusable is what lets the server heal: without it, one
        unlucky boot reports unhealthy until somebody restarts the process,
        which is the restart loop the on-demand design exists to avoid, merely
        driven by the health poller rather than by a crash.
        """
        if self._reason is None:
            return True
        with self._lock:
            if self._reason is None:  # another poller got there first
                return True
            try:
                self._provision()
            except Exception as e:  # pylint: disable=broad-exception-caught
                self._reason = str(e)
                logger.warning("workspace at %s is unusable: %s", self.path, e)
                return False
            self._reason = None
            logger.info("workspace provisioned at %s", self.path)
            return True

    def deep_link(self, harness: str = DEFAULT_HARNESS) -> str:
        """Return the deep link that opens this workspace in the given harness.

        :raises ValueError: on a harness with no deep link.
        """
        try:
            build = DEEP_LINKS[harness]
        except KeyError as e:
            raise ValueError(f"no deep link for harness {harness!r}") from e
        return build(self.path)

    def open_session(
        self, harness: str = DEFAULT_HARNESS, *, fallback: bool = False
    ) -> str:
        """Open a Claude Code session here; return the harness it opened in.

        Success means the URL handler accepted the deep link, which is as much
        as the OS tells us: `xdg-open` (and `open`) can exit 0 without any
        handler having actually opened a window. So a "launched" answer is a
        best effort, not a proof that the session appeared on screen.

        `fallback` says the harness was ours to pick, not the operator's: try
        it first, then the others. A caller who *names* a harness gets that one
        or an error, because naming one is a choice and quietly opening the
        other Claude Code would make the choice a lie. But an unnamed one is
        only DEFAULT_HARNESS, our guess — and Pearl and the agent UI both
        launch without naming one, so on a machine with only the CLI installed
        that guess was the whole reason no session ever opened (OPE-1867).

        :raises ValueError: on an unknown harness;
        :raises LaunchError: when none of the deep links tried would open.
        """
        order = [harness]
        if fallback:
            order += [known for known in DEEP_LINKS if known != harness]
        for candidate in order:
            url = self.deep_link(candidate)  # only order[0] can be unknown
            if not _open_url(url):
                continue
            logger.info("launched %s via %s", candidate, url.split("?", maxsplit=1)[0])
            if candidate != harness:
                logger.info(
                    "%s would not open, so the session went to %s instead — "
                    "set the harness in the agent UI to stop us guessing",
                    harness,
                    candidate,
                )
            return candidate
        # "change the harness" is no way out on a machine where both have
        # already been tried, so the exhausted case names what it tried instead
        if len(order) == 1:
            reason = (
                f"Could not open {harness} via its deep link — is it installed? "
                f"If you use the other Claude Code, change the harness in the "
                f"agent UI."
            )
        else:
            reason = (
                f"Could not open a Claude Code session — none of "
                f"{', '.join(order)} answered its deep link. Is Claude Code "
                f"installed?"
            )
        raise LaunchError(f"{reason} The workspace is at {self.path}")

    def _provision(self) -> None:
        """Write our files into the workspace, leaving every other one alone."""
        self.path.mkdir(parents=True, exist_ok=True)
        self._write_mcp_config()
        self._write_gitignore()
        self._write_claude_settings()
        self._install_claude_md()
        self._install_skills()

    def _install_claude_md(self) -> None:
        """Overwrite CLAUDE.md (the agent's identity/context brief) from assets.

        :raises FileNotFoundError: when the bundled CLAUDE.md is absent.
        """
        source = assets_dir() / "CLAUDE.md"
        if not source.exists():
            raise FileNotFoundError(f"bundled CLAUDE.md not found under {source}")
        shutil.copyfile(source, self.path / "CLAUDE.md")

    def _write_mcp_config(self) -> None:
        """Merge our server entry into .mcp.json (0600), preserving other entries."""
        path = self.path / MCP_CONFIG_FILE
        config: dict = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    config = existing
            except json.JSONDecodeError:
                logger.warning("existing %s is invalid JSON; rewriting it", path)
        config.setdefault("mcpServers", {})[MCP_SERVER_NAME] = {
            "type": "http",
            "url": mcp_url(),
            "headers": {"Authorization": f"Bearer {self._token}"},
            "timeout": MCP_TOOL_TIMEOUT_MS,
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.unlink(missing_ok=True)  # a stale tmp may have looser permissions
        tmp.touch(mode=0o600)
        tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(path)

    def _write_gitignore(self) -> None:
        """Keep the token file out of any repo the agent may init here."""
        path = self.path / ".gitignore"
        existing = (
            path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        )
        missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
        if not missing:
            return
        lines = existing + ["# connect: never commit the signer token"] + missing
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _write_claude_settings(self) -> None:
        """Merge our token-hygiene deny rules into .claude/settings.json.

        Denying the Read tool keeps the token out of session transcripts; the
        Claude Code harness parses .mcp.json itself, the model never needs it.
        User-added settings in the file are preserved.
        """
        path = self.path / CLAUDE_SETTINGS_FILE
        config: dict = {}
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    config = existing
            except json.JSONDecodeError:
                # the file is user-owned config: one typo must not wipe it —
                # keep the broken content recoverable next to the rewrite
                backup = path.with_suffix(".json.bak")
                path.replace(backup)
                logger.warning(
                    "existing %s is invalid JSON; backed up to %s and rewriting",
                    path,
                    backup,
                )
        deny = config.setdefault("permissions", {}).setdefault("deny", [])
        for rule in TOKEN_DENY_RULES:
            if rule not in deny:
                deny.append(rule)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def _install_skills(self) -> None:
        """Overwrite our skills from the bundle; user files elsewhere are untouched."""
        source = assets_dir() / "skills"
        target_root = self.path / SKILLS_SUBDIR
        target_root.mkdir(parents=True, exist_ok=True)
        for skill_dir in source.iterdir():
            if not skill_dir.is_dir():
                logger.warning(
                    "skipping non-directory %s under bundled skills", skill_dir
                )
                continue
            target = target_root / skill_dir.name
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(
                skill_dir, target, ignore=shutil.ignore_patterns("__pycache__")
            )


def harness_env() -> dict[str, str]:
    """Our environment minus the loader variables our packaging leaks.

    Everything the session goes on to start — hooks, MCP servers, whatever it
    shells out to — inherits this. See LOADER_ENV_VARS. What was dropped is
    logged, because an operator who set one of these on purpose would otherwise
    have nothing to go on: the scrub is invisible from inside the session.
    """
    scrubbed = {
        key: value
        for key, value in os.environ.items()
        if key not in LOADER_ENV_VARS and not key.startswith(LOADER_ENV_PREFIXES)
    }
    dropped = sorted(set(os.environ) - set(scrubbed))
    if dropped:
        logger.info(
            "not passing %s to the session — our packaging leaks them; "
            "to set one deliberately, use the workspace's .claude/settings.json",
            ", ".join(dropped),
        )
    return scrubbed


def _open_url(url: str) -> bool:
    try:
        if sys.platform == "darwin":  # pragma: no cover — macOS only
            args = ["open", url]
        elif sys.platform == "win32":  # pragma: no cover — Windows only
            # os.startfile takes no environment, and there is no LD_/DYLD_
            # loader path here — so no scrub, and nothing claiming one either
            os.startfile(url)  # type: ignore[attr-defined] # nosec B606
            return True
        else:  # pragma: no cover — Linux/Unix only
            args = ["xdg-open", url]
        result = subprocess.run(  # nosec B603, B607
            args, capture_output=True, timeout=15, check=False, env=harness_env()
        )
        if result.returncode == 0:
            return True
        # Loudly, and at a level the default config shows. This is the only
        # place the OS says *why* a link did not open, and the caller turns
        # every failure into the same "is Claude Code installed?" guess — with
        # a fallback trying two links, a silent first refusal would leave the
        # operator's actual problem nowhere to be read.
        detail = (result.stderr or b"").decode(errors="replace").strip()
        logger.warning(
            "deep link %s was refused (exit %s)%s",
            url.split("?", maxsplit=1)[0],
            result.returncode,
            f": {detail[:200]}" if detail else "",
        )
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("deep link %s failed: %s", url.split("?", maxsplit=1)[0], e)
        return False
