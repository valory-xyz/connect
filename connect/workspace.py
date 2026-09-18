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

"""The agent workspace (STORE_PATH): what the agent session opens into.

STORE_PATH is the persistent_data dir Pearl reserves for this service. The
Workspace owns it: it provisions our MCP entry in .mcp.json and
.codex/config.toml (rotating the token each run) and overwrites our bundled
brief and skills, leaving every other file alone; it knows whether it is fit
to open a session into, and re-attempts a failed provisioning while it is not;
and it opens the session itself.

What stays outside the class is what is not about *a* workspace: where the
bundle lives, the MCP URL, the harness-to-launcher registries, the OS calls
that hand a URL to a URL handler or a command to a terminal, and the
environment scrub that keeps our own packaging out of the session it starts.
"""

import json
import logging
import os
import shlex
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import threading
import tomllib
import typing as t
from pathlib import Path
from urllib.parse import quote

import tomli_w

from connect.config import AGENT_HTTP_PORT, BIND_HOST
from connect.settings import (
    DEFAULT_HARNESS,
    HARNESS_CLAUDE_CODE_CLI,
    HARNESS_CLAUDE_CODE_DESKTOP,
    HARNESS_CODEX_CLI,
    HARNESS_CODEX_DESKTOP,
)

logger = logging.getLogger("agent")

MCP_SERVER_NAME = "pearl-connect"
MCP_CONFIG_FILE = ".mcp.json"
CODEX_CONFIG_FILE = Path(".codex") / "config.toml"
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
BRIEF_FILES = ("CLAUDE.md", "AGENTS.md")
AGENT_DIRS = (Path(".claude"), Path(".agents"))
CLAUDE_SETTINGS_FILE = Path(".claude") / "settings.json"
# the harnesses read these themselves; the model never needs to, and reading
# one would put the bearer token into the session transcript
TOKEN_DENY_RULES = ("Read(./.mcp.json*)", "Read(./.codex/config.toml*)")
# a `git init` in the workspace must never be able to stage the token, nor
# the virtualenv the connect-polymarket skill builds at the workspace root
GITIGNORE_ENTRIES = (".mcp.json*", ".codex/config.toml*", ".venv/")
# picked, not tuned: refusals seen exit in ms; still running by then means launching
LAUNCH_SETTLE_SECONDS = 2.0
LAUNCH_PROBE_SECONDS = 10.0
# xdg-open's generic fallback runs the handler in the foreground until it exits
URL_OPENER_SECONDS = 15.0

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
    """An agent session could not be opened in the requested harness."""


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
# operator's own opening question, not something we sent. The brief tells the
# agent how to answer it: with a short, concrete tour of what it can be asked.
FIRST_PROMPT = "hi, what can you do?"


def desktop_deep_link(store_path: Path) -> str:
    """Claude Code desktop-app deep link, opening prompt pre-filled."""
    return f"claude://code/new?folder={quote(str(store_path))}&q={quote(FIRST_PROMPT)}"


def cli_deep_link(store_path: Path) -> str:
    """Claude Code CLI deep link, opening prompt pre-filled."""
    return f"claude-cli://open?cwd={quote(str(store_path))}&q={quote(FIRST_PROMPT)}"


def codex_desktop_deep_link(store_path: Path) -> str:
    """Codex desktop-app deep link, opening prompt pre-filled."""
    return (
        f"codex://threads/new?path={quote(str(store_path))}"
        f"&prompt={quote(FIRST_PROMPT)}"
    )


# The one place a harness gets a way to be opened: a deep link, or a command
# for a terminal when the harness registers no URL handler. settings.HARNESSES
# says which harnesses the operator may choose; a test pins these keys against
# it, because a harness that can be chosen but never opened is a dead end the
# operator only discovers when a session refuses to start.
DEEP_LINKS: dict[str, t.Callable[[Path], str]] = {
    HARNESS_CLAUDE_CODE_DESKTOP: desktop_deep_link,
    HARNESS_CLAUDE_CODE_CLI: cli_deep_link,
    HARNESS_CODEX_DESKTOP: codex_desktop_deep_link,
}
TERMINAL_COMMANDS: dict[str, str] = {HARNESS_CODEX_CLI: "codex"}

# shells that take `-lic`; tcsh, fish and friends do not
POSIX_SHELLS = ("bash", "zsh", "ksh", "mksh", "dash", "sh")
LINUX_TERMINALS: dict[str, t.Callable[[str, list[str]], list[str]]] = {
    "ptyxis": lambda cwd, argv: ["--new-window", "-d", cwd, "-x", shlex.join(argv)],
    "gnome-terminal": lambda cwd, argv: [f"--working-directory={cwd}", "--", *argv],
    "konsole": lambda cwd, argv: ["--workdir", cwd, "-e", *argv],
    "xfce4-terminal": lambda cwd, argv: [f"--working-directory={cwd}", "-x", *argv],
    "kitty": lambda cwd, argv: ["--directory", cwd, *argv],
    "alacritty": lambda cwd, argv: ["--working-directory", cwd, "-e", *argv],
    "wezterm": lambda cwd, argv: ["start", "--cwd", cwd, "--", *argv],
    "xterm": lambda cwd, argv: ["-e", *argv],
}


def terminal_launches(store_path: Path, command: str) -> list[list[str]]:
    """Command lines that each open a terminal running `command` in store_path."""
    cwd = str(store_path)
    if sys.platform == "darwin":
        return [["open", "-a", "Terminal", _command_file(cwd, command)]]
    if sys.platform == "win32":
        return [
            ["wt.exe", "-d", cwd, "cmd.exe", "/k", command],
            ["cmd.exe", "/c", "start", "", "/d", cwd, "cmd.exe", "/k", command],
        ]
    # the cd is for client/server terminals, whose window ignores our cwd
    argv = [_login_shell(), "-lic", f'cd -- "$1" && exec {command}', command, cwd]
    wanted = os.environ.get("TERMINAL")
    # only a name from our table, so $TERMINAL can pick a terminal but never a program
    first = (wanted,) if wanted in LINUX_TERMINALS else ()
    if wanted and not first:
        logger.warning(
            "ignoring $TERMINAL: Connect drives only %s", ", ".join(LINUX_TERMINALS)
        )
    launches: list[list[str]] = []
    seen: set[str] = set()
    for name in (*first, "x-terminal-emulator", *LINUX_TERMINALS):
        found = shutil.which(name)
        if found is None:
            continue
        real = os.path.realpath(found)
        if real in seen:
            continue
        seen.add(real)
        # x-terminal-emulator wrappers take xterm's `-e program args...` (Debian policy)
        build = LINUX_TERMINALS.get(Path(real).name, LINUX_TERMINALS["xterm"])
        launches.append([found, *build(cwd, argv)])
    return launches


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
        """Open an agent session here; return the harness it opened in.

        Success means the URL handler accepted the deep link, or the terminal
        started, which is as much as the OS tells us: `xdg-open` (and `open`)
        can exit 0 without any handler having actually opened a window. So a
        "launched" answer is a best effort, not a proof that the session
        appeared on screen.

        `fallback` says the harness was ours to pick, not the operator's: try
        it first, then the others. A caller who *names* a harness gets that one
        or an error, because naming one is a choice and quietly opening another
        harness would make the choice a lie. But an unnamed one is only
        DEFAULT_HARNESS, our guess — and Pearl and the agent UI both launch
        without naming one, so on a machine with only the CLI installed that
        guess was the whole reason no session ever opened (OPE-1867).

        :raises ValueError: on an unknown harness;
        :raises LaunchError: when none of the harnesses tried would open.
        """
        order = [harness]
        if fallback:
            order += [
                known for known in (*DEEP_LINKS, *TERMINAL_COMMANDS) if known != harness
            ]
        for candidate in order:
            if candidate in TERMINAL_COMMANDS:
                via = "a terminal"
                command = TERMINAL_COMMANDS[candidate]
                opened = _resolves(command) and _open_terminal(self.path, command)
            else:
                url = self.deep_link(candidate)  # only order[0] can be unknown
                via = url.split("?", maxsplit=1)[0]
                opened = _open_url(url, self.path)
            if not opened:
                continue
            logger.info("launched %s via %s", candidate, via)
            if candidate != harness:
                logger.info(
                    "%s would not open, so the session went to %s instead — "
                    "if that preference is stale, update the harness in the "
                    "agent UI",
                    harness,
                    candidate,
                )
            return candidate
        # "change the harness" is no way out on a machine where every harness
        # has already been tried, so the exhausted case names what it tried
        if not fallback:
            reason = (
                f"Could not open {harness} — is it installed? "
                f"If you use another harness, change the harness in the agent UI."
            )
        else:
            reason = (
                f"Could not open an agent session — none of {', '.join(order)} "
                f"would open. Is Claude Code or Codex installed?"
            )
        raise LaunchError(f"{reason} The workspace is at {self.path}")

    def _provision(self) -> None:
        """Write our files into the workspace, leaving every other one alone."""
        self.path.mkdir(parents=True, exist_ok=True)
        self._write_mcp_config()
        self._write_codex_config()
        self._write_gitignore()
        self._write_claude_settings()
        self._install_brief()
        self._install_skills()
        self._install_lib()

    def _install_brief(self) -> None:
        """Overwrite the agent's context brief (CLAUDE.md, AGENTS.md) from assets.

        :raises FileNotFoundError: when the bundled CLAUDE.md is absent.
        """
        source = assets_dir() / "CLAUDE.md"
        if not source.exists():
            raise FileNotFoundError(f"bundled CLAUDE.md not found under {source}")
        for name in BRIEF_FILES:
            shutil.copyfile(source, self.path / name)

    def _write_mcp_config(self) -> None:
        """Merge our server entry into .mcp.json (0600), preserving other entries."""
        path = self.path / MCP_CONFIG_FILE
        config = _load_config(path, json.loads, "mcpServers")
        config.setdefault("mcpServers", {})[MCP_SERVER_NAME] = {
            "type": "http",
            "url": mcp_url(),
            "headers": {"Authorization": f"Bearer {self._token}"},
            "timeout": MCP_TOOL_TIMEOUT_MS,
        }
        _write_private(path, json.dumps(config, indent=2))

    def _write_codex_config(self) -> None:
        """Merge our server entry into .codex/config.toml (0600), keeping the rest."""
        path = self.path / CODEX_CONFIG_FILE
        config = _load_config(
            path, tomllib.loads, "mcp_servers", "sandbox_workspace_write"
        )
        config.setdefault("mcp_servers", {})[MCP_SERVER_NAME] = {
            "url": mcp_url(),
            "http_headers": {"Authorization": f"Bearer {self._token}"},
            "tool_timeout_sec": MCP_TOOL_TIMEOUT_MS // 1000,
        }
        config.setdefault("sandbox_workspace_write", {}).setdefault(
            "network_access", True
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(path, tomli_w.dumps(config))

    def _write_gitignore(self) -> None:
        """Keep the token file out of any repo the agent may init here."""
        path = self.path / ".gitignore"
        existing = (
            path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        )
        missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
        if not missing:
            return
        lines = (
            existing + ["# connect: never commit the signer token or venv"] + missing
        )
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _write_claude_settings(self) -> None:
        """Merge our token-hygiene deny rules into .claude/settings.json.

        Denying the Read tool keeps the token out of session transcripts; the
        Claude Code harness parses .mcp.json itself, the model never needs it.
        User-added settings in the file are preserved.
        """
        path = self.path / CLAUDE_SETTINGS_FILE
        config = _load_config(path, json.loads, "permissions")
        deny = config.setdefault("permissions", {}).setdefault("deny", [])
        for rule in TOKEN_DENY_RULES:
            if rule not in deny:
                deny.append(rule)
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(path, json.dumps(config, indent=2))

    def _install_lib(self) -> None:
        """Overwrite the shared modules our skills import, beside each skills dir."""
        for agent_dir in AGENT_DIRS:
            _replace_tree(assets_dir() / "lib", self.path / agent_dir / "lib")

    def _install_skills(self) -> None:
        """Overwrite our skills from the bundle; user files elsewhere are untouched."""
        skills = []
        for skill_dir in (assets_dir() / "skills").iterdir():
            if not skill_dir.is_dir():
                logger.warning(
                    "skipping non-directory %s under bundled skills", skill_dir
                )
                continue
            skills.append(skill_dir)
        for agent_dir in AGENT_DIRS:
            target_root = self.path / agent_dir / "skills"
            target_root.mkdir(parents=True, exist_ok=True)
            for skill_dir in skills:
                _replace_tree(skill_dir, target_root / skill_dir.name)


def _remove(target: Path) -> None:
    """Delete whatever is at target; a link is unlinked, never followed."""
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.exists():
        shutil.rmtree(target)


def _replace_tree(source: Path, target: Path) -> None:
    """Replace target, whatever it currently is, with a copy of source."""
    _remove(target)
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))


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
            "to set one deliberately, use the workspace's .claude/settings.json "
            "or .codex/config.toml",
            ", ".join(dropped),
        )
    return scrubbed


def _load_config(path: Path, loads: t.Callable[[str], t.Any], *tables: str) -> dict:
    """Read a config we merge into; set aside one we cannot, rather than fail.

    It is the operator's file too, so a broken one is kept as `.bak`, not
    wiped; failing instead would leave the server unhealthy on every retry.
    """
    try:
        config = loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except ValueError as e:  # parse and decode errors alike
        problem = str(e)
    else:
        if isinstance(config, dict) and all(
            isinstance(config.get(table, {}), dict) for table in tables
        ):
            return config
        problem = "not the expected tables"
    backup = path.with_name(f"{path.name}.bak")
    path.replace(backup)
    logger.warning(
        "existing %s is unusable (%s); backed up to %s and rewriting",
        path,
        problem,
        backup,
    )
    return {}


def _write_private(path: Path, text: str) -> None:
    """Atomically replace a file, readable by its owner alone."""
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.unlink(missing_ok=True)  # a stale tmp may have looser permissions
    tmp.touch(mode=0o600)
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def _login_shell() -> str:
    """Return the operator's login shell if it takes `-lic`, else bash, else sh."""
    import pwd  # pylint: disable=import-outside-toplevel # POSIX only

    try:
        shell = pwd.getpwuid(os.getuid()).pw_shell
    except KeyError:
        shell = ""
    if Path(shell).name in POSIX_SHELLS:
        return shell
    # bash, not sh: dash never reads the ~/.bashrc that puts codex on PATH
    return shutil.which("bash") or "/bin/sh"


def _command_file(cwd: str, command: str) -> str:
    """Write a Terminal .command file that runs `command` in cwd, then deletes itself."""
    fd, path = tempfile.mkstemp(prefix="connect-", suffix=".command")
    with os.fdopen(fd, "w", encoding="utf-8") as script:
        script.write(
            f'#!/bin/sh\nrm -f "$0"\ncd {shlex.quote(cwd)} && exec {command}\n'
        )
    os.chmod(path, 0o700)
    return path


def _resolves(command: str) -> bool:
    """Whether `command` resolves where a terminal session would run it."""
    if sys.platform == "win32":
        return shutil.which(command) is not None
    try:
        code = subprocess.run(  # nosec B603
            [_login_shell(), "-lic", f"command -v {command}"],
            env=harness_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=LAUNCH_PROBE_SECONDS,
            check=False,
        ).returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.warning(
            "could not check that %s resolves (%s); trying anyway", command, e
        )
        return True
    if code:
        logger.warning(
            "%s is not on the login shell's PATH; not opening a terminal", command
        )
    return code == 0


def _launch(
    argv: list[str], env: dict[str, str], wait: float, cwd: Path
) -> tuple[int | None, str]:
    """Start argv detached; return its exit code (None if still running) and stderr."""
    # no pipes: the app a launcher starts inherits them and outlives any wait
    with tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(  # pylint: disable=consider-using-with # nosec B603
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            code: int | None = process.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            code = None
        stderr.seek(0)
        return code, stderr.read(4096).decode(errors="replace").strip()


def _detail(text: str) -> str:
    return f": {text[:200]}" if text else ""


def _open_terminal(store_path: Path, command: str) -> bool:
    """Open the first terminal that starts running `command` in store_path."""
    env = harness_env()
    for argv in terminal_launches(store_path, command):
        try:
            code, stderr = _launch(argv, env, LAUNCH_SETTLE_SECONDS, store_path)
        except OSError as e:
            logger.warning("terminal %s would not start: %s", argv[0], e)
            continue
        if code in (None, 0):
            return True
        logger.warning("terminal %s exited with %s%s", argv[0], code, _detail(stderr))
    return False


def _open_url(url: str, cwd: Path) -> bool:
    link = url.split("?", maxsplit=1)[0]
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
        code, detail = _launch(args, harness_env(), URL_OPENER_SECONDS, cwd)
        if code is None:
            logger.info(
                "opener for %s still running after %ss; assuming it launched%s",
                link,
                URL_OPENER_SECONDS,
                _detail(detail),
            )
            return True
        if code == 0:
            return True
        # Loudly, and at a level the default config shows. This is the only
        # place the OS says *why* a link did not open, and the caller turns
        # every failure into the same "is it installed?" guess — with a
        # fallback trying several links, a silent first refusal would leave the
        # operator's actual problem nowhere to be read.
        logger.warning(
            "deep link %s was refused (exit %s)%s", link, code, _detail(detail)
        )
        return False
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("deep link %s failed: %s", link, e)
        return False
