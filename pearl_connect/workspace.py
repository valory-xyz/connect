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

"""Populate the agent workspace (STORE_PATH) and launch the Claude Code session.

STORE_PATH is the persistent_data dir Pearl reserves for this service. On every
start we ensure our MCP entry in .mcp.json (rotating the token) and overwrite
our bundled skill, leaving every other file in the workspace alone.
"""

import json
import logging
import os
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path
from urllib.parse import quote

from pearl_connect.config import AGENT_HTTP_PORT, BIND_HOST
from pearl_connect.settings import DEFAULT_HARNESS, HARNESS_CLAUDE_CODE_CLI

logger = logging.getLogger("agent")

MCP_SERVER_NAME = "pearl-connect"
MCP_CONFIG_FILE = ".mcp.json"
SKILLS_SUBDIR = Path(".claude") / "skills"
CLAUDE_SETTINGS_FILE = Path(".claude") / "settings.json"
# the harness itself reads .mcp.json; the model never needs to, and reading
# it would put the bearer token into the session transcript
TOKEN_DENY_RULES = ("Read(./.mcp.json)",)
# a `git init` in the workspace must never be able to stage the token
GITIGNORE_ENTRIES = (".mcp.json",)


def assets_dir() -> Path:
    """Bundled assets location — PyInstaller extracts to sys._MEIPASS."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    for candidate in (base / "assets", base / "pearl_connect" / "assets"):
        if candidate.exists():
            return candidate
    raise FileNotFoundError(f"bundled assets not found under {base}")


def mcp_url() -> str:
    """Mcp url."""
    return f"http://{BIND_HOST}:{AGENT_HTTP_PORT}/mcp"


def populate(store_path: Path, token: str) -> None:
    """Populate the workspace: MCP config, agent context, bundled skills."""
    store_path.mkdir(parents=True, exist_ok=True)
    _ensure_mcp_config(store_path, token)
    _ensure_gitignore(store_path)
    _ensure_claude_settings(store_path)
    _install_claude_md(store_path)
    _install_skills(store_path)


def _install_claude_md(store_path: Path) -> None:
    """Overwrite CLAUDE.md (the agent's identity/context brief) from assets."""
    source = assets_dir() / "CLAUDE.md"
    if source.exists():
        shutil.copyfile(source, store_path / "CLAUDE.md")
    else:
        logger.warning("bundled CLAUDE.md not found under %s", source)


def _ensure_mcp_config(store_path: Path, token: str) -> None:
    """Merge our server entry into .mcp.json (0600), preserving other entries."""
    path = store_path / MCP_CONFIG_FILE
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
        "headers": {"Authorization": f"Bearer {token}"},
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.unlink(missing_ok=True)  # a stale tmp may have looser permissions
    tmp.touch(mode=0o600)
    tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def _ensure_gitignore(store_path: Path) -> None:
    """Keep the token file out of any repo the agent may init here."""
    path = store_path / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    missing = [entry for entry in GITIGNORE_ENTRIES if entry not in existing]
    if not missing:
        return
    lines = existing + ["# pearl-connect: never commit the signer token"] + missing
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _ensure_claude_settings(store_path: Path) -> None:
    """Merge our token-hygiene deny rules into .claude/settings.json.

    Denying the Read tool keeps the token out of session transcripts; the
    Claude Code harness parses .mcp.json itself, the model never needs it.
    User-added settings in the file are preserved.
    """
    path = store_path / CLAUDE_SETTINGS_FILE
    config: dict = {}
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(existing, dict):
                config = existing
        except json.JSONDecodeError:
            logger.warning("existing %s is invalid JSON; rewriting it", path)
    deny = config.setdefault("permissions", {}).setdefault("deny", [])
    for rule in TOKEN_DENY_RULES:
        if rule not in deny:
            deny.append(rule)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")


def _install_skills(store_path: Path) -> None:
    """Overwrite our skills from bundled assets; user files elsewhere are untouched."""
    source = assets_dir() / "skills"
    target_root = store_path / SKILLS_SUBDIR
    target_root.mkdir(parents=True, exist_ok=True)
    for skill_dir in source.iterdir():
        if not skill_dir.is_dir():
            logger.warning("skipping non-directory %s under bundled skills", skill_dir)
            continue
        target = target_root / skill_dir.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(skill_dir, target)


def desktop_deep_link(store_path: Path) -> str:
    """Claude Code desktop-app deep link."""
    return f"claude://code/new?folder={quote(str(store_path))}"


def cli_deep_link(store_path: Path) -> str:
    """Claude Code CLI deep link."""
    return f"claude-cli://open?cwd={quote(str(store_path))}"


def launch_order(store_path: Path, harness: str = DEFAULT_HARNESS) -> tuple[str, str]:
    """Deep links to try, the configured harness's first, the other as fallback."""
    desktop, cli = desktop_deep_link(store_path), cli_deep_link(store_path)
    if harness == HARNESS_CLAUDE_CODE_CLI:
        return cli, desktop
    return desktop, cli


def launch_claude(store_path: Path, harness: str = DEFAULT_HARNESS) -> bool:
    """Open a Claude Code session at STORE_PATH via deep link. Never fatal."""
    for url in launch_order(store_path, harness):
        if _open_url(url):
            logger.info("launched Claude Code via %s", url.split("?", maxsplit=1)[0])
            return True
    logger.warning(
        "could not launch Claude Code via deep link; open it manually at %s", store_path
    )
    return False


def _open_url(url: str) -> bool:
    try:
        if sys.platform == "darwin":  # pragma: no cover — macOS only
            result = subprocess.run(  # nosec B603, B607
                ["open", url], capture_output=True, timeout=15, check=False
            )
        elif sys.platform == "win32":  # pragma: no cover — Windows only
            os.startfile(url)  # type: ignore[attr-defined] # nosec B606
            return True
        else:  # pragma: no cover — Linux/Unix only
            result = subprocess.run(  # nosec B603, B607
                ["xdg-open", url], capture_output=True, timeout=15, check=False
            )
        return result.returncode == 0
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.debug("deep link %s failed: %s", url.split("?", maxsplit=1)[0], e)
        return False
