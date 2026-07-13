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

"""Test workspace module."""

import json
import stat
import sys
from pathlib import Path

import pytest

from pearl_connect import workspace


def mcp_entry(store_path: Path) -> dict:
    """Mcp entry."""
    return json.loads((store_path / ".mcp.json").read_text())["mcpServers"][
        "pearl-connect"
    ]


def test_populate_writes_mcp_config_0600(store_path: Path) -> None:
    """Test populate writes mcp config 0600."""
    workspace.populate(store_path, "tok-1")
    path = store_path / ".mcp.json"
    if sys.platform != "win32":  # Windows does not enforce POSIX mode bits
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    entry = mcp_entry(store_path)
    assert entry["url"] == "http://127.0.0.1:8716/mcp"
    assert entry["headers"]["Authorization"] == "Bearer tok-1"


def test_populate_preserves_other_mcp_servers(store_path: Path) -> None:
    """Test populate preserves other mcp servers."""
    (store_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"type": "stdio", "command": "x"}}})
    )
    workspace.populate(store_path, "tok-1")
    config = json.loads((store_path / ".mcp.json").read_text())
    assert "other" in config["mcpServers"]
    assert "pearl-connect" in config["mcpServers"]


def test_second_populate_rotates_token(store_path: Path) -> None:
    """Test second populate rotates token."""
    workspace.populate(store_path, "tok-1")
    workspace.populate(store_path, "tok-2")
    assert mcp_entry(store_path)["headers"]["Authorization"] == "Bearer tok-2"


def test_skills_installed_and_overwritten(store_path: Path) -> None:
    """Test skills installed and overwritten."""
    workspace.populate(store_path, "tok")
    skill_md = store_path / ".claude" / "skills" / "pearl-connect" / "SKILL.md"
    assert skill_md.exists()
    # a stale file inside our skill dir is removed on re-populate
    stale = skill_md.parent / "stale.txt"
    stale.write_text("old")
    workspace.populate(store_path, "tok")
    assert not stale.exists()


def test_claude_md_installed_and_overwritten(store_path: Path) -> None:
    """CLAUDE.md is installed from assets and rewritten on each start."""
    workspace.populate(store_path, "tok")
    claude_md = store_path / "CLAUDE.md"
    assert "pearl-connect skill" in claude_md.read_text()
    claude_md.write_text("user edits")
    workspace.populate(store_path, "tok")
    assert claude_md.read_text() != "user edits"


def test_user_files_survive(store_path: Path) -> None:
    """Test user files survive."""
    user_file = store_path / "notes.md"
    user_file.write_text("mine")
    user_skill = store_path / ".claude" / "skills" / "my-skill"
    user_skill.mkdir(parents=True)
    (user_skill / "SKILL.md").write_text("mine too")
    workspace.populate(store_path, "tok")
    assert user_file.read_text() == "mine"
    assert (user_skill / "SKILL.md").read_text() == "mine too"


def test_gitignore_provisioned_and_preserved(store_path: Path) -> None:
    """The token file is gitignored; user entries survive; idempotent."""
    workspace._ensure_gitignore(store_path)  # pylint: disable=protected-access
    content = (store_path / ".gitignore").read_text()
    assert ".mcp.json" in content

    (store_path / ".gitignore").write_text("user-stuff/\n")
    workspace._ensure_gitignore(store_path)  # pylint: disable=protected-access
    content = (store_path / ".gitignore").read_text()
    assert "user-stuff/" in content
    assert ".mcp.json" in content

    before = (store_path / ".gitignore").read_text()
    workspace._ensure_gitignore(store_path)  # pylint: disable=protected-access
    assert (store_path / ".gitignore").read_text() == before  # no growth


def test_claude_settings_deny_rule_merged(store_path: Path) -> None:
    """The Read deny rule lands without clobbering user settings."""
    import json

    settings_path = store_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps({"permissions": {"deny": ["WebFetch"]}, "model": "opus"})
    )
    workspace._ensure_claude_settings(store_path)  # pylint: disable=protected-access
    config = json.loads(settings_path.read_text())
    assert config["model"] == "opus"
    assert "WebFetch" in config["permissions"]["deny"]
    assert "Read(./.mcp.json)" in config["permissions"]["deny"]

    # invalid JSON is backed up, then rewritten rather than crashing the boot
    settings_path.write_text("{nope")
    workspace._ensure_claude_settings(store_path)  # pylint: disable=protected-access
    config = json.loads(settings_path.read_text())
    assert config["permissions"]["deny"] == ["Read(./.mcp.json)"]
    # the user's broken content stays recoverable next to the rewrite
    assert settings_path.with_suffix(".json.bak").read_text() == "{nope"


def test_populate_provisions_token_hygiene(store_path: Path) -> None:
    """populate() ships the gitignore and the deny rule alongside the skill."""
    import json

    workspace.populate(store_path, "tok")
    assert ".mcp.json" in (store_path / ".gitignore").read_text()
    config = json.loads((store_path / ".claude" / "settings.json").read_text())
    assert "Read(./.mcp.json)" in config["permissions"]["deny"]


def test_deep_links(store_path: Path) -> None:
    """Deep links, and the one the configured harness resolves to."""
    assert workspace.desktop_deep_link(store_path).startswith(
        "claude://code/new?folder="
    )
    assert workspace.cli_deep_link(store_path).startswith("claude-cli://open?cwd=")
    # the harness resolves to exactly one link — the other is never a fallback
    assert workspace.deep_link(store_path).startswith("claude://")
    assert workspace.deep_link(store_path, "claude_code_cli").startswith(
        "claude-cli://"
    )


def test_open_session_never_falls_back(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On demand, only the chosen harness counts: no silent other-harness open.

    launch_claude may fall back at boot; open_session must not — the operator
    picked a harness and needs to see it fail, not to get the other one.
    """
    tried: list[str] = []

    def refuse(url: str) -> bool:
        tried.append(url)
        return False

    monkeypatch.setattr(workspace, "_open_url", refuse)
    with pytest.raises(workspace.LaunchError, match="claude_code_cli"):
        workspace.open_session(store_path, "claude_code_cli")
    assert len(tried) == 1  # the desktop link was never tried as a fallback
    assert tried[0].startswith("claude-cli://")

    tried.clear()

    def accept(url: str) -> bool:
        tried.append(url)
        return True

    monkeypatch.setattr(workspace, "_open_url", accept)
    workspace.open_session(store_path, "claude_code_cli")
    assert tried == [workspace.cli_deep_link(store_path)]
