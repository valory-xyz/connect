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


def test_deep_links(store_path: Path) -> None:
    """Deep links and the launch order."""
    assert workspace.desktop_deep_link(store_path).startswith(
        "claude://code/new?folder="
    )
    assert workspace.cli_deep_link(store_path).startswith("claude-cli://open?cwd=")
    # desktop first, CLI as fallback
    first, second = workspace.launch_order(store_path)
    assert first.startswith("claude://")
    assert second.startswith("claude-cli://")
