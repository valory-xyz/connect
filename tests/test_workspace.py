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
from urllib.parse import parse_qs, urlparse

import pytest

from connect import workspace
from connect.mech import MAX_DELIVERY_TIMEOUT
from connect.settings import HARNESSES
from connect.workspace import Workspace


def mcp_entry(store_path: Path) -> dict:
    """Mcp entry."""
    return json.loads((store_path / ".mcp.json").read_text())["mcpServers"][
        "pearl-connect"
    ]


def provisioned(store_path: Path, token: str = "tok") -> Workspace:  # nosec B107
    """Return a workspace that provisioned itself, as a healthy boot leaves it."""
    agent_workspace = Workspace(store_path, token)
    assert agent_workspace.ensure() is True, agent_workspace.reason
    return agent_workspace


def test_provisioning_writes_mcp_config_0600(store_path: Path) -> None:
    """Test provisioning writes mcp config 0600."""
    provisioned(store_path, "tok-1")
    path = store_path / ".mcp.json"
    if sys.platform != "win32":  # Windows does not enforce POSIX mode bits
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    entry = mcp_entry(store_path)
    assert entry["url"] == "http://127.0.0.1:8716/mcp/"
    assert entry["headers"]["Authorization"] == "Bearer tok-1"


def test_mcp_entry_grants_a_tool_budget_covering_the_longest_wait(
    store_path: Path,
) -> None:
    """The harness must not abandon a mech request the agent already paid for.

    An HTTP MCP server otherwise gets a 60s first-byte timer and a 5-minute
    idle window, both shorter than a mech delivery wait. The per-server
    timeout raises all of them, so it has to cover the longest wait the
    server itself permits.
    """
    provisioned(store_path)
    assert mcp_entry(store_path)["timeout"] == workspace.MCP_TOOL_TIMEOUT_MS
    # TWICE the delivery timeout: mech-client's on-chain watcher spends it
    # once waiting for the marketplace to name a delivering mech, then
    # restarts its clock to scan that mech's logs. Asserting a single pass
    # held while the budget still fell short of the real worst case.
    assert workspace.MCP_TOOL_TIMEOUT_MS >= 2 * MAX_DELIVERY_TIMEOUT * 1000


def test_provisioning_preserves_other_mcp_servers(store_path: Path) -> None:
    """Test provisioning preserves other mcp servers."""
    (store_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"type": "stdio", "command": "x"}}})
    )
    provisioned(store_path, "tok-1")
    config = json.loads((store_path / ".mcp.json").read_text())
    assert "other" in config["mcpServers"]
    assert "pearl-connect" in config["mcpServers"]


def test_a_second_run_rotates_the_token(store_path: Path) -> None:
    """The token is minted per run, so the next run's workspace rewrites it.

    Two workspaces over one store is what a restart looks like: the same
    persistent_data dir, a fresh token.
    """
    provisioned(store_path, "tok-1")
    provisioned(store_path, "tok-2")
    assert mcp_entry(store_path)["headers"]["Authorization"] == "Bearer tok-2"


def test_skills_installed_and_overwritten(store_path: Path) -> None:
    """Test skills installed and overwritten."""
    provisioned(store_path)
    skill_md = store_path / ".claude" / "skills" / "pearl-connect" / "SKILL.md"
    assert skill_md.exists()
    # a stale file inside our skill dir is removed on the next run
    stale = skill_md.parent / "stale.txt"
    stale.write_text("old")
    provisioned(store_path)
    assert not stale.exists()


def test_claude_md_installed_and_overwritten(store_path: Path) -> None:
    """CLAUDE.md is installed from assets and rewritten on each start."""
    provisioned(store_path)
    claude_md = store_path / "CLAUDE.md"
    assert "pearl-connect skill" in claude_md.read_text()
    claude_md.write_text("user edits")
    provisioned(store_path)
    assert claude_md.read_text() != "user edits"


def test_user_files_survive(store_path: Path) -> None:
    """Test user files survive."""
    user_file = store_path / "notes.md"
    user_file.write_text("mine")
    user_skill = store_path / ".claude" / "skills" / "my-skill"
    user_skill.mkdir(parents=True)
    (user_skill / "SKILL.md").write_text("mine too")
    provisioned(store_path)
    assert user_file.read_text() == "mine"
    assert (user_skill / "SKILL.md").read_text() == "mine too"


def test_gitignore_provisioned_and_preserved(store_path: Path) -> None:
    """The token file is gitignored; user entries survive; idempotent."""
    provisioned(store_path)
    assert ".mcp.json" in (store_path / ".gitignore").read_text()

    (store_path / ".gitignore").write_text("user-stuff/\n")
    provisioned(store_path)
    content = (store_path / ".gitignore").read_text()
    assert "user-stuff/" in content
    assert ".mcp.json" in content

    provisioned(store_path)
    assert (store_path / ".gitignore").read_text() == content  # no growth


def test_claude_settings_deny_rule_merged(store_path: Path) -> None:
    """The Read deny rule lands without clobbering user settings."""
    settings_path = store_path / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True)
    settings_path.write_text(
        json.dumps({"permissions": {"deny": ["WebFetch"]}, "model": "opus"})
    )
    provisioned(store_path)
    config = json.loads(settings_path.read_text())
    assert config["model"] == "opus"
    assert "WebFetch" in config["permissions"]["deny"]
    assert "Read(./.mcp.json)" in config["permissions"]["deny"]

    # invalid JSON is backed up, then rewritten rather than crashing the boot
    settings_path.write_text("{nope")
    provisioned(store_path)
    config = json.loads(settings_path.read_text())
    assert config["permissions"]["deny"] == ["Read(./.mcp.json)"]
    # the user's broken content stays recoverable next to the rewrite
    assert settings_path.with_suffix(".json.bak").read_text() == "{nope"


def test_harness_env_drops_what_our_packaging_leaks(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The launched session inherits none of the PyInstaller loader state.

    The names are spelled out rather than read back from LOADER_ENV_VARS: a
    regression that shrinks that tuple must fail here, not move the goalposts
    with it.
    """
    leaks = {
        "LD_LIBRARY_PATH": "/tmp/_MEIabc123",  # nosec B108
        "LD_LIBRARY_PATH_ORIG": "/opt/pearl/_internal",
        "DYLD_LIBRARY_PATH": "/tmp/_MEIabc123",  # nosec B108
        "DYLD_LIBRARY_PATH_ORIG": "/opt/pearl/_internal",
        "_PYI_APPLICATION_HOME_DIR": "/tmp/_MEIabc123",  # nosec B108
    }
    for name, value in leaks.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PATH", "/usr/bin")

    with caplog.at_level("INFO"):
        env = workspace.harness_env()
    for leaked in leaks:
        assert leaked not in env
        assert leaked in caplog.text  # the scrub says what it took
    assert "/opt/pearl/_internal" not in env.values()  # _ORIG is not restored
    assert env["PATH"] == "/usr/bin"  # everything else is passed through

    # nothing to strip: nothing to say
    caplog.clear()
    for name in leaks:
        monkeypatch.delenv(name)
    with caplog.at_level("INFO"):
        assert workspace.harness_env()["PATH"] == "/usr/bin"
    assert caplog.text == ""


@pytest.mark.parametrize(
    ("platform", "opener"), [("linux", "xdg-open"), ("darwin", "open")]
)
def test_launch_hands_the_url_handler_a_scrubbed_environment(
    platform: str, opener: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No platform that spawns an opener spawns it with our extraction dir.

    Both branches, because a fix applied to one of them is the regression this
    guards: the mac binaries are as much a release asset as the Linux ones.
    """
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")  # nosec B108
    monkeypatch.setattr(workspace.sys, "platform", platform)
    seen: dict = {}

    class Result:
        """subprocess result stub."""

        returncode = 0

    def record(*args: object, **kwargs: object) -> Result:
        """Capture the child's argv and environment."""
        seen["args"] = args
        seen.update(kwargs)
        return Result()

    monkeypatch.setattr(workspace.subprocess, "run", record)
    assert workspace._open_url("claude://x")  # pylint: disable=protected-access
    assert seen["args"][0] == [opener, "claude://x"]
    assert "LD_LIBRARY_PATH" not in seen["env"]


def test_provisioning_ships_token_hygiene(store_path: Path) -> None:
    """The gitignore and the deny rule ship alongside the skill, not apart."""
    provisioned(store_path)
    assert ".mcp.json" in (store_path / ".gitignore").read_text()
    config = json.loads((store_path / ".claude" / "settings.json").read_text())
    assert "Read(./.mcp.json)" in config["permissions"]["deny"]


def test_deep_links(store_path: Path) -> None:
    """Deep links carry the working dir and a pre-filled opening prompt."""
    desktop = workspace.desktop_deep_link(store_path)
    cli = workspace.cli_deep_link(store_path)
    assert desktop.startswith("claude://code/new?folder=")
    assert cli.startswith("claude-cli://open?cwd=")
    # both pre-fill the same opening question, url-encoded, so a fresh session
    # opens on "what can you do?" and the agent answers with its recipe tour
    for url in (desktop, cli):
        assert parse_qs(urlparse(url).query)["q"] == [workspace.FIRST_PROMPT]
    # the harness resolves to exactly one link — the other is never a fallback
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    assert agent_workspace.deep_link().startswith("claude://")
    assert agent_workspace.deep_link("claude_code_cli").startswith("claude-cli://")


def test_ui_build_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The UI turns on when a build is dropped in, and never breaks boot."""
    assets = tmp_path / "assets"
    assets.mkdir()
    monkeypatch.setattr(workspace, "assets_dir", lambda: assets)
    assert workspace.ui_build_dir() is None  # no ui dir: no UI was intended

    # a directory with no index.html is a packaging failure, not a choice —
    # answering None as quietly as for "no UI" would take the operator's only
    # guardrail control surface off the air while health stayed green
    (assets / "ui").mkdir()
    with caplog.at_level("WARNING"):
        assert workspace.ui_build_dir() is None
    assert "has no index.html" in caplog.text

    (assets / "ui" / "index.html").write_text("<!doctype html>")
    assert workspace.ui_build_dir() == assets / "ui"

    # a bundle missing altogether must not take the server down with it
    def no_assets() -> Path:
        raise FileNotFoundError("bundled assets not found")

    monkeypatch.setattr(workspace, "assets_dir", no_assets)
    assert workspace.ui_build_dir() is None


def test_load_ui_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The whole build is read into memory, nested files and all."""
    assets = tmp_path / "assets"
    ui = assets / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html>")
    (ui / "assets" / "app.js").write_text("console.log('hi')")
    monkeypatch.setattr(workspace, "assets_dir", lambda: assets)

    bundle = workspace.load_ui_bundle()
    assert bundle == {
        "index.html": b"<!doctype html>",
        "assets/app.js": b"console.log('hi')",
    }

    # no build, no bundle — and no crash: the API serves on its own
    monkeypatch.setattr(workspace, "ui_build_dir", lambda: None)
    assert workspace.load_ui_bundle() is None


def test_deep_link_rejects_an_unknown_harness(store_path: Path) -> None:
    """A harness with no link raises, instead of quietly opening the desktop."""
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    with pytest.raises(ValueError, match="cursor"):
        agent_workspace.deep_link("cursor")


def test_every_choosable_harness_can_be_opened() -> None:
    """Whatever the operator may choose, we must be able to open.

    HARNESSES is what PATCH /settings and POST /session accept; DEEP_LINKS is
    what can actually be launched. A member of the first missing from the
    second is a dead end the operator only meets when a session refuses to
    start — so the two are pinned to each other here rather than left to drift.
    """
    assert set(workspace.DEEP_LINKS) == set(HARNESSES)


def test_open_session_never_falls_back(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """On demand, only the chosen harness counts: no silent other-harness open.

    The operator picked a harness: they need to see that one fail, not to be
    handed the other one and told it worked.
    """
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    tried: list[str] = []

    def refuse(url: str) -> bool:
        tried.append(url)
        return False

    monkeypatch.setattr(workspace, "_open_url", refuse)
    with pytest.raises(workspace.LaunchError, match="claude_code_cli"):
        agent_workspace.open_session("claude_code_cli")
    assert len(tried) == 1  # the desktop link was never tried as a fallback
    assert tried[0].startswith("claude-cli://")

    tried.clear()

    def accept(url: str) -> bool:
        tried.append(url)
        return True

    monkeypatch.setattr(workspace, "_open_url", accept)
    agent_workspace.open_session("claude_code_cli")
    assert tried == [workspace.cli_deep_link(store_path)]
