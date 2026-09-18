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
import shlex
import stat
import sys
import tomllib
import typing as t
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


def test_lib_installed_and_overwritten(store_path: Path) -> None:
    """The shared modules land in .claude/lib and are refreshed every boot."""
    provisioned(store_path)
    module = store_path / ".claude" / "lib" / "uniswap.py"
    assert module.exists()
    module.write_text("tampered", encoding="utf-8")
    stale = module.parent / "stale.py"
    stale.write_text("old")
    provisioned(store_path)
    assert "tampered" not in module.read_text(encoding="utf-8")
    assert not stale.exists()


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


def test_a_file_in_place_of_a_tree_is_replaced(store_path: Path) -> None:
    """Not a directory must not wedge provisioning on every health poll."""
    lib = store_path / ".claude" / "lib"
    lib.parent.mkdir(parents=True)
    lib.write_text("not a directory", encoding="utf-8")
    provisioned(store_path)
    assert (lib / "uniswap.py").is_file()


def test_a_link_in_place_of_a_tree_is_unlinked_not_followed(
    store_path: Path, tmp_path: Path
) -> None:
    """Whatever the link pointed at is left alone."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "keep.txt").write_text("keep", encoding="utf-8")
    skills = store_path / ".claude" / "skills"
    skills.mkdir(parents=True)
    try:
        (skills / "pearl-connect").symlink_to(elsewhere, target_is_directory=True)
    except OSError:
        pytest.skip("this platform will not create a symlink for us")
    provisioned(store_path)
    assert (skills / "pearl-connect" / "SKILL.md").is_file()
    assert not (skills / "pearl-connect").is_symlink()
    assert (elsewhere / "keep.txt").read_text(encoding="utf-8") == "keep"


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
    assert config["permissions"]["deny"] == list(workspace.TOKEN_DENY_RULES)
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
    assert "not passing" not in caplog.text


@pytest.mark.parametrize(
    ("platform", "opener"), [("linux", "xdg-open"), ("darwin", "open")]
)
def test_launch_hands_the_url_handler_a_scrubbed_environment(
    platform: str, opener: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No opener is spawned with our extraction dir, or with a pipe to hold.

    Both branches, because a fix applied to one of them is the regression this
    guards: the mac binaries are as much a release asset as the Linux ones. And
    no pipe, because the app a handler starts inherits it: waiting for it to
    close waited out the app, so a Codex Desktop that opened read as a failure
    and the launch fell back to a second harness.
    """
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEIabc123")  # nosec B108
    monkeypatch.setattr(workspace.sys, "platform", platform)
    seen: dict = {}

    class Process:
        """Popen stub that records how the opener was spawned."""

        def __init__(self, args: list[str], **kwargs: t.Any) -> None:
            """Capture the child's argv, environment and standard streams."""
            seen["args"] = args
            seen.update(kwargs)

        def wait(self, timeout: float) -> int:
            """Report the opener as done."""
            return 0

    monkeypatch.setattr(workspace.subprocess, "Popen", Process)
    assert workspace._open_url("claude://x")  # pylint: disable=protected-access
    assert seen["args"] == [opener, "claude://x"]
    assert "LD_LIBRARY_PATH" not in seen["env"]
    streams = (seen["stdin"], seen["stdout"], seen["stderr"])
    assert workspace.subprocess.PIPE not in streams


def test_provisioning_ships_token_hygiene(store_path: Path) -> None:
    """The gitignore and the deny rule ship alongside the skill, not apart."""
    provisioned(store_path)
    assert ".mcp.json" in (store_path / ".gitignore").read_text()
    config = json.loads((store_path / ".claude" / "settings.json").read_text())
    assert "Read(./.mcp.json)" in config["permissions"]["deny"]
    assert "Read(./.codex/config.toml)" in config["permissions"]["deny"]


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
    # each harness resolves to exactly one link, and to its own
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


def test_an_unknown_harness_raises_even_with_a_fallback_offered(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fallback is for a harness that would not open, not for a bogus name.

    settings.py leans on "an unnamed launch falls back" to argue a tampered
    harness cannot deny a session — true only because _harness_or_default
    sanitizes the value on the way out of the settings file, never because
    open_session tolerates a name it does not know. Pin the seam: a value that
    slipped past that sanitizing is a ValueError (a 400), not a quiet open of
    whatever else happens to be installed.
    """
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    tried: list[str] = []

    def accept(url: str) -> bool:
        tried.append(url)
        return True

    monkeypatch.setattr(workspace, "_open_url", accept)
    with pytest.raises(ValueError, match="cursor"):
        agent_workspace.open_session("cursor", fallback=True)
    assert not tried  # no link was opened on the way to the raise


def test_every_choosable_harness_can_be_opened() -> None:
    """Whatever the operator may choose, we must be able to open.

    HARNESSES is what PATCH /settings and POST /session accept; DEEP_LINKS is
    what can actually be launched. A member of the first missing from the
    second is a dead end the operator only meets when a session refuses to
    start — so the two are pinned to each other here rather than left to drift.
    """
    assert set(workspace.DEEP_LINKS) | set(workspace.TERMINAL_COMMANDS) == set(
        HARNESSES
    )
    assert not set(workspace.DEEP_LINKS) & set(workspace.TERMINAL_COMMANDS)


def test_a_named_harness_never_falls_back(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ask for a harness by name and you get that one: no silent other open.

    Naming one is a choice. The caller needs to see *that* one fail, not to be
    handed the other and told it worked.
    """
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    tried: list[str] = []

    def refuse(url: str) -> bool:
        tried.append(url)
        return False

    monkeypatch.setattr(workspace, "_open_url", refuse)
    with pytest.raises(workspace.LaunchError, match="change the harness"):
        agent_workspace.open_session("claude_code_cli")
    assert len(tried) == 1  # the desktop link was never tried as a fallback
    assert tried[0].startswith("claude-cli://")

    tried.clear()

    def accept(url: str) -> bool:
        tried.append(url)
        return True

    monkeypatch.setattr(workspace, "_open_url", accept)
    assert agent_workspace.open_session("claude_code_cli") == "claude_code_cli"
    assert tried == [workspace.cli_deep_link(store_path)]


def test_an_unnamed_harness_falls_back_to_the_other_claude_code(
    store_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Our own guess is not a choice to hold the operator to (OPE-1867).

    An operator with only the CLI installed met nothing but the default
    failing — so a launch nobody named tries the other one too, and says which
    one it ended up in.
    """
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    tried: list[str] = []

    def only_the_cli(url: str) -> bool:
        tried.append(url)
        return url.startswith("claude-cli://")

    monkeypatch.setattr(workspace, "_open_url", only_the_cli)
    with caplog.at_level("INFO"):
        launched = agent_workspace.open_session(fallback=True)
    assert launched == "claude_code_cli"  # the harness that opened, not the ask
    assert tried == [
        workspace.desktop_deep_link(store_path),
        workspace.cli_deep_link(store_path),
    ]
    # never silently: the preference the operator has stopped getting is named
    assert "went to claude_code_cli instead" in caplog.text

    # and with neither installed, the error names what was tried — "change the
    # harness" is no answer once both harnesses have already been tried
    tried.clear()

    def refuse(url: str) -> bool:
        tried.append(url)
        return False

    def no_terminal(path: Path, command: str) -> bool:
        tried.append(command)
        return False

    monkeypatch.setattr(workspace, "_open_url", refuse)
    monkeypatch.setattr(workspace, "_resolves", lambda command: True)
    monkeypatch.setattr(workspace, "_open_terminal", no_terminal)
    with pytest.raises(workspace.LaunchError, match="none of claude_code_desktop") as e:
        agent_workspace.open_session(fallback=True)
    assert "codex_cli" in str(e.value)
    assert str(store_path) in str(e.value)
    assert len(tried) == len(workspace.DEEP_LINKS) + len(workspace.TERMINAL_COMMANDS)


def codex_config(store_path: Path) -> dict:
    """Return the workspace's parsed Codex config."""
    return tomllib.loads((store_path / ".codex" / "config.toml").read_text())


def test_codex_config_carries_the_mcp_json_entry(store_path: Path) -> None:
    """Codex gets what .mcp.json carries: the URL, this run's token, the budget."""
    provisioned(store_path, "tok-1")
    path = store_path / ".codex" / "config.toml"
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert codex_config(store_path)["mcp_servers"]["pearl-connect"] == {
        "url": mcp_entry(store_path)["url"],
        "http_headers": {"Authorization": "Bearer tok-1"},
        "tool_timeout_sec": workspace.MCP_TOOL_TIMEOUT_MS // 1000,
    }
    provisioned(store_path, "tok-2")
    entry = codex_config(store_path)["mcp_servers"]["pearl-connect"]
    assert entry["http_headers"]["Authorization"] == "Bearer tok-2"


def test_codex_sandbox_reaches_the_network_unless_the_file_says_otherwise(
    store_path: Path,
) -> None:
    """Network access defaults on; a value already in the file is kept."""
    provisioned(store_path)
    sandbox = codex_config(store_path)["sandbox_workspace_write"]
    assert sandbox == {"network_access": True}
    path = store_path / ".codex" / "config.toml"
    path.write_text("[sandbox_workspace_write]\nnetwork_access = false\n")
    provisioned(store_path)
    sandbox = codex_config(store_path)["sandbox_workspace_write"]
    assert sandbox == {"network_access": False}


def test_codex_config_keeps_what_else_is_in_it(store_path: Path) -> None:
    """Other settings survive the merge; a broken file is backed up, not lost."""
    path = store_path / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text('model = "o3"\n\n[mcp_servers.other]\ncommand = "x"\n')
    provisioned(store_path)
    config = tomllib.loads(path.read_text())
    assert config["model"] == "o3"
    assert set(config["mcp_servers"]) == {"other", "pearl-connect"}

    path.write_text("[nope")
    provisioned(store_path)
    assert set(tomllib.loads(path.read_text())["mcp_servers"]) == {"pearl-connect"}
    assert path.with_suffix(".toml.bak").read_text() == "[nope"

    path.write_text('mcp_servers = "not a table"\n')
    provisioned(store_path)
    assert set(tomllib.loads(path.read_text())["mcp_servers"]) == {"pearl-connect"}
    assert "not a table" in path.with_suffix(".toml.bak").read_text()


def test_codex_gets_the_brief_skills_and_ignore_rule(store_path: Path) -> None:
    """AGENTS.md, .agents/skills and the gitignore entry mirror the Claude side."""
    provisioned(store_path)
    assert (store_path / "AGENTS.md").read_text() == (
        store_path / "CLAUDE.md"
    ).read_text()
    for root in (".claude", ".agents"):
        assert (store_path / root / "skills" / "pearl-connect" / "SKILL.md").exists()
        assert (store_path / root / "lib" / "uniswap.py").exists()
    gitignore = (store_path / ".gitignore").read_text().splitlines()
    assert ".codex/config.toml*" in gitignore


def test_codex_deep_link(store_path: Path) -> None:
    """The Codex link opens a new thread in the workspace, prompt pre-filled."""
    url = Workspace(store_path, "tok").deep_link("codex_desktop")  # nosec B106
    assert url.startswith("codex://threads/new?")
    assert parse_qs(urlparse(url).query) == {
        "path": [str(store_path)],
        "prompt": [workspace.FIRST_PROMPT],
    }


def test_codex_cli_opens_in_a_terminal(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI registers no URL handler, so its session is a terminal running codex."""
    opened: list[tuple[Path, str]] = []

    def terminal(path: Path, command: str) -> bool:
        opened.append((path, command))
        return True

    monkeypatch.setattr(workspace, "_resolves", lambda command: True)
    monkeypatch.setattr(workspace, "_open_terminal", terminal)
    monkeypatch.setattr(workspace, "_open_url", pytest.fail)
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    assert agent_workspace.open_session("codex_cli") == "codex_cli"
    assert opened == [(store_path, "codex")]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX executables and symlinks")
def test_linux_terminals_are_tried_in_the_operators_order(
    store_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A known $TERMINAL, then x-terminal-emulator by its target, then the known list."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("my-term", "ptyxis", "kitty", "xterm"):
        (bin_dir / name).touch(mode=0o755)
    (bin_dir / "x-terminal-emulator").symlink_to(bin_dir / "ptyxis")
    shells = tmp_path / "shells"
    shells.write_text("# login shells\n/bin/zsh\n", encoding="utf-8")
    monkeypatch.setattr(workspace, "ETC_SHELLS", shells)
    monkeypatch.setattr(workspace.sys, "platform", "linux")
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setenv("TERMINAL", "xterm")
    monkeypatch.setenv("SHELL", "/bin/zsh")
    cwd = str(store_path)
    shell = ["/bin/zsh", "-lic", "codex"]
    assert workspace.terminal_launches(store_path, "codex") == [
        [str(bin_dir / "xterm"), "-e", *shell],
        [
            str(bin_dir / "x-terminal-emulator"),
            "--new-window",
            "-d",
            cwd,
            "-x",
            "/bin/zsh -lic codex",
        ],
        [str(bin_dir / "kitty"), "--directory", cwd, *shell],
    ]

    monkeypatch.setenv("TERMINAL", "my-term")
    monkeypatch.setenv("SHELL", "/opt/not-a-login-shell")
    with caplog.at_level("WARNING"):
        launches = workspace.terminal_launches(store_path, "codex")
    assert "ignoring $TERMINAL" in caplog.text
    names = ("x-terminal-emulator", "kitty", "xterm")
    assert [launch[0] for launch in launches] == [str(bin_dir / n) for n in names]
    assert launches[0][-1] == "/bin/sh -lic codex"

    shells.unlink()
    monkeypatch.setenv("SHELL", "/bin/zsh")
    assert (
        workspace.terminal_launches(store_path, "codex")[0][-1] == "/bin/sh -lic codex"
    )


def test_macos_and_windows_terminals(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Terminal.app opens a self-deleting script; Windows tries wt, then cmd."""
    posix = sys.platform != "win32"  # read it before the patch below rewrites it
    monkeypatch.setattr(workspace.sys, "platform", "darwin")
    spaced = store_path / "work dir"
    [launch] = workspace.terminal_launches(spaced, "codex")
    assert launch[:-1] == ["open", "-a", "Terminal"]
    script = Path(launch[-1])
    assert script.suffix == ".command"
    assert script.read_text(encoding="utf-8") == (
        f'#!/bin/sh\nrm -f "$0"\ncd {shlex.quote(str(spaced))} && exec codex\n'
    )
    if posix:
        assert stat.S_IMODE(script.stat().st_mode) == 0o700
    script.unlink()

    monkeypatch.setattr(workspace.sys, "platform", "win32")
    cwd = str(store_path)
    assert workspace.terminal_launches(store_path, "codex") == [
        ["wt.exe", "-d", cwd, "cmd.exe", "/k", "codex"],
        ["cmd.exe", "/c", "start", "", "/d", cwd, "cmd.exe", "/k", "codex"],
    ]


def test_open_terminal_moves_past_terminals_that_fail(
    store_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A terminal that won't start or exits non-zero at once gives way to the next."""
    launches = [["missing"], ["bad-flags"], ["client"]]
    monkeypatch.setattr(workspace, "terminal_launches", lambda path, command: launches)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/opt/_MEIabc123")
    started: list[list[str]] = []

    class Process:
        """A Popen stand-in whose wait() is the terminal's fate."""

        def __init__(self, argv: list[str], **kwargs: t.Any) -> None:
            """Refuse the missing terminal; record the rest and how they ran."""
            if argv == ["missing"]:
                raise FileNotFoundError(argv[0])
            assert kwargs["cwd"] == store_path
            assert "LD_LIBRARY_PATH" not in kwargs["env"]
            started.append(argv)
            self.argv = argv

        def wait(self, timeout: float) -> int:
            """Exit at once, or keep running past the timeout as a window does."""
            if self.argv == ["window"]:
                raise workspace.subprocess.TimeoutExpired(self.argv, timeout)
            return {"bad-flags": 2, "client": 0}[self.argv[0]]

    monkeypatch.setattr(workspace.subprocess, "Popen", Process)
    open_terminal = workspace._open_terminal  # pylint: disable=protected-access
    with caplog.at_level("WARNING"):
        assert open_terminal(store_path, "codex")
    assert started == [["bad-flags"], ["client"]]
    assert "missing would not start" in caplog.text
    assert "bad-flags exited with 2" in caplog.text

    launches[:] = [["window"]]
    assert open_terminal(store_path, "codex")

    launches[:] = [["missing"], ["bad-flags"]]
    assert not open_terminal(store_path, "codex")


def test_a_missing_codex_never_opens_a_terminal(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without codex, codex_cli fails as not installed and a fallback moves past it."""
    monkeypatch.setattr(workspace, "_resolves", lambda command: False)
    monkeypatch.setattr(workspace, "_open_terminal", pytest.fail)
    monkeypatch.setattr(workspace, "_open_url", lambda url: False)
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    with pytest.raises(workspace.LaunchError, match="is it installed"):
        agent_workspace.open_session("codex_cli")
    with pytest.raises(workspace.LaunchError, match="none of"):
        agent_workspace.open_session(fallback=True)


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (0, True),
        (1, False),
        (workspace.subprocess.TimeoutExpired("sh", 10), True),
        (OSError("no shell"), True),
    ],
)
def test_resolves_asks_the_login_shell(
    outcome: t.Any, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex counts as installed if the login shell finds it, or cannot say."""
    monkeypatch.setattr(workspace.sys, "platform", "linux")
    monkeypatch.setattr(workspace, "_login_shell", lambda: "/bin/zsh")
    seen: dict = {}

    class Result:
        """subprocess result stub."""

        returncode = outcome

    def run(args: list[str], **kwargs: t.Any) -> Result:
        """Record the probe and answer with the outcome."""
        seen.update(kwargs, args=args)
        if isinstance(outcome, Exception):
            raise outcome
        return Result()

    monkeypatch.setattr(workspace.subprocess, "run", run)
    assert workspace._resolves("codex") is expected  # pylint: disable=protected-access
    assert seen["args"] == ["/bin/zsh", "-lic", "command -v codex"]
    streams = (seen["stdin"], seen["stdout"], seen["stderr"])
    assert workspace.subprocess.PIPE not in streams


def test_resolves_on_windows_looks_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows runs codex from our own PATH, so that is where to look."""
    monkeypatch.setattr(workspace.sys, "platform", "win32")
    monkeypatch.setattr(
        workspace.shutil, "which", lambda name: None if name == "codex" else "C:/x"
    )
    resolves = workspace._resolves  # pylint: disable=protected-access
    assert not resolves("codex")
    assert resolves("other")
