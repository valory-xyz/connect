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

"""Open a real terminal for the terminal harnesses, running stand-in binaries."""

import os
import shlex
import sys
import time
from pathlib import Path

import pytest

from connect import ocb, workspace
from connect.workspace import Workspace

LAUNCH_TIMEOUT_SECONDS = 90

pytestmark = [
    pytest.mark.launch,
    pytest.mark.skipif(
        os.environ.get("CONNECT_LAUNCH_TEST") != "1",
        reason="opens a real terminal window; run with `tox -e launch-tests`",
    ),
]


def mock_codex(bin_dir: Path) -> str:
    """Write a codex that records the directory it ran in; return its command."""
    if sys.platform == "win32":
        script = bin_dir / "codex.cmd"
        script.write_text(
            "@echo off\r\n"
            "cd > launched.tmp\r\n"
            "move /y launched.tmp codex-launched >nul\r\n"
            "exit\r\n",
            encoding="utf-8",
        )
        return str(script)
    script = bin_dir / "codex"
    script.write_text(
        "#!/bin/sh\npwd > launched.tmp && mv launched.tmp codex-launched\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return shlex.quote(str(script))


def test_codex_cli_launches_in_the_workspace(
    store_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A codex_cli session is a terminal that runs codex inside STORE_PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # an absolute path: client/server terminals and Terminal.app ignore our PATH
    monkeypatch.setitem(workspace.TERMINAL_COMMANDS, "codex_cli", mock_codex(bin_dir))
    tried: list[list[str]] = []
    launches = workspace.terminal_launches

    def recorded(path: Path, command: str) -> list[list[str]]:
        found = launches(path, command)
        tried.extend(found)
        return found

    monkeypatch.setattr(workspace, "terminal_launches", recorded)
    agent_workspace = Workspace(store_path, "tok", record_key=b"k" * 32)  # nosec B106
    assert agent_workspace.open_session("codex_cli") == "codex_cli"

    marker = store_path / "codex-launched"
    deadline = time.monotonic() + LAUNCH_TIMEOUT_SECONDS
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert marker.exists(), f"no terminal ran codex; tried {tried}"
    ran_in = Path(marker.read_text(encoding="utf-8").strip())
    assert ran_in.samefile(store_path)


@pytest.mark.skipif(sys.platform == "win32", reason="OCB is not offered on Windows")
def test_ocb_cli_launches_the_installed_agent_with_its_model(
    store_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ocb_cli session is a terminal running the installed ocb-agent by path."""
    mech = "0x" + "ab" * 20
    # a space: the path must be quoted
    tools = tmp_path / "uv tools"
    monkeypatch.setenv("UV_TOOL_DIR", str(tools))
    agent = tools / "olas-ocb-agent" / "bin" / "ocb-agent"
    agent.parent.mkdir(parents=True)
    agent.write_text(
        '#!/bin/sh\necho "$PWD $*" > launched.tmp && mv launched.tmp ocb-launched\n',
        encoding="utf-8",
    )
    agent.chmod(0o755)
    store_path.mkdir(parents=True, exist_ok=True)
    record_dir = tmp_path / "deployment"
    record_dir.mkdir()
    monkeypatch.setattr(workspace, "assets_dir", lambda: record_dir / "no-bundle")
    agent_workspace = Workspace(
        store_path, "tok", mech, record_dir, record_key=b"k" * 32
    )  # nosec B106
    (record_dir / ocb.OCB_RECORD_FILE).write_text(
        agent_workspace.ocb._signed_record(agent, "x"),  # pylint: disable=W0212
        encoding="utf-8",
    )

    assert agent_workspace.open_session("ocb_cli") == "ocb_cli"

    marker = store_path / "ocb-launched"
    deadline = time.monotonic() + LAUNCH_TIMEOUT_SECONDS
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert marker.exists(), "no terminal ran ocb-agent"
    ran_in, args = marker.read_text(encoding="utf-8").strip().split(" ", 1)
    assert Path(ran_in).samefile(store_path)
    assert args == f"--dir {store_path} --model mech:chat@{mech} --model-budget 1"
