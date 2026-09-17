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

"""Open a real terminal for the codex_cli harness, running a stand-in codex."""

import os
import shlex
import sys
import time
from pathlib import Path

import pytest

from connect import workspace
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
    agent_workspace = Workspace(store_path, "tok")  # nosec B106
    assert agent_workspace.open_session("codex_cli") == "codex_cli"

    marker = store_path / "codex-launched"
    deadline = time.monotonic() + LAUNCH_TIMEOUT_SECONDS
    while not marker.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert marker.exists(), "no terminal ran codex"
    ran_in = Path(marker.read_text(encoding="utf-8").strip())
    assert ran_in.samefile(store_path)
