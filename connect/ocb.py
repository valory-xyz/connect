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

"""OCB: the launch line, and installing it from the bundled script and wheel.

Split out of workspace.py, over pylint's line limit. The workspace hands in
where the bundle is and the scrubbed environment, so this module needs
nothing from it.
"""

import contextlib
import json
import logging
import os
import shlex
import signal
import subprocess  # nosec B404
import threading
import typing as t
from pathlib import Path

from connect.launch_errors import InstallError
from connect.settings import OCB_MODEL_BUDGET_USD

logger = logging.getLogger("agent")

# the bundle's place in the assets, and what it holds (from olas-ocb-agent)
OCB_ASSETS_SUBDIR = "ocb"
OCB_INSTALL_SCRIPT = "install.sh"
OCB_WHEEL_GLOB = "olas_ocb_agent-*.whl"
# the installed ocb-agent path and the wheel it came from, kept outside the
# workspace in Connect's own directory
OCB_RECORD_FILE = ".ocb-agent.json"
# the script fetches uv, a Python and the wheel's dependencies
OCB_INSTALL_TIMEOUT_SECONDS = 600.0
# how long POST /session waits for an install: Pearl gives up at ~300s
OCB_SESSION_WAIT_SECONDS = 240.0
# how much of the installer's output a failure log keeps
OCB_INSTALL_LOG_CHARS = 2000


def ocb_command(path: Path, mech: str | None, store_path: Path) -> str:
    """Return the shell-quoted line running OCB in store_path with `mech` as model.

    `--dir` names this instance's workspace: without it ocb-agent picks the
    first Connect service it finds under ~/.operate.

    :raises ValueError: when there is no confirmed chat mech — a launch must
        never hand OCB a model that does not exist.
    """
    if mech is None:
        raise ValueError("OCB has no confirmed chat mech on this instance's chain")
    return shlex.join(
        [
            str(path),
            "--dir",
            str(store_path),
            "--model",
            f"mech:chat@{mech}",
            "--model-budget",
            str(OCB_MODEL_BUDGET_USD),
        ]
    )


def _bundled_ocb(bundle_dir: t.Callable[[], Path]) -> tuple[Path, Path]:
    """Return the bundled install script and the one wheel it installs.

    :raises InstallError: when the build does not bundle exactly that.
    """
    try:
        bundle = bundle_dir()
    except FileNotFoundError as e:
        raise InstallError(str(e)) from e
    script = bundle / OCB_INSTALL_SCRIPT
    wheels = sorted(bundle.glob(OCB_WHEEL_GLOB))
    if not script.is_file() or len(wheels) != 1:
        raise InstallError(f"this Connect build does not bundle OCB under {bundle}")
    return script, wheels[0]


class OcbInstaller:
    """Installs OCB with its bundled script, in the background, one at a time.

    The script brings uv and a Python of its own, installs the bundled wheel
    and prints the absolute path of `ocb-agent`, which is launched by path:
    uv's tool directory is not always on the login PATH. The path is recorded
    with the wheel it came from, so a Connect release bundling another wheel
    installs again. The record lives in `record_dir`, outside the workspace,
    so the session cannot point Connect's next launch at another program.
    """

    def __init__(
        self,
        store_path: Path,
        record_dir: Path,
        bundle_dir: t.Callable[[], Path],
        env: t.Callable[[], dict[str, str]],
    ) -> None:
        """Hold where the script runs, its result is kept, and the bundle is.

        `env` is the scrubbed environment the session's own programs get.
        """
        self._store_path = store_path
        self._bundle_dir = bundle_dir
        self._env = env
        self._record = record_dir / OCB_RECORD_FILE
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._error: InstallError | None = None

    def _read_record(self) -> dict:
        """Return the install record, or {} when there is no usable one."""
        try:
            record = json.loads(self._record.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            logger.warning("could not read %s (%s); reinstalling OCB", self._record, e)
            return {}
        return record if isinstance(record, dict) else {}

    def path(self) -> Path | None:
        """Return the installed `ocb-agent`, or None when it must be installed."""
        record = self._read_record()
        installed = _executable(str(record.get("path", "")))
        if installed is None:
            return None
        try:
            bundled = _bundled_ocb(self._bundle_dir)[1].name
        except InstallError:
            return installed  # nothing newer to install
        if record.get("wheel") != bundled:
            logger.info(
                "bundled OCB wheel is now %s (installed: %s); reinstalling",
                bundled,
                record.get("wheel"),
            )
            return None
        return installed

    def start(self) -> threading.Thread:
        """Start an install in the background, or return the one running."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._error = None
                self._thread = threading.Thread(
                    target=self._install_in_background, name="ocb-install", daemon=True
                )
                self._thread.start()
            return self._thread

    def ensure(self, wait: float) -> Path:
        """Return `ocb-agent`, installing it first if needed, waiting up to `wait`.

        The install itself is bounded by OCB_INSTALL_TIMEOUT_SECONDS and goes
        on after `wait` runs out, so a later call finds it done.

        :raises InstallError: when the install failed, or is still running.
        """
        installed = self.path()
        if installed is not None:
            return installed
        install = self.start()
        install.join(wait)
        if install.is_alive():
            raise InstallError("OCB is still being installed; retry in a minute")
        installed = self.path()
        if installed is not None:
            return installed
        raise self._error or InstallError("OCB could not be installed")

    def _install_in_background(self) -> None:
        try:
            if self.path() is None:
                self._install(OCB_INSTALL_TIMEOUT_SECONDS)
        except InstallError as e:
            self._error = e
            logger.error("OCB install failed: %s", e)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # a thread's own excepthook prints to stderr, not to log.txt
            self._error = InstallError(f"OCB install failed unexpectedly: {e}")
            logger.exception("OCB install failed unexpectedly")

    def _install(self, timeout: float) -> Path:
        """Run the bundled script and record the path it reports."""
        script, wheel = _bundled_ocb(self._bundle_dir)
        logger.info("installing OCB from %s", wheel.name)
        returncode, stdout, stderr = _run_installer(
            ["sh", str(script)],
            cwd=self._store_path,
            env={**self._env(), "OCB_AGENT_SPEC": str(wheel)},
            timeout=timeout,
        )
        installed = None if returncode else _executable(stdout.strip())
        if installed is None:
            logger.error(
                "OCB installer exited %s; stdout: %s; stderr: %s",
                returncode,
                stdout[-OCB_INSTALL_LOG_CHARS:],
                stderr[-OCB_INSTALL_LOG_CHARS:],
            )
        if returncode:
            lines = stderr.strip().splitlines()
            raise InstallError(
                lines[-1] if lines else f"the OCB installer exited {returncode}"
            )
        if installed is None:
            raise InstallError("the OCB installer reported no ocb-agent executable")
        try:
            self._record.write_text(
                json.dumps({"path": str(installed), "wheel": wheel.name}),
                encoding="utf-8",
            )
        except OSError as e:
            raise InstallError(f"could not record where OCB is installed: {e}") from e
        logger.info("OCB installed at %s", installed)
        return installed


def _run_installer(
    argv: list[str], cwd: Path, env: dict[str, str], timeout: float
) -> tuple[int, str, str]:
    """Run argv in its own session; on timeout, kill the session's whole group.

    The script starts uv and curl, which a plain kill of `sh` would leave
    running beside the next attempt.

    :raises InstallError: when it cannot start or does not finish in time.
    """
    try:
        process = subprocess.Popen(  # pylint: disable=consider-using-with # nosec B603
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except OSError as e:
        raise InstallError(f"the OCB installer did not start: {e}") from e
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as e:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)  # POSIX: OCB is off on Windows
        process.communicate()
        raise InstallError(f"the OCB installer did not finish: {e}") from e
    return process.returncode, stdout, stderr


def _executable(reported: str) -> Path | None:
    """Return the path if it names an executable file by absolute path, else None."""
    path = Path(reported)
    if reported and path.is_absolute() and path.is_file() and os.access(path, os.X_OK):
        return path
    return None
