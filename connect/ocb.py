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

"""OCB: the launch line, and installing it from PyPI with the bundled script.

Split out of workspace.py, over pylint's line limit. The workspace hands in
where the bundle is and the scrubbed environment, so this module needs
nothing from it.
"""

import contextlib
import hashlib
import hmac
import json
import logging
import os
import re
import shlex
import signal
import subprocess  # nosec B404
import threading
import typing as t
from pathlib import Path

from connect.launch_errors import InstallError
from connect.private_files import write_private
from connect.settings import OCB_MODEL_BUDGET_USD

logger = logging.getLogger("agent")

# the bundle's place in the assets, and what it holds (from olas-ocb-agent)
OCB_ASSETS_SUBDIR = "ocb"
OCB_INSTALL_SCRIPT = "install.sh"
# the olas-ocb-agent release to install, e.g. `v0.1.0`
OCB_VERSION_FILE = "VERSION"
# the installed ocb-agent path and the requirement it came from, kept beside
# STORE_PATH (its parent, the service folder): outside the session's
# workspace, and not in Connect's cwd, the deployment directory Pearl rebuilds
# on every service start; HMAC'd with a key derived from the agent key
OCB_RECORD_FILE = ".ocb-agent.json"
_RECORD_KEY_INFO = b"pearl-connect ocb install record v1"
# what uv names the tool and the executable a recorded path must resolve to
OCB_EXECUTABLE = "ocb-agent"
# the script fetches uv, a Python, olas-ocb-agent and its dependencies
OCB_INSTALL_TIMEOUT_SECONDS = 600.0
# how long POST /session waits for an install: Pearl gives up at ~300s
OCB_SESSION_WAIT_SECONDS = 240.0
# ocb-agent's CLI imports the facilitator at startup, so the package installs
# with that extra; without it every launch dies on a missing eth_abi
OCB_PACKAGE = "olas-ocb-agent"
OCB_EXTRA = "facilitator"
# how much of the installer's output a failure log keeps
OCB_INSTALL_LOG_CHARS = 2000


def ocb_command(
    path: Path, mech: str, store_path: Path, trusted_skills: t.Iterable[str] = ()
) -> str:
    """Return the shell-quoted line running OCB in store_path with `mech` as model.

    `--dir` names this instance's workspace: without it ocb-agent picks the
    first Connect service it finds under ~/.operate. `trusted_skills` are the
    SHA-256 digests of the skill files this workspace ships, one
    `--trusted-skill-hash` each: OCB reads a skill file whose digest it was
    not given as data, never as instructions.
    """
    line = [
        str(path),
        "--dir",
        str(store_path),
        "--model",
        f"mech:chat@{mech}",
        "--model-budget",
        str(OCB_MODEL_BUDGET_USD),
    ]
    for digest in trusted_skills:
        line += ["--trusted-skill-hash", digest]
    return shlex.join(line)


def install_identity(version: str) -> str:
    """Return what an install of `version` is recorded as: install.sh's requirement.

    The script installs `olas-ocb-agent[facilitator]==<version>` from PyPI, so
    a record naming anything else (another release, another extra, or a wheel
    an earlier Connect release bundled) installs again.
    """
    return f"{OCB_PACKAGE}[{OCB_EXTRA}]=={version}"


class _Attempt:
    """One background install, and the error it ended with, if any.

    Kept per attempt so a caller joining one install reads that install's
    error, even after a later start() has begun another.
    """

    def __init__(self, run: t.Callable[["_Attempt"], None]) -> None:
        """Start running `run` on a daemon thread."""
        self.error: InstallError | None = None
        self._thread = threading.Thread(
            target=run, args=(self,), name="ocb-install", daemon=True
        )
        self._thread.start()

    def join(self, timeout: float) -> None:
        """Wait up to `timeout` seconds for the install to end."""
        self._thread.join(timeout)

    def is_alive(self) -> bool:
        """Return whether the install is still running."""
        return self._thread.is_alive()


def _bundled_ocb(bundle_dir: t.Callable[[], Path]) -> tuple[Path, str]:
    """Return the bundled install script and the release it installs (no `v`).

    :raises InstallError: when the build does not bundle both.
    """
    try:
        bundle = bundle_dir()
    except FileNotFoundError as e:
        raise InstallError(str(e)) from e
    script = bundle / OCB_INSTALL_SCRIPT
    try:
        version = (bundle / OCB_VERSION_FILE).read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        version = ""
    version = version.removeprefix("v")
    if not script.is_file() or not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise InstallError(f"this Connect build does not bundle OCB under {bundle}")
    return script, version


class OcbInstaller:
    """Installs OCB with its bundled script, in the background, one at a time.

    The script brings uv and a Python of its own, installs the release named
    in the bundle's VERSION from PyPI and prints the absolute path of
    `ocb-agent`, which is launched by path: uv's tool directory is not always
    on the login PATH. The path is recorded with the requirement it came from
    (install_identity), so a Connect release asking for another release or
    extra, or one replacing a wheel an earlier release bundled, installs
    again; a matching record does not. The record lives in `record_dir`, outside the workspace, and carries a MAC
    keyed off the agent key, so neither the session nor anything else that
    can write the file can point Connect's next launch at another program: an
    unsigned or tampered record reads as no record, and OCB installs again.
    A recorded path must also be `ocb-agent` inside uv's tool directory for
    olas-ocb-agent, or it is not launched.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        store_path: Path,
        record_dir: Path,
        bundle_dir: t.Callable[[], Path],
        env: t.Callable[[], dict[str, str]],
        *,
        record_key: bytes,
    ) -> None:
        """Hold where the script runs, its result is kept, and the bundle is.

        `env` is the scrubbed environment the session's own programs get;
        `record_key` signs the install record.
        """
        self._store_path = store_path
        self._bundle_dir = bundle_dir
        self._env = env
        self._record = record_dir / OCB_RECORD_FILE
        self._record_key = hmac.new(
            record_key, _RECORD_KEY_INFO, hashlib.sha256
        ).digest()
        self._lock = threading.Lock()
        self._attempt: _Attempt | None = None

    def _mac(self, path: str, requirement: str) -> str:
        """Return the record's MAC over exactly what it says."""
        canonical = json.dumps(
            {"path": path, "requirement": requirement},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hmac.new(
            self._record_key, canonical.encode(), hashlib.sha256
        ).hexdigest()

    def _signed_record(self, path: Path, requirement: str) -> str:
        """Return the record to write: the path, the requirement and their MAC."""
        return json.dumps(
            {
                "path": str(path),
                "requirement": requirement,
                "mac": self._mac(str(path), requirement),
            }
        )

    def _read_record(self) -> dict:
        """Return the verified install record, or {} when there is no usable one.

        A record without a valid MAC (one written before records were signed,
        or edited since) is treated as missing: OCB installs again.
        """
        try:
            record = json.loads(self._record.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            logger.warning("could not read %s (%s); reinstalling OCB", self._record, e)
            return {}
        if not isinstance(record, dict):
            return {}
        path, requirement = str(record.get("path", "")), str(
            record.get("requirement", "")
        )
        if not hmac.compare_digest(
            str(record.get("mac", "")), self._mac(path, requirement)
        ):
            logger.warning(
                "%s is unsigned or was changed; reinstalling OCB", self._record
            )
            return {}
        return record

    def _tool_dir(self) -> Path:
        """Return uv's tool directory for the installer's environment.

        uv's own rule: UV_TOOL_DIR, else $XDG_DATA_HOME/uv/tools, else
        ~/.local/share/uv/tools.
        """
        env = self._env()
        if env.get("UV_TOOL_DIR"):
            return Path(env["UV_TOOL_DIR"])
        data = env.get("XDG_DATA_HOME") or str(
            Path(env.get("HOME") or Path.home()) / ".local" / "share"
        )
        return Path(data) / "uv" / "tools"

    def _ocb_agent(self, reported: str) -> Path | None:
        """Return `reported` if it is uv's olas-ocb-agent `ocb-agent`, else None.

        The path the script prints is uv's link in its bin directory; what it
        resolves to must be `ocb-agent` inside the tool's own directory.
        """
        path = _executable(reported)
        if path is None:
            return None
        target = path.resolve()
        tool = (self._tool_dir() / OCB_PACKAGE).resolve()
        if target.name != OCB_EXECUTABLE or not target.is_relative_to(tool):
            logger.warning("%s is not %s's %s", path, OCB_PACKAGE, OCB_EXECUTABLE)
            return None
        return path

    def path(self) -> Path | None:
        """Return the installed `ocb-agent`, or None when it must be installed."""
        record = self._read_record()
        installed = self._ocb_agent(str(record.get("path", "")))
        if installed is None:
            return None
        try:
            wanted = install_identity(_bundled_ocb(self._bundle_dir)[1])
        except InstallError:
            return installed  # nothing newer to install
        if record.get("requirement") != wanted:
            logger.info(
                "Connect now installs %s (installed: %s); reinstalling",
                wanted,
                record.get("requirement"),
            )
            return None
        return installed

    def start(self) -> _Attempt:
        """Start an install in the background, or return the one running."""
        with self._lock:
            if self._attempt is None or not self._attempt.is_alive():
                self._attempt = _Attempt(self._install_in_background)
            return self._attempt

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
        raise install.error or InstallError("OCB could not be installed")

    def _install_in_background(self, attempt: _Attempt) -> None:
        try:
            if self.path() is None:
                self._install(OCB_INSTALL_TIMEOUT_SECONDS)
        except InstallError as e:
            attempt.error = e
            logger.error("OCB install failed: %s", e)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # a thread's own excepthook prints to stderr, not to log.txt
            attempt.error = InstallError(f"OCB install failed unexpectedly: {e}")
            logger.exception("OCB install failed unexpectedly")

    def _install(self, timeout: float) -> Path:
        """Run the bundled script and record the path it reports."""
        script, version = _bundled_ocb(self._bundle_dir)
        logger.info("installing OCB %s from PyPI", version)
        returncode, stdout, stderr = _run_installer(
            ["sh", str(script), version],
            cwd=self._store_path,
            # unset: it would replace the PyPI requirement the record names
            env={k: v for k, v in self._env().items() if k != "OCB_AGENT_SPEC"},
            timeout=timeout,
        )
        installed = None if returncode else self._ocb_agent(_last_line(stdout))
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
            write_private(
                self._record,
                self._signed_record(installed, install_identity(version)),
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


def _last_line(stdout: str) -> str:
    """Return the last non-empty line of `stdout`: where install.sh puts the path."""
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _executable(reported: str) -> Path | None:
    """Return the path if it names an executable file by absolute path, else None."""
    path = Path(reported)
    if reported and path.is_absolute() and path.is_file() and os.access(path, os.X_OK):
        return path
    return None
