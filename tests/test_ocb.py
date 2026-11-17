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


"""OCB CLI: availability, install, launch and the routes that drive them."""

import json
import shlex
import sys
import threading
import time
import typing as t
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from connect import ocb
from connect import settings as settings_module
from connect import workspace
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.launch_errors import InstallError, OcbLaunchError
from connect.ocb import OcbInstaller
from connect.settings import (
    DEFAULT_HARNESS,
    HARNESS_CODEX_DESKTOP,
    HARNESS_OCB_CLI,
    MODE_UNRESTRICTED,
    Protected,
    SETTINGS_FILE,
    Settings,
    SettingsStore,
    derive_mac_key,
    harness_unavailable_reason,
    ocb_chat_mech,
)
from connect.signer import Signer
from connect.workspace import Workspace

from tests.conftest import audit_entries

MECH = "0x" + "ab" * 20
WHEEL = "olas_ocb_agent-0.4.1-py3-none-any.whl"  # the name olas-ocb-agent builds
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="sh install script")


def write_bundle(root: Path, script: str, wheels: tuple[str, ...] = (WHEEL,)) -> Path:
    """Lay out assets/ocb with an install script and these wheels."""
    bundle = root / "assets" / ocb.OCB_ASSETS_SUBDIR
    bundle.mkdir(parents=True)
    (bundle / ocb.OCB_INSTALL_SCRIPT).write_text(script, encoding="utf-8")
    for wheel in wheels:
        (bundle / wheel).write_bytes(b"")
    return bundle


def installer_script(executable: Path) -> str:
    """Return an install.sh honouring the contract: record the spec, print the path."""
    return (
        "#!/bin/sh\n"
        'echo "$OCB_AGENT_SPEC" >> installs.log\n'
        f"printf '#!/bin/sh\\n' > {shlex.quote(str(executable))}\n"
        f"chmod +x {shlex.quote(str(executable))}\n"
        f"echo {shlex.quote(str(executable))}\n"
    )


@pytest.fixture(name="record_dir")
def record_dir_fixture(tmp_path: Path) -> Path:
    """Return Connect's own directory, where the install record is kept."""
    record_dir = tmp_path / "deployment"
    record_dir.mkdir()
    return record_dir


@pytest.fixture(name="installer")
def installer_fixture(store_path: Path, record_dir: Path) -> OcbInstaller:
    """Return an installer for the workspace, recording outside it."""
    store_path.mkdir(parents=True, exist_ok=True)
    return OcbInstaller(
        store_path,
        record_dir,
        bundle_dir=lambda: workspace.assets_dir() / ocb.OCB_ASSETS_SUBDIR,
        env=workspace.harness_env,
    )


@pytest.fixture(name="bundle")
def bundle_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a bundle whose script installs a stand-in ocb-agent under tmp_path."""
    bundle = write_bundle(tmp_path, installer_script(tmp_path / "bin" / "ocb-agent"))
    (tmp_path / "bin").mkdir()
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    return bundle


# --- availability ---------------------------------------------------------


@pytest.mark.parametrize(
    ("harness", "mech", "platform", "expected"),
    [
        (HARNESS_CODEX_DESKTOP, None, "win32", None),
        (HARNESS_OCB_CLI, MECH, "linux", None),
        (HARNESS_OCB_CLI, MECH, "darwin", None),
        (HARNESS_OCB_CLI, MECH, "win32", "windows_unsupported"),
        (HARNESS_OCB_CLI, None, "win32", "windows_unsupported"),
        (HARNESS_OCB_CLI, None, "linux", "model_unavailable"),
    ],
)
def test_ocb_needs_a_chat_mech_and_not_windows(
    harness: str, mech: str | None, platform: str, expected: str | None
) -> None:
    """Windows is ruled out first; then the chain must have a chat mech."""
    assert harness_unavailable_reason(harness, mech, platform) == expected


def test_no_chat_mech_ships_confirmed() -> None:
    """Until each mech is deployed and confirmed, OCB is offered nowhere."""
    assert set(settings_module.OCB_CHAT_MECHS.values()) == {None}
    assert settings_module.HARNESSES[-1] == HARNESS_OCB_CLI
    assert DEFAULT_HARNESS != HARNESS_OCB_CLI


@pytest.mark.parametrize(
    ("chain", "overrides", "shipped", "expected"),
    [
        ("gnosis", {"gnosis": MECH}, None, MECH),  # the QA override fills a gap
        ("gnosis", {"gnosis": MECH}, "0x" + "cd" * 20, MECH),  # and wins
        ("gnosis", {"polygon": MECH}, None, None),  # only for its own chain
        ("gnosis", {}, "0x" + "cd" * 20, "0x" + "cd" * 20),
        ("gnosis", None, None, None),
        (None, {"gnosis": MECH}, None, None),  # no instance chain, no mech
    ],
)
def test_the_chat_mech_is_the_override_then_the_shipped_one(
    monkeypatch: pytest.MonkeyPatch,
    chain: str | None,
    overrides: dict[str, str] | None,
    shipped: str | None,
    expected: str | None,
) -> None:
    """One lookup feeds availability and the launch line alike."""
    monkeypatch.setitem(settings_module.OCB_CHAT_MECHS, "gnosis", shipped)
    assert ocb_chat_mech(chain, overrides) == expected


def store_with(
    path: Path, account: LocalAccount, activity: ActivityLog, reason: str | None
) -> SettingsStore:
    """Return a settings store on which OCB is unavailable for `reason`, if any."""
    return SettingsStore(
        path / SETTINGS_FILE,
        derive_mac_key(account),
        activity,
        unavailable=lambda h: reason if h == HARNESS_OCB_CLI else None,
    )


def test_a_saved_ocb_that_became_unavailable_loads_as_the_default(
    store_path: Path,
    account: LocalAccount,
    activity: ActivityLog,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A settings file copied to a machine where OCB cannot run, said once."""
    saved = Settings(
        protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}),
        harness=HARNESS_OCB_CLI,
    )
    store_with(store_path, account, activity, None).save(saved)
    elsewhere = store_with(store_path, account, activity, "windows_unsupported")
    for _ in range(3):  # load() runs on every guarded request
        assert elsewhere.load().harness == DEFAULT_HARNESS
    assert caplog.text.count("saved harness ocb_cli is unavailable") == 1
    # the file keeps the choice, so it applies again where OCB can run
    assert '"ocb_cli"' in (store_path / SETTINGS_FILE).read_text()


def test_patching_something_else_keeps_a_harness_unavailable_here(
    store_path: Path, account: LocalAccount, activity: ActivityLog
) -> None:
    """A protected change must not rewrite the harness the file carries."""
    saved = Settings(
        protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}),
        harness=HARNESS_OCB_CLI,
    )
    store_with(store_path, account, activity, None).save(saved)
    elsewhere = store_with(store_path, account, activity, "windows_unsupported")
    previous, updated = elsewhere.patch({"protected": {"mode": "restricted"}})
    assert (previous.harness, updated.harness) == (DEFAULT_HARNESS, DEFAULT_HARNESS)
    assert '"ocb_cli"' in (store_path / SETTINGS_FILE).read_text()


def test_patching_to_an_unavailable_ocb_is_refused(
    store_path: Path, account: LocalAccount, activity: ActivityLog
) -> None:
    """The reason reaches the caller, and nothing is written."""
    store = store_with(store_path, account, activity, "model_unavailable")
    with pytest.raises(ValueError, match="model_unavailable"):
        store.patch({"harness": HARNESS_OCB_CLI})
    assert store.load().harness == DEFAULT_HARNESS
    assert store.harnesses()[-1] == {
        "id": HARNESS_OCB_CLI,
        "available": False,
        "unavailable_reason": "model_unavailable",
    }


# --- launch line ----------------------------------------------------------


def test_ocb_runs_by_path_in_this_workspace_with_the_chat_mech() -> None:
    """--dir names this instance; the mech is the model, at OCB's own budget."""
    command = ocb.ocb_command(
        Path("/opt/my tools/ocb-agent"), MECH, Path("/home/op/.operate/svc a/data")
    )
    assert shlex.split(command) == [
        "/opt/my tools/ocb-agent",
        "--dir",
        "/home/op/.operate/svc a/data",
        "--model",
        f"mech:chat@{MECH}",
        "--model-budget",
        "1",
    ]


def test_ocb_is_never_launched_without_a_mech() -> None:
    """A None mech would hand OCB a model that does not exist."""
    with pytest.raises(ValueError, match="chat mech"):
        ocb.ocb_command(Path("/bin/ocb-agent"), None, Path("/store"))


# --- install ---------------------------------------------------------------


@POSIX_ONLY
def test_install_runs_the_bundled_script_once(
    bundle: Path, installer: OcbInstaller, store_path: Path, tmp_path: Path
) -> None:
    """The real wheel name is found and installed plain; a rerun installs nothing."""
    assert installer.path() is None
    installed = installer.ensure(30)
    assert installed == tmp_path / "bin" / "ocb-agent"
    assert installer.ensure(30) == installed
    log = (store_path / "installs.log").read_text().splitlines()
    assert log == [str(bundle / WHEEL)]


@POSIX_ONLY
def test_the_install_record_stays_out_of_the_workspace(
    bundle: Path, installer: OcbInstaller, store_path: Path, record_dir: Path
) -> None:
    """The session cannot point Connect's next launch at another program."""
    installer.ensure(30)
    assert (record_dir / ocb.OCB_RECORD_FILE).is_file()
    assert not [p for p in store_path.iterdir() if p.name.startswith(".ocb-agent")]


@POSIX_ONLY
def test_a_workspace_records_in_connect_s_own_directory(
    store_path: Path, record_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """By default the record sits in the process cwd, beside log.txt."""
    monkeypatch.chdir(record_dir)
    agent = record_dir / "ocb-agent"
    agent.write_text("#!/bin/sh\n")
    agent.chmod(0o755)
    (record_dir / ocb.OCB_RECORD_FILE).write_text(json.dumps({"path": str(agent)}))
    monkeypatch.setattr(workspace, "assets_dir", lambda: record_dir / "no-bundle")
    assert Workspace(store_path, "tok").ocb.path() == agent  # nosec B106


@POSIX_ONLY
def test_a_newer_bundled_wheel_installs_again(
    tmp_path: Path,
    installer: OcbInstaller,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Connect release with another wheel reaches users who installed before."""
    (tmp_path / "bin").mkdir()
    script = installer_script(tmp_path / "bin" / "ocb-agent")
    old = write_bundle(tmp_path / "old", script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: old.parent)
    installer.ensure(30)
    new_wheel = "olas_ocb_agent-0.4.2-py3-none-any.whl"
    new = write_bundle(tmp_path / "new", script, wheels=(new_wheel,))
    monkeypatch.setattr(workspace, "assets_dir", lambda: new.parent)
    assert installer.path() is None
    installer.ensure(30)
    log = (store_path / "installs.log").read_text().splitlines()
    assert log == [str(old / WHEEL), str(new / new_wheel)]


@POSIX_ONLY
def test_install_reruns_when_the_installed_binary_is_gone(
    bundle: Path, installer: OcbInstaller, store_path: Path, tmp_path: Path
) -> None:
    """A start with the stored path gone installs again."""
    installer.ensure(30).unlink()
    assert installer.path() is None
    assert installer.ensure(30) == tmp_path / "bin" / "ocb-agent"
    assert len((store_path / "installs.log").read_text().splitlines()) == 2


@POSIX_ONLY
def test_without_a_bundle_the_recorded_install_still_runs(
    bundle: Path, installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing newer to install is no reason to drop the one installed."""
    installed = installer.ensure(30)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent / "gone")
    assert installer.path() == installed


@pytest.mark.parametrize(
    "record", ["not json", "[]", json.dumps({"path": "relative/ocb-agent"})]
)
def test_an_unusable_record_means_reinstall(
    installer: OcbInstaller, record_dir: Path, record: str
) -> None:
    """A record that is not one of ours is treated as not installed."""
    (record_dir / ocb.OCB_RECORD_FILE).write_text(record)
    assert installer.path() is None


def test_an_unreadable_record_means_reinstall(
    installer: OcbInstaller, record_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A record that cannot be read is logged, then treated as not installed."""
    (record_dir / ocb.OCB_RECORD_FILE).mkdir()  # read -> OSError
    assert installer.path() is None
    assert "reinstalling OCB" in caplog.text


@POSIX_ONLY
@pytest.mark.parametrize(
    ("script", "error"),
    [
        ("echo 'no space left on device' >&2\nexit 3\n", "no space left on device"),
        ("exit 4\n", "exited 4"),
        ("echo relative/ocb-agent\n", "no ocb-agent executable"),
        ("echo /nonexistent/ocb-agent\n", "no ocb-agent executable"),
        ("echo\n", "no ocb-agent executable"),
    ],
)
def test_a_failed_install_says_why(
    tmp_path: Path,
    installer: OcbInstaller,
    record_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    script: str,
    error: str,
) -> None:
    """A non-zero exit carries the script's last stderr line; a bad path is caught."""
    bundle = write_bundle(tmp_path, script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    with pytest.raises(InstallError, match=error):
        installer.ensure(30)
    assert not (record_dir / ocb.OCB_RECORD_FILE).exists()


@pytest.mark.parametrize(
    "wheels",
    [
        (),
        (
            "olas_ocb_agent-0.4.1-py3-none-any.whl",
            "olas_ocb_agent-0.4.2-py3-none-any.whl",
        ),
        ("ocb_agent-0.4.1-py3-none-any.whl",),  # not the package's name
    ],
)
def test_a_build_without_exactly_one_wheel_cannot_install(
    tmp_path: Path,
    installer: OcbInstaller,
    monkeypatch: pytest.MonkeyPatch,
    wheels: tuple[str, ...],
) -> None:
    """Which wheel to install must never be a guess."""
    bundle = write_bundle(tmp_path, "exit 0\n", wheels=wheels)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    with pytest.raises(InstallError, match="does not bundle OCB"):
        installer.ensure(30)


def test_a_build_without_assets_cannot_install(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No bundle at all is an install failure, not a crash."""

    def missing() -> Path:
        raise FileNotFoundError("bundled assets not found")

    monkeypatch.setattr(workspace, "assets_dir", missing)
    with pytest.raises(InstallError, match="bundled assets not found"):
        installer.ensure(30)


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="reads /proc")
def test_a_script_that_cannot_finish_takes_its_children_with_it(
    tmp_path: Path, store_path: Path, record_dir: Path
) -> None:
    """On timeout the whole process group goes, not just sh."""
    child = tmp_path / "child.pid"
    began = time.monotonic()
    with pytest.raises(InstallError, match="did not finish"):
        ocb._run_installer(  # pylint: disable=protected-access
            ["sh", "-c", f"sleep 30 & echo $! > {child}; wait"],
            cwd=store_path if store_path.exists() else tmp_path,
            env={},
            timeout=0.5,
        )
    # a child left holding the pipes would keep the caller waiting on it
    assert time.monotonic() - began < 10
    stat = Path(f"/proc/{int(child.read_text())}/stat")
    for _ in range(50):
        # gone, or a zombie waiting for its reaper: either way not running
        if not stat.exists() or stat.read_text().split(") ")[1][0] == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("the installer's child outlived the timeout")


def test_an_installer_that_cannot_start_is_an_install_failure(tmp_path: Path) -> None:
    """A missing sh is install_failed, not a crash."""
    with pytest.raises(InstallError, match="did not start"):
        ocb._run_installer(  # pylint: disable=protected-access
            [str(tmp_path / "no-such-sh")], cwd=tmp_path, env={}, timeout=5
        )


def test_a_session_waits_a_bounded_time_and_the_install_goes_on(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pearl gives up at ~300s, so the session stops waiting first."""
    started, release = threading.Event(), threading.Event()
    agent = Path("/opt/ocb-agent")
    done: list[bool] = []

    def slow(self: OcbInstaller, timeout: float) -> Path:
        started.set()
        release.wait(5)
        done.append(True)
        return agent

    monkeypatch.setattr(OcbInstaller, "_install", slow)
    monkeypatch.setattr(OcbInstaller, "path", lambda self: agent if done else None)
    with pytest.raises(InstallError, match="still being installed"):
        installer.ensure(0.05)
    assert started.wait(5)
    release.set()
    installer.start().join(5)
    assert installer.ensure(0.05) == agent  # a Retry finds it done
    assert ocb.OCB_SESSION_WAIT_SECONDS < 300


def test_a_session_joins_a_running_install(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session started mid-install waits for it and installs nothing more."""
    started, release = threading.Event(), threading.Event()
    installs: list[float] = []
    agent = Path("/opt/ocb-agent")

    def slow(self: OcbInstaller, timeout: float) -> Path:
        installs.append(timeout)
        started.set()
        release.wait(5)
        return agent

    monkeypatch.setattr(OcbInstaller, "_install", slow)
    monkeypatch.setattr(
        OcbInstaller,
        "path",
        lambda self: agent if installs and release.is_set() else None,
    )
    installer.start()
    assert started.wait(5)
    joined: list[Path] = []
    session = threading.Thread(target=lambda: joined.append(installer.ensure(5)))
    session.start()
    release.set()
    session.join(5)
    assert joined == [agent]
    assert installs == [ocb.OCB_INSTALL_TIMEOUT_SECONDS]


def test_a_failed_background_install_reaches_the_session(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session reports the install's own reason."""

    def offline(self: OcbInstaller, timeout: float) -> Path:
        raise InstallError("uv download failed")

    monkeypatch.setattr(OcbInstaller, "_install", offline)
    with pytest.raises(InstallError, match="uv download failed"):
        installer.ensure(5)


def test_start_installs_in_the_background_once(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Selection starts an install and returns; a second start joins it."""
    started, release = threading.Event(), threading.Event()
    calls: list[float] = []

    def slow(self: OcbInstaller, timeout: float) -> Path:
        calls.append(timeout)
        started.set()
        release.wait(5)
        raise InstallError("offline")

    monkeypatch.setattr(OcbInstaller, "_install", slow)
    first = installer.start()
    assert started.wait(5)
    assert installer.start() is first
    release.set()
    first.join(5)
    assert calls == [ocb.OCB_INSTALL_TIMEOUT_SECONDS]


def test_an_up_to_date_install_is_not_rerun_on_selection(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Selecting OCB again with it installed runs nothing."""
    monkeypatch.setattr(OcbInstaller, "path", lambda self: Path("/opt/ocb-agent"))
    monkeypatch.setattr(OcbInstaller, "_install", pytest.fail)
    installer.start().join(5)


def test_an_unexpected_background_failure_reaches_the_log_and_the_session(
    installer: OcbInstaller,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A thread's own excepthook would print to stderr, not to log.txt."""

    def boom(self: OcbInstaller, timeout: float) -> Path:
        raise RuntimeError("boom")

    monkeypatch.setattr(OcbInstaller, "_install", boom)
    with pytest.raises(InstallError, match="boom"):
        installer.ensure(5)
    assert "OCB install failed unexpectedly" in caplog.text


@POSIX_ONLY
def test_an_install_that_cannot_be_recorded_fails(
    bundle: Path, installer: OcbInstaller, record_dir: Path
) -> None:
    """Pearl gets install_failed, not a 500, when the record will not write."""
    record_dir.chmod(0o500)
    try:
        with pytest.raises(InstallError, match="could not record"):
            installer.ensure(30)
    finally:
        record_dir.chmod(0o700)


# --- open_session ----------------------------------------------------------


def ocb_workspace(store_path: Path, path: Path | None) -> Workspace:
    """Return a workspace with a chat mech whose installer yields `path` or fails."""
    agent_workspace = Workspace(
        store_path, "tok", MECH, store_path.parent
    )  # nosec B106

    def ensure(wait: float) -> Path:
        assert wait == ocb.OCB_SESSION_WAIT_SECONDS
        if path is None:
            raise InstallError("offline")
        return path

    agent_workspace.ocb.ensure = ensure  # type: ignore[method-assign]
    return agent_workspace


def test_ocb_opens_a_terminal_running_the_installed_agent(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """By path, in this workspace, with no PATH probe and no opening prompt."""
    opened: list[tuple[Path, str]] = []
    monkeypatch.setattr(workspace, "_resolves", pytest.fail)

    def terminal(path: Path, command: str) -> bool:
        opened.append((path, command))
        return True

    monkeypatch.setattr(workspace, "_open_terminal", terminal)
    agent = Path("/opt/ocb/bin/ocb-agent")
    assert ocb_workspace(store_path, agent).open_session(HARNESS_OCB_CLI) == "ocb_cli"
    assert opened == [(store_path, ocb.ocb_command(agent, MECH, store_path))]


@pytest.mark.parametrize("fallback", [False, True])
def test_a_failed_ocb_launch_never_falls_back(
    store_path: Path, monkeypatch: pytest.MonkeyPatch, fallback: bool
) -> None:
    """Neither an install nor a terminal failure opens another harness."""
    monkeypatch.setattr(workspace, "_open_url", pytest.fail)
    monkeypatch.setattr(workspace, "_open_terminal", lambda p, c: False)
    with pytest.raises(InstallError, match="offline"):
        ocb_workspace(store_path, None).open_session(HARNESS_OCB_CLI, fallback=fallback)
    with pytest.raises(OcbLaunchError) as raised:
        ocb_workspace(store_path, Path("/bin/ocb")).open_session(
            HARNESS_OCB_CLI, fallback=fallback
        )
    assert raised.value.reason == "launch_failed"


def test_ocb_is_never_a_fallback(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fallback launch tries every other harness, and never installs OCB."""
    tried: list[str] = []

    def refuse(first: object, second: object) -> bool:
        tried.append(f"{first} {second}")
        return False

    monkeypatch.setattr(workspace, "_open_url", refuse)
    monkeypatch.setattr(workspace, "_resolves", lambda command: True)
    monkeypatch.setattr(workspace, "_open_terminal", refuse)
    agent_workspace = ocb_workspace(store_path, None)
    agent_workspace.ocb.ensure = pytest.fail  # type: ignore[method-assign]
    with pytest.raises(workspace.LaunchError) as raised:
        agent_workspace.open_session(fallback=True)
    assert raised.value.reason == "not_installed"
    assert len(tried) == len(workspace.DEEP_LINKS) + len(workspace.TERMINAL_COMMANDS)


def test_ocb_token_shim_is_kept_out_of_git_and_transcripts() -> None:
    """OCB copies the bearer token into ocb-agent/ in the workspace."""
    assert "ocb-agent/" in workspace.GITIGNORE_ENTRIES
    assert "Read(./ocb-agent/**)" in workspace.TOKEN_DENY_RULES


def test_the_bundle_directory_says_what_goes_in_it() -> None:
    """The OCB team drops install.sh and the wheel here."""
    readme = Path(workspace.__file__).parent / "assets" / "ocb" / "README.md"
    text = readme.read_text(encoding="utf-8")
    for name in ("install.sh", "olas_ocb_agent-", "VERSION"):
        assert name in text


# --- routes ---------------------------------------------------------------


@pytest.fixture(name="ocb_reason")
def ocb_reason_fixture() -> dict[str, str | None]:
    """Why OCB is unavailable in the route tests; mutable per test."""
    return {"reason": None}


@pytest.fixture(name="settings_store")
def settings_store_fixture(
    account: LocalAccount,
    store_path: Path,
    activity: ActivityLog,
    ocb_reason: dict[str, str | None],
) -> SettingsStore:
    """Return the app's store, with OCB's availability under the test's control."""
    store = SettingsStore(
        store_path / SETTINGS_FILE,
        derive_mac_key(account),
        activity,
        unavailable=lambda h: ocb_reason["reason"] if h == HARNESS_OCB_CLI else None,
    )
    store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
    return store


@pytest.fixture(name="client")
def client_fixture(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
) -> t.Iterator[TestClient]:
    """Yield a client of the app over the controllable store."""
    with TestClient(
        make_app(test_signer, app_config, activity), base_url="http://127.0.0.1:8716"
    ) as client:
        yield client


def test_settings_list_ocb_with_its_reason(
    client: TestClient, ocb_reason: dict[str, str | None]
) -> None:
    """The UI renders this list; the server owns the rule."""
    ocb_reason["reason"] = "windows_unsupported"
    harnesses = client.get("/settings").json()["harnesses"]
    assert [h["id"] for h in harnesses] == list(settings_module.HARNESSES)
    assert harnesses[-1] == {
        "id": "ocb_cli",
        "available": False,
        "unavailable_reason": "windows_unsupported",
    }


def test_selecting_an_unavailable_ocb_is_a_400(
    client: TestClient, ocb_reason: dict[str, str | None]
) -> None:
    """Neither the preference nor a one-off launch can reach it."""
    ocb_reason["reason"] = "model_unavailable"
    patched = client.patch("/settings", json={"harness": "ocb_cli"})
    assert patched.status_code == 400
    assert "model_unavailable" in patched.json()["detail"]
    launched = client.post("/session", json={"harness": "ocb_cli"})
    assert launched.status_code == 400
    assert "model_unavailable" in launched.json()["detail"]


def test_selecting_ocb_starts_its_install(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed on selection; the PATCH itself does not wait for it."""
    started: list[bool] = []
    monkeypatch.setattr(OcbInstaller, "start", lambda self: started.append(True))
    response = client.patch("/settings", json={"harness": "ocb_cli"})
    assert response.status_code == 200
    assert response.json()["harness"] == "ocb_cli"
    assert response.json()["harnesses"][-1] == {"id": "ocb_cli", "available": True}
    assert started == [True]
    client.patch("/settings", json={"harness": "codex_desktop"})
    assert started == [True]  # another harness installs nothing


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (InstallError("uv download failed"), "install_failed"),
        (OcbLaunchError("no terminal"), "launch_failed"),
    ],
)
def test_ocb_session_failures_carry_their_reason(
    client: TestClient,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    reason: str,
) -> None:
    """Pearl tells a failed install from a failed launch by `reason`."""

    def refuse(self: Workspace, harness: str, *, fallback: bool = False) -> str:
        raise error

    monkeypatch.setattr(OcbInstaller, "start", lambda self: None)
    monkeypatch.setattr(Workspace, "open_session", refuse)
    client.patch("/settings", json={"harness": "ocb_cli"})
    response = client.post("/session")
    assert response.json() == {
        "launched": False,
        "harness": "ocb_cli",
        "requested": "ocb_cli",
        "reason": reason,
        "error": str(error),
    }
    entry = audit_entries(store_path)[-1]
    assert (entry["kind"], entry["reason"]) == ("session_launch_failed", reason)
