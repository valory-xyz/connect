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

import shlex
import sys
import threading
import typing as t
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from connect import settings as settings_module
from connect import workspace
from connect.activity import ActivityLog
from connect.config import AppConfig
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
)
from connect.signer import Signer
from connect.workspace import InstallError, OcbInstaller, OcbLaunchError, Workspace

from tests.conftest import audit_entries

MECH = "0x" + "ab" * 20
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="sh install script")


@pytest.fixture(name="confirmed_mech")
def confirmed_mech_fixture(monkeypatch: pytest.MonkeyPatch) -> str:
    """Give the test chain a confirmed chat mech; none ships confirmed yet."""
    monkeypatch.setitem(settings_module.OCB_CHAT_MECHS, "testchain", MECH)
    return MECH


def write_bundle(root: Path, script: str, wheels: int = 1) -> Path:
    """Lay out assets/ocb with an install script and `wheels` wheels."""
    bundle = root / "assets" / workspace.OCB_ASSETS_SUBDIR
    bundle.mkdir(parents=True)
    (bundle / workspace.OCB_INSTALL_SCRIPT).write_text(script, encoding="utf-8")
    for n in range(wheels):
        (bundle / f"ocb_agent-0.4.{n}-py3-none-any.whl").write_bytes(b"")
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


@pytest.fixture(name="bundle")
def bundle_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a bundle whose script installs a stand-in ocb-agent under tmp_path."""
    bundle = write_bundle(tmp_path, installer_script(tmp_path / "bin" / "ocb-agent"))
    (tmp_path / "bin").mkdir()
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    return bundle


# --- availability ---------------------------------------------------------


@pytest.mark.parametrize(
    ("harness", "chain", "platform", "expected"),
    [
        (HARNESS_CODEX_DESKTOP, None, "win32", None),
        (HARNESS_OCB_CLI, "testchain", "linux", None),
        (HARNESS_OCB_CLI, "testchain", "darwin", None),
        (HARNESS_OCB_CLI, "testchain", "win32", "windows_unsupported"),
        (HARNESS_OCB_CLI, None, "win32", "windows_unsupported"),
        (HARNESS_OCB_CLI, "gnosis", "linux", "model_unavailable"),
        (HARNESS_OCB_CLI, "unknownchain", "linux", "model_unavailable"),
        (HARNESS_OCB_CLI, None, "linux", "model_unavailable"),
    ],
)
def test_ocb_needs_a_confirmed_mech_and_not_windows(
    confirmed_mech: str,
    harness: str,
    chain: str | None,
    platform: str,
    expected: str | None,
) -> None:
    """Windows is ruled out first; then the chain must have a chat mech."""
    assert harness_unavailable_reason(harness, chain, platform) == expected


def test_no_chat_mech_ships_confirmed() -> None:
    """Until each mech is deployed and confirmed, OCB is offered nowhere."""
    assert set(settings_module.OCB_CHAT_MECHS.values()) == {None}
    assert settings_module.HARNESSES[-1] == HARNESS_OCB_CLI
    assert DEFAULT_HARNESS != HARNESS_OCB_CLI


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
    store_path: Path, account: LocalAccount, activity: ActivityLog
) -> None:
    """A settings file copied to a machine where OCB cannot run."""
    saved = Settings(
        protected=Protected(mode=MODE_UNRESTRICTED, whitelist={}),
        harness=HARNESS_OCB_CLI,
    )
    store_with(store_path, account, activity, None).save(saved)
    elsewhere = store_with(store_path, account, activity, "windows_unsupported")
    assert elsewhere.load().harness == DEFAULT_HARNESS
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


def test_ocb_runs_by_path_with_the_chain_s_chat_mech(confirmed_mech: str) -> None:
    """The mech is OCB's model, capped at OCB's own per-session mech budget."""
    command = workspace.ocb_command(Path("/opt/my tools/ocb-agent"), "testchain")
    assert shlex.split(command) == [
        "/opt/my tools/ocb-agent",
        "--model",
        f"mech:chat@{confirmed_mech}",
        "--model-budget",
        "1",
    ]


@pytest.mark.parametrize("chain", ["gnosis", None])
def test_ocb_is_never_launched_without_a_mech(chain: str | None) -> None:
    """A None mech would hand OCB a model that does not exist."""
    with pytest.raises(ValueError, match="chat mech"):
        workspace.ocb_command(Path("/bin/ocb-agent"), chain)


# --- install ---------------------------------------------------------------


@POSIX_ONLY
def test_install_runs_the_bundled_script_once(
    bundle: Path, store_path: Path, tmp_path: Path
) -> None:
    """The reported path is kept, so a second ensure reinstalls nothing."""
    store_path.mkdir(parents=True, exist_ok=True)
    installer = OcbInstaller(store_path)
    assert installer.path() is None
    installed = installer.ensure(30)
    assert installed == tmp_path / "bin" / "ocb-agent"
    assert installer.ensure(30) == installed
    log = (store_path / "installs.log").read_text().splitlines()
    assert log == [str(next(bundle.glob("*.whl")))]  # one run, plain wheel


@POSIX_ONLY
def test_install_reruns_when_the_installed_binary_is_gone(
    bundle: Path, store_path: Path, tmp_path: Path
) -> None:
    """A start with the stored path gone installs again."""
    store_path.mkdir(parents=True, exist_ok=True)
    installer = OcbInstaller(store_path)
    installer.ensure(30).unlink()
    assert installer.path() is None
    assert installer.ensure(30) == tmp_path / "bin" / "ocb-agent"
    assert len((store_path / "installs.log").read_text().splitlines()) == 2


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
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    script: str,
    error: str,
) -> None:
    """A non-zero exit carries the script's last stderr line; a bad path is caught."""
    bundle = write_bundle(tmp_path, script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    store_path.mkdir(parents=True, exist_ok=True)
    with pytest.raises(InstallError, match=error):
        OcbInstaller(store_path).ensure(30)
    assert not (store_path / workspace.OCB_PATH_FILE).exists()


@pytest.mark.parametrize("wheels", [0, 2])
def test_a_build_without_exactly_one_wheel_cannot_install(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch, wheels: int
) -> None:
    """Which wheel to install must never be a guess."""
    bundle = write_bundle(tmp_path, "exit 0\n", wheels=wheels)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    with pytest.raises(InstallError, match="does not bundle OCB"):
        OcbInstaller(store_path).ensure(30)


def test_a_build_without_assets_cannot_install(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No bundle at all is an install failure, not a crash."""

    def missing() -> Path:
        raise FileNotFoundError("bundled assets not found")

    monkeypatch.setattr(workspace, "assets_dir", missing)
    with pytest.raises(InstallError, match="bundled assets not found"):
        OcbInstaller(store_path).ensure(30)


@POSIX_ONLY
def test_a_script_that_cannot_finish_is_an_install_failure(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timeout bounds the script."""
    bundle = write_bundle(tmp_path, "sleep 5\n")
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    store_path.mkdir(parents=True, exist_ok=True)
    with pytest.raises(InstallError, match="did not finish"):
        OcbInstaller(store_path).ensure(0.2)


def test_a_session_gives_up_on_an_install_that_outlasts_its_timeout(
    store_path: Path,
) -> None:
    """One install at a time: a caller waits for the running one, within limits."""
    installer = OcbInstaller(store_path)
    installer._install_lock.acquire()  # pylint: disable=protected-access
    with pytest.raises(InstallError, match="still being installed"):
        installer.ensure(0.05)
    installer._install_lock.release()  # pylint: disable=protected-access


def test_a_session_joins_a_running_install(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session started mid-install waits for it and installs nothing more."""
    started, release = threading.Event(), threading.Event()
    installs: list[float] = []
    installer = OcbInstaller(store_path)
    agent = store_path / "ocb-agent"

    def slow(self: OcbInstaller, timeout: float) -> Path:
        installs.append(timeout)
        started.set()
        release.wait(5)
        return agent

    monkeypatch.setattr(OcbInstaller, "_install", slow)
    monkeypatch.setattr(OcbInstaller, "path", lambda self: agent if installs else None)
    installer.start()
    assert started.wait(5)
    joined: list[Path] = []
    session = threading.Thread(target=lambda: joined.append(installer.ensure(5)))
    session.start()
    release.set()
    session.join(5)
    assert joined == [agent]
    assert len(installs) == 1


def test_start_installs_in_the_background_once(
    store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Selection starts an install and returns; a second start is a no-op."""
    started, release = threading.Event(), threading.Event()
    calls: list[float] = []

    def slow(self: OcbInstaller, timeout: float) -> Path:
        calls.append(timeout)
        started.set()
        release.wait(5)
        raise InstallError("offline")

    monkeypatch.setattr(OcbInstaller, "_install", slow)
    installer = OcbInstaller(store_path)
    installer.start()
    assert started.wait(5)  # the thread has taken the lock
    installer.start()
    release.set()
    for thread in threading.enumerate():
        if thread.name == "ocb-install":
            thread.join(5)
    assert len(calls) == 1
    assert 0 < calls[0] <= workspace.OCB_INSTALL_TIMEOUT_SECONDS


# --- open_session ----------------------------------------------------------


def ocb_workspace(store_path: Path, path: Path | None) -> Workspace:
    """Return a workspace on the test chain whose installer yields `path` or fails."""
    agent_workspace = Workspace(store_path, "tok", "testchain")  # nosec B106

    def ensure(timeout: float) -> Path:
        if path is None:
            raise InstallError("offline")
        return path

    agent_workspace.ocb.ensure = ensure  # type: ignore[method-assign]
    return agent_workspace


def test_ocb_opens_a_terminal_running_the_installed_agent(
    store_path: Path, monkeypatch: pytest.MonkeyPatch, confirmed_mech: str
) -> None:
    """By path, with no PATH probe, and no opening prompt."""
    opened: list[tuple[Path, str]] = []
    monkeypatch.setattr(workspace, "_resolves", pytest.fail)

    def terminal(path: Path, command: str) -> bool:
        opened.append((path, command))
        return True

    monkeypatch.setattr(workspace, "_open_terminal", terminal)
    agent = Path("/opt/ocb/bin/ocb-agent")
    assert ocb_workspace(store_path, agent).open_session(HARNESS_OCB_CLI) == "ocb_cli"
    assert opened == [(store_path, workspace.ocb_command(agent, "testchain"))]


@pytest.mark.parametrize("fallback", [False, True])
def test_a_failed_ocb_launch_never_falls_back(
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    confirmed_mech: str,
    fallback: bool,
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


def test_an_unreadable_path_record_means_reinstall(
    store_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A record that cannot be read is logged, then treated as not installed."""
    (store_path / workspace.OCB_PATH_FILE).mkdir(parents=True)  # read -> OSError
    assert OcbInstaller(store_path).path() is None
    assert "reinstalling OCB" in caplog.text


@POSIX_ONLY
def test_an_install_that_cannot_be_recorded_fails(
    bundle: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pearl gets install_failed, not a 500, when the record will not write."""
    store_path.mkdir(parents=True, exist_ok=True)

    def refuse(self: Path, *args: object, **kwargs: object) -> int:
        raise OSError("read-only file system")

    monkeypatch.setattr(Path, "write_text", refuse)
    with pytest.raises(InstallError, match="read-only file system"):
        OcbInstaller(store_path).ensure(30)


def test_an_unexpected_background_failure_reaches_the_log(
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A thread's own excepthook would print to stderr, not to log.txt."""

    def boom(self: OcbInstaller, timeout: float) -> Path:
        raise RuntimeError("boom")

    monkeypatch.setattr(OcbInstaller, "ensure", boom)
    OcbInstaller(store_path)._install_in_background()  # pylint: disable=W0212
    assert "OCB install failed unexpectedly" in caplog.text
