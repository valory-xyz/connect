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

import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import threading
import time
import typing as t
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient
from web3 import Web3

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
    UnavailableReason,
    derive_mac_key,
    harness_unavailable_reason,
    ocb_chat_mech,
)
from connect.signer import Signer
from connect.workspace import Workspace

from tests.conftest import audit_entries

MECH = "0x" + "ab" * 20
VERSION = "0.4.1"
VERSION_FILE = b"v0.4.1"  # as the OCB team writes it
# what earlier releases recorded for their bundled wheel
BUNDLED_WHEEL_RECORD = (
    "olas-ocb-agent[facilitator] @ olas_ocb_agent-0.1.0-py3-none-any.whl "
    "sha256:98a68cd9e7ee62eb04412342f7d3c84da6004a91cc793e9c6eceaa8d7998846f"
)
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="sh install script")


def write_bundle(root: Path, script: str, version: bytes | None = VERSION_FILE) -> Path:
    """Lay out assets/ocb with an install script and, unless None, this VERSION."""
    bundle = root / "assets" / ocb.OCB_ASSETS_SUBDIR
    bundle.mkdir(parents=True)
    (bundle / ocb.OCB_INSTALL_SCRIPT).write_text(script, encoding="utf-8")
    if version is not None:
        (bundle / ocb.OCB_VERSION_FILE).write_bytes(version + b"\n")
    return bundle


def make_agent(path: Path) -> Path:
    """Create an executable stand-in at `path`."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def installer_script(executable: Path) -> str:
    """Return an install.sh honouring the contract: record the version, print the path.

    A set OCB_AGENT_SPEC, which would replace the PyPI requirement, is logged too.
    """
    return (
        "#!/bin/sh\n"
        'echo "$1${OCB_AGENT_SPEC:+ spec=$OCB_AGENT_SPEC}" >> installs.log\n'
        f"printf '#!/bin/sh\\n' > {shlex.quote(str(executable))}\n"
        f"chmod +x {shlex.quote(str(executable))}\n"
        f"echo {shlex.quote(str(executable))}\n"
    )


RECORD_KEY = b"k" * 32


def tool_agent(tmp_path: Path) -> Path:
    """Return where uv installs olas-ocb-agent's ocb-agent under the test's tool dir."""
    return tmp_path / "tools" / "olas-ocb-agent" / "bin" / "ocb-agent"


@pytest.fixture(autouse=True)
def uv_tool_dir_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point uv's tool directory, as the installer's environment names it, at tmp_path."""
    monkeypatch.setenv("UV_TOOL_DIR", str(tmp_path / "tools"))
    return tmp_path / "tools"


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
    return Workspace(
        store_path, "tok", record_dir=record_dir, record_key=RECORD_KEY
    ).ocb  # nosec B106


@pytest.fixture(name="bundle")
def bundle_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Return a bundle whose script installs a stand-in ocb-agent under tmp_path."""
    bundle = write_bundle(tmp_path, installer_script(tool_agent(tmp_path)))
    tool_agent(tmp_path).parent.mkdir(parents=True)
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


def test_the_deployed_chat_mechs_ship() -> None:
    """Each chain ships its deployed, on-chain-confirmed chat mech."""
    assert settings_module.OCB_CHAT_MECHS == {
        "gnosis": "0x4a8A3FA1cde489DFec96F8442d65e9526ec3405c",
        "polygon": "0x364b8238C7d9a05e0F68F87cfF364b6aBD926fEc",
        "robinhood": "0xd3f392C8384cAa4D2864ACba826374337d43a100",
        "base": "0x195Fe9d745a92deE64C9Bf75EFDc7779EB7a5C91",
        "optimism": "0x8122Dcd1E271d0F793827D13410333852DBB9dAb",
    }
    for mech in settings_module.OCB_CHAT_MECHS.values():
        assert Web3.is_checksum_address(mech)
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
    path: Path,
    account: LocalAccount,
    activity: ActivityLog,
    reason: UnavailableReason | None,
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
    # refused before anything is written: not even the defaults exist yet
    assert not (store_path / SETTINGS_FILE).exists()
    assert store.load().harness == DEFAULT_HARNESS
    assert store.harnesses()[-1] == {
        "id": HARNESS_OCB_CLI,
        "available": False,
        "unavailable_reason": "model_unavailable",
    }


# --- launch line ----------------------------------------------------------


@POSIX_ONLY
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
    with_skills = ocb.ocb_command(
        Path("/opt/ocb-agent"), MECH, Path("/d"), ["a" * 64, "b" * 64]
    )
    assert shlex.split(with_skills)[-4:] == [
        "--trusted-skill-hash",
        "a" * 64,
        "--trusted-skill-hash",
        "b" * 64,
    ]


def test_the_launch_line_trusts_each_bundled_skill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OCB is told the digest of every skill Connect ships, so it reads them as instructions."""
    bundled = sorted(
        hashlib.sha256(skill.read_bytes()).hexdigest()
        for skill in (workspace.assets_dir() / "skills").glob("*/SKILL.md")
    )
    assert bundled
    assert workspace.skill_hashes() == bundled
    monkeypatch.setattr(workspace, "assets_dir", lambda: tmp_path / "no-bundle")
    assert workspace.skill_hashes() == []


def test_ocb_is_never_launched_or_installed_without_a_mech(store_path: Path) -> None:
    """A None mech would hand OCB a model that does not exist; nothing installs."""
    agent_workspace = Workspace(
        store_path, "tok", None, store_path.parent, record_key=RECORD_KEY
    )  # nosec B106
    agent_workspace.ocb.ensure = pytest.fail  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="chat mech"):
        agent_workspace.open_session(HARNESS_OCB_CLI)


# --- install ---------------------------------------------------------------


def test_an_install_is_recorded_as_install_sh_s_pypi_requirement() -> None:
    """ocb-agent's CLI imports the facilitator at startup; a plain install crashes."""
    assert ocb.install_identity("0.4.1") == "olas-ocb-agent[facilitator]==0.4.1"


@POSIX_ONLY
def test_install_runs_the_bundled_script_once(
    bundle: Path,
    installer: OcbInstaller,
    store_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """VERSION is passed without its v, never a spec; a rerun installs nothing."""
    monkeypatch.setenv("OCB_AGENT_SPEC", "olas-ocb-agent @ https://example.com/x")
    assert installer.path() is None
    installed = installer.ensure(30)
    assert installed == tool_agent(tmp_path)
    assert installer.ensure(30) == installed
    log = (store_path / "installs.log").read_text().splitlines()
    assert log == [VERSION]


@POSIX_ONLY
def test_uv_s_index_and_source_settings_do_not_reach_the_installer(
    bundle: Path,
    installer: OcbInstaller,
    store_path: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OCB comes from PyPI whatever index Connect's environment names."""
    redirects = [
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_NO_INDEX",
        "UV_INDEX_STRATEGY",
        "UV_OVERRIDE",
        "UV_CONSTRAINT",
        "UV_BUILD_CONSTRAINT",
        "UV_CONFIG_FILE",
    ]
    for name in redirects:
        monkeypatch.setenv(name, "https://example.com/simple")
    script = (bundle / ocb.OCB_INSTALL_SCRIPT).read_text(encoding="utf-8")
    (bundle / ocb.OCB_INSTALL_SCRIPT).write_text(
        script.replace("#!/bin/sh\n", "#!/bin/sh\nenv > installer.env\n", 1),
        encoding="utf-8",
    )
    installer.ensure(30)
    seen = dict(
        line.split("=", 1)
        for line in (store_path / "installer.env").read_text().splitlines()
        if "=" in line
    )
    assert not set(redirects) & set(seen)
    assert seen["UV_TOOL_DIR"] == str(tmp_path / "tools")  # uv's locations stay


@POSIX_ONLY
def test_the_install_record_stays_out_of_the_workspace(
    bundle: Path, installer: OcbInstaller, store_path: Path, record_dir: Path
) -> None:
    """The session cannot point Connect's next launch at another program."""
    installer.ensure(30)
    assert (record_dir / ocb.OCB_RECORD_FILE).is_file()
    assert not [p for p in store_path.iterdir() if p.name.startswith(".ocb-agent")]


@POSIX_ONLY
def test_a_workspace_records_in_the_service_folder(
    store_path: Path, record_dir: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """By default the record sits beside STORE_PATH, not in the process cwd."""
    monkeypatch.chdir(record_dir)
    agent = make_agent(tool_agent(tmp_path))
    installer = Workspace(store_path, "tok", record_key=RECORD_KEY).ocb  # nosec B106
    (store_path.parent / ocb.OCB_RECORD_FILE).write_text(
        installer._signed_record(agent, "x")  # pylint: disable=protected-access
    )
    monkeypatch.setattr(workspace, "assets_dir", lambda: record_dir / "no-bundle")
    assert installer.path() == agent


@POSIX_ONLY
def test_a_restart_that_rebuilds_the_deployment_does_not_reinstall(
    bundle: Path, store_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pearl wipes Connect's working directory on every service start."""
    deployment = tmp_path / "deployment"
    deployment.mkdir()
    monkeypatch.chdir(deployment)
    installed = Workspace(store_path, "tok", record_key=RECORD_KEY).ocb.ensure(
        30
    )  # nosec B106
    monkeypatch.chdir(tmp_path)
    shutil.rmtree(deployment)  # the middleware's rebuild of the deployment
    deployment.mkdir()
    monkeypatch.chdir(deployment)
    restarted = Workspace(store_path, "tok", record_key=RECORD_KEY).ocb  # nosec B106
    assert restarted.path() == installed
    assert restarted.ensure(30) == installed
    log = (store_path / "installs.log").read_text().splitlines()
    assert len(log) == 1


@POSIX_ONLY
def test_a_newer_version_installs_again(
    tmp_path: Path,
    installer: OcbInstaller,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Connect release with another VERSION reaches users who installed before."""
    tool_agent(tmp_path).parent.mkdir(parents=True)
    script = installer_script(tool_agent(tmp_path))
    old = write_bundle(tmp_path / "old", script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: old.parent)
    installer.ensure(30)
    new = write_bundle(tmp_path / "new", script, version=b"0.4.2")
    monkeypatch.setattr(workspace, "assets_dir", lambda: new.parent)
    assert installer.path() is None
    installer.ensure(30)
    log = (store_path / "installs.log").read_text().splitlines()
    assert log == [VERSION, "0.4.2"]


@POSIX_ONLY
def test_a_change_of_extra_installs_again(
    bundle: Path, installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same release, another extra: the install on disk is not what is asked for.

    How a machine that installed the plain package picks up [facilitator].
    """
    installer.ensure(30)
    monkeypatch.setattr(ocb, "OCB_EXTRA", "something-else")
    assert installer.path() is None


@POSIX_ONLY
def test_a_moved_bundle_does_not_reinstall(
    tmp_path: Path,
    installer: OcbInstaller,
    store_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The packaged binary extracts its bundle somewhere new on every start."""
    tool_agent(tmp_path).parent.mkdir(parents=True)
    script = installer_script(tool_agent(tmp_path))
    first = write_bundle(tmp_path / "run1", script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: first.parent)
    installed = installer.ensure(30)
    again = write_bundle(tmp_path / "run2", script)
    monkeypatch.setattr(workspace, "assets_dir", lambda: again.parent)
    assert installer.path() == installed
    assert len((store_path / "installs.log").read_text().splitlines()) == 1


@POSIX_ONLY
@pytest.mark.parametrize(
    "requirement",
    [
        BUNDLED_WHEEL_RECORD,  # Connect v0.1.16-v0.1.17
        BUNDLED_WHEEL_RECORD.split(" sha256:", maxsplit=1)[0],  # before the sha256
    ],
)
@pytest.mark.usefixtures("bundle")
def test_an_install_from_a_bundled_wheel_is_replaced_from_pypi_once(
    installer: OcbInstaller,
    record_dir: Path,
    store_path: Path,
    tmp_path: Path,
    requirement: str,
) -> None:
    """Earlier releases installed a bundled wheel; the next start installs from PyPI.

    After that one install the record matches, and nothing installs again.
    """
    installed = make_agent(tool_agent(tmp_path))
    (record_dir / ocb.OCB_RECORD_FILE).write_text(
        installer._signed_record(installed, requirement)  # pylint: disable=W0212
    )
    assert installer.path() is None
    assert installer.ensure(30) == installed
    record = json.loads((record_dir / ocb.OCB_RECORD_FILE).read_text())
    assert record["requirement"] == f"olas-ocb-agent[facilitator]=={VERSION}"
    assert installer.path() == installed
    assert installer.ensure(30) == installed
    assert (store_path / "installs.log").read_text().splitlines() == [VERSION]


@POSIX_ONLY
def test_an_unreadable_version_keeps_the_recorded_install(
    bundle: Path, installer: OcbInstaller
) -> None:
    """Nothing readable to install is no reason to drop the one installed."""
    installed = installer.ensure(30)
    (bundle / ocb.OCB_VERSION_FILE).unlink()
    (bundle / ocb.OCB_VERSION_FILE).mkdir()  # read -> OSError
    assert installer.path() == installed


@POSIX_ONLY
def test_the_install_record_is_private(
    bundle: Path, installer: OcbInstaller, record_dir: Path
) -> None:
    """It decides which program Connect launches; only its owner may read it."""
    installer.ensure(30)
    record = record_dir / ocb.OCB_RECORD_FILE
    assert record.stat().st_mode & 0o777 == 0o600


@POSIX_ONLY
def test_install_reruns_when_the_installed_binary_is_gone(
    bundle: Path, installer: OcbInstaller, store_path: Path, tmp_path: Path
) -> None:
    """A start with the stored path gone installs again."""
    installer.ensure(30).unlink()
    assert installer.path() is None
    assert installer.ensure(30) == tool_agent(tmp_path)
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


@POSIX_ONLY
def test_a_record_without_a_valid_mac_means_reinstall(
    bundle: Path,
    installer: OcbInstaller,
    record_dir: Path,
    store_path: Path,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Edited, unsigned (written before records were signed) or another key's."""
    installed = installer.ensure(30)
    record = record_dir / ocb.OCB_RECORD_FILE
    signed = json.loads(record.read_text())
    other = make_agent(tmp_path / "tools" / "olas-ocb-agent" / "x" / "ocb-agent")
    stranger = Workspace(
        store_path, "tok", record_dir=record_dir, record_key=b"o" * 32
    ).ocb  # nosec B106
    for written in (
        {**signed, "path": str(other)},  # the path edited
        {"path": signed["path"], "requirement": signed["requirement"]},  # unsigned
        json.loads(
            stranger._signed_record(  # pylint: disable=protected-access
                installed, signed["requirement"]
            )
        ),
    ):
        record.write_text(json.dumps(written))
        assert installer.path() is None
    assert "unsigned or was changed; reinstalling OCB" in caplog.text
    assert installer.ensure(30) == installed  # and it installs again
    assert len((store_path / "installs.log").read_text().splitlines()) == 2


@POSIX_ONLY
@pytest.mark.parametrize(
    "where",
    [
        "elsewhere/ocb-agent",  # outside uv's tool dir
        "tools/other-tool/bin/ocb-agent",  # another uv tool
        "tools/olas-ocb-agent/bin/pearl",  # inside, but not ocb-agent
    ],
)
def test_a_signed_record_must_name_uv_s_ocb_agent(
    installer: OcbInstaller,
    record_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
) -> None:
    """Even a valid record launches only olas-ocb-agent's ocb-agent."""
    monkeypatch.setattr(workspace, "assets_dir", lambda: tmp_path / "no-bundle")
    agent = make_agent(tmp_path / where)
    (record_dir / ocb.OCB_RECORD_FILE).write_text(
        installer._signed_record(agent, "x")  # pylint: disable=protected-access
    )
    assert installer.path() is None


@POSIX_ONLY
def test_uv_s_link_in_its_bin_directory_is_launched_by_that_path(
    installer: OcbInstaller,
    record_dir: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What install.sh prints: ~/.local/bin/ocb-agent, a link into the tool dir."""
    monkeypatch.setattr(workspace, "assets_dir", lambda: tmp_path / "no-bundle")
    link = tmp_path / "bin" / "ocb-agent"
    link.parent.mkdir()
    link.symlink_to(make_agent(tool_agent(tmp_path)))
    (record_dir / ocb.OCB_RECORD_FILE).write_text(
        installer._signed_record(link, "x")  # pylint: disable=protected-access
    )
    assert installer.path() == link


@POSIX_ONLY
def test_an_installer_reporting_another_program_fails_the_install(
    tmp_path: Path, installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path outside uv's tool dir is never recorded, so never launched."""
    agent = tmp_path / "elsewhere" / "ocb-agent"
    agent.parent.mkdir()
    bundle = write_bundle(tmp_path, installer_script(agent))
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    with pytest.raises(InstallError, match="no ocb-agent executable"):
        installer.ensure(30)


@pytest.mark.parametrize(
    ("env", "expected"),
    [
        ({"UV_TOOL_DIR": "/t", "XDG_DATA_HOME": "/x", "HOME": "/h"}, "/t"),
        ({"XDG_DATA_HOME": "/x", "HOME": "/h"}, "/x/uv/tools"),
        ({"HOME": "/h"}, "/h/.local/share/uv/tools"),
        ({}, None),  # no HOME in the environment: this user's home
    ],
)
def test_uv_s_tool_dir_follows_uv_s_rule(
    store_path: Path, env: dict[str, str], expected: str | None
) -> None:
    """UV_TOOL_DIR, else $XDG_DATA_HOME/uv/tools, else ~/.local/share/uv/tools."""
    installer = OcbInstaller(
        store_path,
        store_path.parent,
        bundle_dir=lambda: store_path,
        env=lambda: env,
        record_key=RECORD_KEY,
    )
    tool_dir = installer._tool_dir()  # pylint: disable=protected-access
    want = Path(expected) if expected else Path.home() / ".local/share/uv/tools"
    assert tool_dir == want


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
        (  # a regular file, but not executable
            ': > "$PWD/not-x" && echo "$PWD/not-x"\n',
            "no ocb-agent executable",
        ),
        ("echo /nonexistent/ocb-agent\n", "no ocb-agent executable"),
        ("echo\n", "no ocb-agent executable"),
        ("echo /nonexistent/ocb-agent\necho relative\n", "no ocb-agent executable"),
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
    ("version", "error"),
    [
        (None, "cannot read OCB's .*VERSION: "),
        (b"\xff\xfe", "cannot read OCB's .*VERSION: .*codec"),  # not UTF-8
        (b"", "VERSION names no release: ''"),
        (b"v", "VERSION names no release: 'v'"),
        # install.sh would refuse it too
        (b"0.1.0; rm -rf ~", "VERSION names no release: '0.1.0; rm -rf ~'"),
    ],
)
def test_a_build_without_a_usable_version_cannot_install(
    tmp_path: Path,
    installer: OcbInstaller,
    monkeypatch: pytest.MonkeyPatch,
    version: bytes | None,
    error: str,
) -> None:
    """Which release to install must never be a guess, and the error says why."""
    bundle = write_bundle(tmp_path, "exit 0\n", version=version)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    with pytest.raises(InstallError, match=error):
        installer.ensure(30)


def test_a_build_without_the_install_script_cannot_install(
    tmp_path: Path, installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """VERSION alone installs nothing."""
    bundle = write_bundle(tmp_path, "exit 0\n")
    (bundle / ocb.OCB_INSTALL_SCRIPT).unlink()
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


@POSIX_ONLY
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
    pid = int(child.read_text())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        # the orphaned child is killed with the group, then reaped by init
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
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
    calls: list[float] = []
    monkeypatch.setattr(OcbInstaller, "path", lambda self: Path("/opt/ocb-agent"))
    monkeypatch.setattr(
        OcbInstaller, "_install", lambda self, timeout: calls.append(timeout)
    )
    installer.start().join(5)
    assert calls == []


def test_a_joined_install_reports_its_own_error(
    installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A later start() must not wipe the failure the joined install ended with."""
    release = threading.Event()
    outcomes = iter([InstallError("uv download failed"), None])
    reads: list[int] = []

    def install(self: OcbInstaller, timeout: float) -> Path:
        outcome = next(outcomes)
        if outcome is not None:
            raise outcome
        release.wait(5)
        raise InstallError("second attempt")

    def path(self: OcbInstaller) -> None:
        # ensure()'s check after the join: another caller starts a new
        # attempt just then, between the join and the raise
        reads.append(1)
        if len(reads) == 3:
            self.start()

    monkeypatch.setattr(OcbInstaller, "_install", install)
    monkeypatch.setattr(OcbInstaller, "path", path)
    with pytest.raises(InstallError, match="uv download failed"):
        installer.ensure(5)
    release.set()


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
        store_path, "tok", MECH, store_path.parent, record_key=RECORD_KEY
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
    assert opened == [
        (store_path, ocb.ocb_command(agent, MECH, store_path, workspace.skill_hashes()))
    ]


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


@POSIX_ONLY
def test_only_the_last_line_the_installer_prints_is_the_path(
    tmp_path: Path, installer: OcbInstaller, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Chatter before the path, and blank lines after it, are ignored."""
    agent = tool_agent(tmp_path)
    script = installer_script(agent).replace(
        "#!/bin/sh\n", "#!/bin/sh\necho 'resolved 12 packages'\n"
    )
    bundle = write_bundle(tmp_path, script + "echo\necho '  '\n")
    agent.parent.mkdir(parents=True)
    monkeypatch.setattr(workspace, "assets_dir", lambda: bundle.parent)
    assert installer.ensure(30) == agent


def test_this_build_bundles_ocb() -> None:
    """The shipped bundle resolves, holds no wheel, and asks for install.sh's default.

    Deleting the script or VERSION fails here, as does a VERSION the script's
    DEFAULT_VERSION disagrees with.
    """
    bundle = workspace.assets_dir() / ocb.OCB_ASSETS_SUBDIR
    script, version = ocb._bundled_ocb(lambda: bundle)  # pylint: disable=W0212
    assert script == bundle / ocb.OCB_INSTALL_SCRIPT
    assert not list(bundle.glob("*.whl"))
    default = re.search(
        r'^DEFAULT_VERSION="([^"]+)"', script.read_text(encoding="utf-8"), re.M
    )
    assert default is not None
    assert version == default.group(1)


def test_the_bundle_directory_says_what_goes_in_it() -> None:
    """The OCB team drops install.sh here; VERSION names the PyPI release."""
    readme = Path(workspace.__file__).parent / "assets" / "ocb" / "README.md"
    text = readme.read_text(encoding="utf-8")
    for name in ("install.sh", "VERSION", "PyPI"):
        assert name in text


# --- routes ---------------------------------------------------------------


@pytest.fixture(name="ocb_reason")
def ocb_reason_fixture() -> dict[str, UnavailableReason | None]:
    """Why OCB is unavailable in the route tests; mutable per test."""
    return {"reason": None}


@pytest.fixture(name="settings_store")
def settings_store_fixture(
    account: LocalAccount,
    store_path: Path,
    activity: ActivityLog,
    ocb_reason: dict[str, UnavailableReason | None],
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
    client: TestClient, ocb_reason: dict[str, UnavailableReason | None]
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
    client: TestClient,
    ocb_reason: dict[str, UnavailableReason | None],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither the preference nor a one-off launch can reach it, nor install it."""
    started: list[bool] = []
    monkeypatch.setattr(OcbInstaller, "start", lambda self: started.append(True))
    ocb_reason["reason"] = "model_unavailable"
    patched = client.patch("/settings", json={"harness": "ocb_cli"})
    assert patched.status_code == 400
    assert "model_unavailable" in patched.json()["detail"]
    assert started == []
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
