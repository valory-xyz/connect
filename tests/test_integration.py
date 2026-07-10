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

"""Integration tests against a Tenderly Gnosis fork.

The RPC comes from the GNOSIS_TESTNET_RPC env var (CI) or, for local runs,
from the sibling olas-operate-middleware checkout's .env file.
"""

import json
import os
import secrets
import time
from pathlib import Path

import httpx
import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig, ChainConfig
from pearl_connect.guard import Guard
from pearl_connect.mech import MechError, MechService
from pearl_connect.server.app import create_app
from pearl_connect.settings import (
    MODE_UNRESTRICTED,
    SETTINGS_FILE,
    Settings,
    SettingsStore,
    derive_mac_key,
)
from pearl_connect.signer import Signer

from tests.conftest import TEST_PASSWORD

RPC_ENV = "GNOSIS_TESTNET_RPC"
MIDDLEWARE_ENV_FILE = (
    Path(__file__).parent.parent.parent / "olas-operate-middleware" / ".env"
)


def _resolve_rpc() -> str | None:
    """GNOSIS_TESTNET_RPC from the env, else from the middleware repo's .env."""
    if os.environ.get(RPC_ENV):
        return os.environ[RPC_ENV]
    try:
        for line in MIDDLEWARE_ENV_FILE.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == RPC_ENV and value.strip():
                return value.strip()
    except OSError:
        pass
    return None


RPC_URL = _resolve_rpc()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not RPC_URL, reason=f"{RPC_ENV} not set and {MIDDLEWARE_ENV_FILE} not usable"
    ),
]


def _set_balance(rpc_url: str, address: str, wei: int) -> None:
    response = httpx.post(
        rpc_url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tenderly_setBalance",
            "params": [[address], hex(wei)],
        },
        timeout=30,
    )
    response.raise_for_status()
    assert "result" in response.json(), response.text


@pytest.fixture(name="rpc_url")
def rpc_url_fixture() -> str:
    """Return the Tenderly fork RPC URL."""
    assert RPC_URL is not None
    return RPC_URL


@pytest.fixture(name="fork_config")
def fork_config_fixture(rpc_url: str, store_path: Path) -> AppConfig:
    """Return an AppConfig pointing at the Tenderly fork."""
    return AppConfig(
        chains={"gnosis": ChainConfig(rpc_url=rpc_url)},
        store_path=store_path,
    )


@pytest.fixture(name="fork_store")
def fork_store_fixture(account: LocalAccount, store_path: Path) -> SettingsStore:
    """Return the settings store for the fork; fresh -> restricted defaults."""
    return SettingsStore(
        store_path / SETTINGS_FILE, derive_mac_key(account), ActivityLog(store_path)
    )


@pytest.fixture(name="funded_signer")
def funded_signer_fixture(
    rpc_url: str,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> Signer:
    """Return a guarded signer whose EOA holds 1 xDAI on the fork."""
    _set_balance(rpc_url, account.address, 10**18)
    return Signer(
        account=account,
        config=fork_config,
        activity=ActivityLog(store_path),
        guard=Guard(fork_store, fork_config),
    )


def _fork_app(
    signer: Signer,
    config: AppConfig,
    store: SettingsStore,
    store_path: Path,
    token: str,
) -> object:
    activity = ActivityLog(store_path)
    guard = Guard(store, config)
    return create_app(
        signer=signer,
        config=config,
        activity=activity,
        token=token,
        guard=guard,
        settings_store=store,
        mech=MechService(signer, config, activity, guard),
    )


def _wait_mined(signer: Signer, tx_hash: str, timeout: float = 120) -> dict:
    w3 = signer.w3("gnosis")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
        except Exception:  # pylint: disable=broad-except
            time.sleep(3)
            continue
        assert receipt["status"] == 1
        return dict(receipt)
    raise AssertionError(f"tx {tx_hash} not mined within {timeout}s")


def test_sign_and_send_mines_on_fork(
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """A transfer sent through /sign-and-send is broadcast and mined."""
    fork_store.save(Settings(mode=MODE_UNRESTRICTED, whitelist={}))
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        request_id = f"it-{secrets.token_hex(8)}"
        payload = {
            "chain": "gnosis",
            "to": account.address,
            "value": 10**15,
            "data": "0x",
            "request_id": request_id,
        }
        headers = {"Authorization": f"Bearer {token}"}
        response = client.post("/sign-and-send", json=payload, headers=headers)
        assert response.status_code == 200, response.text
        tx_hash = response.json()["tx_hash"]

        # idempotent retry returns the same hash without a second broadcast
        retry = client.post("/sign-and-send", json=payload, headers=headers)
        assert retry.json()["tx_hash"] == tx_hash

    _wait_mined(funded_signer, tx_hash)


def test_funds_status_reports_live_balance(
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
) -> None:
    """/funds-status reflects the on-chain balance against the threshold."""
    fork_config.fund_requirements = {
        "gnosis": {"agent": {"0x" + "00" * 20: 2 * 10**18}}
    }
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, "t")
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        body = client.get("/funds-status").json()
    entry = body["gnosis"][funded_signer.address]["0x" + "00" * 20]
    assert int(entry["balance"]) > 0
    assert int(entry["deficit"]) == max(0, 2 * 10**18 - int(entry["balance"]))
    assert json.dumps(body)  # shape is JSON-serializable end-to-end


def test_restricted_mode_and_settings_flip(  # pylint: disable=too-many-arguments
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    keystore_dir: Path,
    account: LocalAccount,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh settings boot restricted; the password-authed endpoint flips them.

    Covers: blocked arbitrary transfer, allowed EOA->safe sweep, blocked raw
    digest signing, wrong password 401, and live effect of the mode change.
    """
    monkeypatch.chdir(keystore_dir)  # POST /settings re-decrypts the keystore
    fork_config.chains["gnosis"].safe_address = "0x" + "33" * 20
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        assert client.get("/settings").json()["mode"] == "restricted"
        assert client.get("/wallet", headers=headers).json()["mode"] == "restricted"

        # arbitrary transfer: blocked with the violated rule in the message
        blocked = client.post(
            "/sign-and-send",
            json={"chain": "gnosis", "to": account.address, "value": 1},
            headers=headers,
        )
        assert blocked.status_code == 400
        assert "restricted mode" in blocked.json()["detail"]

        # EOA -> safe native sweep: allowed and mined
        sweep = client.post(
            "/sign-and-send",
            json={
                "chain": "gnosis",
                "to": fork_config.chains["gnosis"].safe_address,
                "value": 10**12,
            },
            headers=headers,
        )
        assert sweep.status_code == 200, sweep.text
        _wait_mined(funded_signer, sweep.json()["tx_hash"])

        # raw digest signing: off in restricted mode
        digest_denied = client.post(
            "/sign-message", json={"digest": "0x" + "ab" * 32}, headers=headers
        )
        assert digest_denied.status_code == 400
        assert "restricted" in digest_denied.json()["detail"]

        # settings write: wrong password rejected, right one applies live
        denied = client.post(
            "/settings",
            json={
                "password": "wrong",
                "mode": "unrestricted",
                "whitelist": {},
            },  # nosec B105
        )
        assert denied.status_code == 401
        flipped = client.post(
            "/settings",
            json={"password": TEST_PASSWORD, "mode": "unrestricted", "whitelist": {}},
        )
        assert flipped.status_code == 200, flipped.text
        assert flipped.json()["mode"] == "unrestricted"

        allowed = client.post(
            "/sign-and-send",
            json={"chain": "gnosis", "to": account.address, "value": 1},
            headers=headers,
        )
        assert allowed.status_code == 200, allowed.text


def _deploy_safe(rpc_url: str, signer: Signer, account: LocalAccount) -> str:
    """Deploy a 1/1 Safe (v1.4.1 canonical) owned by the agent EOA on the fork."""
    from eth_typing import URI
    from safe_eth.eth import EthereumClient
    from safe_eth.safe import Safe
    from safe_eth.safe.safe_deployments import safe_deployments

    deployments = safe_deployments["1.4.1"]
    chain = "100"  # gnosis
    tx_sent = Safe.create(
        EthereumClient(URI(rpc_url)),
        deployer_account=account,
        master_copy_address=deployments["SafeL2"][chain][0],
        owners=[account.address],
        threshold=1,
        fallback_handler=deployments["CompatibilityFallbackHandler"][chain][0],
        proxy_factory_address=deployments["SafeProxyFactory"][chain][0],
    )
    _wait_mined(signer, tx_sent.tx_hash.hex())
    return str(tx_sent.contract_address)


def _pick_live_mech(mech_service: MechService) -> tuple[str, str] | None:
    """Find a native-payment mech (and a tool name) via the mech_tools surface.

    Exercises MechService.tools() against the live subgraph + fork. A missing
    tool list degrades to a default tool name: mech-client's tool validation
    is best-effort and no delivery can happen on a fork anyway.
    """
    listing = mech_service.tools(chain="gnosis")
    assert listing["mechs"], "subgraph returned no live mechs"
    for entry in listing["mechs"]:
        try:
            # some mechs may post-date the fork snapshot -> calls revert
            info = mech_service.tools(chain="gnosis", priority_mech=entry["address"])
        except Exception:  # pylint: disable=broad-except # nosec B112
            continue
        if info["payment_type"] == "NATIVE":
            tools = info.get("tools") or ["prediction-online"]
            return str(entry["address"]), str(tools[0])
    return None


def test_mech_request_on_fork_restricted_mode(
    rpc_url: str,
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """An on-chain mech request passes the restricted-mode gate end to end.

    The default whitelist (mech marketplace + trackers) is the only thing
    letting these safe transactions through — there is no bypass. No live
    mech serves a fork, so delivery cannot arrive; the assertions are the
    request-side effects: the safe's execTransaction to the marketplace
    mines and a request id is issued.
    """
    _set_balance(rpc_url, account.address, 10 * 10**18)
    safe_address = _deploy_safe(rpc_url, funded_signer, account)
    _set_balance(rpc_url, safe_address, 10 * 10**18)
    fork_config.chains["gnosis"].safe_address = safe_address

    activity = ActivityLog(store_path)
    guard = Guard(fork_store, fork_config)
    assert guard.mode() == "restricted"  # fresh store -> restricted defaults
    mech_service = MechService(funded_signer, fork_config, activity, guard)

    # off-chain requests are cleanly refused in restricted mode
    with pytest.raises(MechError, match="legacy_on_chain"):
        mech_service.request("test", "test", chain="gnosis")

    picked = _pick_live_mech(mech_service)
    if picked is None:
        pytest.skip("no live native-payment mech found on gnosis")
    assert picked is not None  # mypy: pytest.skip's NoReturn isn't visible
    mech_address, tool = picked

    result = mech_service.request(
        f"integration test {secrets.token_hex(4)}",
        tool,
        chain="gnosis",
        legacy_on_chain=True,
        priority_mech=mech_address,
        timeout=30,  # no delivery will come on a fork; don't wait the default 5m
    )
    assert result["tx_hash"], result
    assert result["request_ids"], result
    receipt = _wait_mined(funded_signer, result["tx_hash"])
    assert receipt["status"] == 1
