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
from pearl_connect.server.app import create_app
from pearl_connect.signer import Signer

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


@pytest.fixture(name="funded_signer")
def funded_signer_fixture(
    rpc_url: str,
    fork_config: AppConfig,
    store_path: Path,
    account: LocalAccount,
) -> Signer:
    """Return a signer whose EOA holds 1 xDAI on the fork."""
    _set_balance(rpc_url, account.address, 10**18)
    return Signer(
        account=account,
        config=fork_config,
        activity=ActivityLog(store_path),
    )


def _fork_app(
    signer: Signer,
    config: AppConfig,
    store_path: Path,
    token: str,
) -> object:
    activity = ActivityLog(store_path)
    return create_app(signer=signer, config=config, activity=activity, token=token)


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
    store_path: Path,
    account: LocalAccount,
) -> None:
    """A transfer sent through /sign-and-send is broadcast and mined."""
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, store_path, token)
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
    store_path: Path,
) -> None:
    """/funds-status reflects the on-chain balance against the threshold."""
    fork_config.fund_requirements = {
        "gnosis": {"agent": {"0x" + "00" * 20: 2 * 10**18}}
    }
    app = _fork_app(funded_signer, fork_config, store_path, "t")
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        body = client.get("/funds-status").json()
    entry = body["gnosis"][funded_signer.address]["0x" + "00" * 20]
    assert int(entry["balance"]) > 0
    assert int(entry["deficit"]) == max(0, 2 * 10**18 - int(entry["balance"]))
    assert json.dumps(body)  # shape is JSON-serializable end-to-end
