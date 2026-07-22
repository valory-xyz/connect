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
import typing as t
from pathlib import Path

import httpx
import pytest
from eth_account.signers.local import LocalAccount
from fastapi import FastAPI
from fastapi.testclient import TestClient
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig, ChainConfig
from connect.guard import Guard
from connect.mech import MechError, MechService
from connect.server.app import create_app
from connect.settings import (
    MODE_UNRESTRICTED,
    Protected,
    SETTINGS_FILE,
    Settings,
    SettingsStore,
    derive_mac_key,
)
from connect.signer import Signer
from connect.workspace import Workspace

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
) -> FastAPI:
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
        workspace=Workspace(store_path, token),
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
    fork_store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
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


def test_safe_transaction_mines_a_server_composed_call_on_fork(
    rpc_url: str,
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """A safe_transaction the server composed executes on a real Safe.

    This is the test that proves the pre-validated signature: a wrong r/s/v
    would make the real Safe reject execTransaction and the tx would revert
    (status 0), failing _wait_mined. The server composes the call, the Safe
    accepts it, and the value leaves the *safe* — not the EOA — and arrives.
    FakeW3 never checks a signature; this is the one place the encoding meets a
    real contract.
    """
    _set_balance(rpc_url, account.address, 10**18)  # gas for deploy + broadcast
    safe_address = _deploy_safe(rpc_url, funded_signer, account)
    _set_balance(rpc_url, safe_address, 5 * 10**18)
    fork_config.chains["gnosis"].safe_address = safe_address
    fork_store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)

    w3 = funded_signer.w3("gnosis")
    # a random recipient, not a fixed one: the fork persists state across runs,
    # so a reused address would already hold what a prior run sent it
    recipient = Web3.to_checksum_address("0x" + secrets.token_hex(20))
    before = w3.eth.get_balance(recipient)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        response = client.post(
            "/safe-transaction",
            json={
                "chain": "gnosis",
                "to": recipient,  # the call the *safe* makes
                "value": 10**17,
                "request_id": f"it-{secrets.token_hex(8)}",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, response.text
        tx_hash = response.json()["tx_hash"]

    receipt = _wait_mined(funded_signer, tx_hash)  # asserts status == 1
    # the execTransaction ran, and the value moved out of the SAFE to the target
    assert receipt["to"].lower() == safe_address.lower()  # outer tx hit the safe
    assert w3.eth.get_balance(recipient) == before + 10**17


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

    Covers: blocked arbitrary transfer, blocked bare transfer to the safe,
    blocked raw digest signing, wrong password 401, the live effect of the mode
    change — and the floor surviving it.
    """
    monkeypatch.chdir(keystore_dir)  # POST /settings re-decrypts the keystore
    fork_config.chains["gnosis"].safe_address = "0x" + "33" * 20
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        assert client.get("/settings").json()["protected"]["mode"] == "restricted"
        assert client.get("/wallet", headers=headers).json()["mode"] == "restricted"

        # arbitrary transfer: blocked with the violated rule in the message
        blocked = client.post(
            "/sign-and-send",
            json={"chain": "gnosis", "to": account.address, "value": 1},
            headers=headers,
        )
        assert blocked.status_code == 400
        assert "restricted mode" in blocked.json()["detail"]

        # even a bare transfer to the safe is refused: funding the safe is the
        # operator's job, and a permission the agent never needed is one the
        # gate should not carry
        bare = client.post(
            "/sign-and-send",
            json={
                "chain": "gnosis",
                "to": fork_config.chains["gnosis"].safe_address,
                "value": 10**12,
            },
            headers=headers,
        )
        assert bare.status_code == 400
        assert "must be execTransaction" in bare.json()["detail"]

        # raw digest signing: off in restricted mode
        digest_denied = client.post(
            "/sign-message", json={"digest": "0x" + "ab" * 32}, headers=headers
        )
        assert digest_denied.status_code == 400
        assert "restricted" in digest_denied.json()["detail"]

        # settings write: wrong password rejected, right one applies live
        denied = client.patch(
            "/settings",
            json={
                "password": "wrong",
                "protected": {"mode": "unrestricted"},
            },  # nosec B105
        )
        assert denied.status_code == 401
        flipped = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "unrestricted"}},
        )
        assert flipped.status_code == 200, flipped.text
        assert flipped.json()["protected"]["mode"] == "unrestricted"

        allowed = client.post(
            "/sign-and-send",
            json={"chain": "gnosis", "to": account.address, "value": 1},
            headers=headers,
        )
        assert allowed.status_code == 200, allowed.text

        # ...but the floor does not move with the mode. Unrestricted widens the
        # gate; it does not open the one door that would outlast it — a module
        # or owner installed here would keep moving funds after the operator
        # switched back, and the switch would have meant nothing.
        safe_address = fork_config.chains["gnosis"].safe_address
        self_call = client.post(
            "/safe-transaction",
            json={"chain": "gnosis", "to": safe_address, "data": "0x610b5925"},
            headers=headers,
        )
        assert self_call.status_code == 400
        assert "may not call itself" in self_call.json()["detail"]


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


def test_wallet_reports_only_actionable_chains_on_fork(
    rpc_url: str,
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """GET /wallet names the chains that can be acted on, against a real chain.

    The reported bug was an agent treating every configured chain as its own
    to work. A unit test can assert the verdict over fakes; only a real chain
    proves the balances behind it are read correctly — so this deploys a safe,
    adds a second configured chain that was never deployed to, and then
    removes the EOA's gas to check the deployed chain drops out as well.
    """
    _set_balance(rpc_url, account.address, 10 * 10**18)
    safe_address = _deploy_safe(rpc_url, funded_signer, account)
    fork_config.chains["gnosis"].safe_address = safe_address
    # the shape that made an agent believe it had work to do elsewhere
    fork_config.chains["undeployed"] = ChainConfig(rpc_url=rpc_url)

    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        body = client.get("/wallet", headers=headers).json()

        assert body["actionable_chains"] == ["gnosis"]
        gnosis = body["chains"]["gnosis"]
        assert gnosis["safe"] == safe_address
        assert gnosis["actionable"] is True
        assert "not_actionable_because" not in gnosis
        assert int(gnosis["balances"]["agent_eoa"]) > 0
        undeployed = body["chains"]["undeployed"]
        assert undeployed["safe"] is None
        assert (
            undeployed["not_actionable_because"] == "not deployed here: no service safe"
        )

        # a deployed chain whose EOA cannot pay gas is not actionable either
        _set_balance(rpc_url, account.address, 0)
        drained = client.get("/wallet", headers=headers).json()
        assert drained["actionable_chains"] == []
        assert "no gas" in drained["chains"]["gnosis"]["not_actionable_because"]

    # leave the fork funded: its state persists across runs
    _set_balance(rpc_url, account.address, 10 * 10**18)


def _iter_gnosis_mechs(
    mech_service: MechService, limit: int | None = None
) -> t.Iterator[tuple[str, dict]]:
    """Yield (address, mech_tools report) for live gnosis mechs.

    Exercises MechService.tools() against the live subgraph + fork. Mechs that
    post-date the fork snapshot revert on the info call; that is expected here
    and skipped rather than failed.
    """
    listing = mech_service.tools(chain="gnosis")
    assert listing["mechs"], "subgraph returned no live mechs"
    entries = listing["mechs"] if limit is None else listing["mechs"][:limit]
    for entry in entries:
        try:
            info = mech_service.tools(chain="gnosis", priority_mech=entry["address"])
        except Exception:  # pylint: disable=broad-except # nosec B112
            continue
        yield str(entry["address"]), info


def _pick_live_mech(mech_service: MechService) -> tuple[str, str] | None:
    """Find a native-payment mech (and a tool name) via the mech_tools surface.

    A missing tool list degrades to a default tool name: mech-client's tool
    validation is best-effort and no delivery can happen on a fork anyway.
    """
    for address, info in _iter_gnosis_mechs(mech_service):
        if info["payment_type"] == "NATIVE":
            tools = info.get("tools") or ["prediction-online"]
            return address, str(tools[0])
    return None


def _pick_offchain_incapable_mech(
    mech_service: MechService,
) -> tuple[tuple[str, dict] | None, int]:
    """Find a live mech the off-chain flow cannot reach, and how many were read.

    Reachability is decided by the `url` field of the mech's published service
    metadata, which is real network state no fixture can stand in for — hence
    reading it here, from the live subgraph and the live gateway.

    The count comes back so the caller can tell "none of the mechs I read was
    unreachable" from "I could not read any mech" — those look identical from
    a bare None, and only the first says anything about reachability.
    """
    read = 0
    # bounded: each unreadable mech costs a full gateway timeout
    for address, info in _iter_gnosis_mechs(mech_service, limit=6):
        read += 1
        assert isinstance(info["offchain_capable"], bool), info
        if not info["offchain_capable"]:
            assert info["offchain_note"], info
            return (address, info), read
    return None, read


def test_offchain_preflight_refuses_an_unreachable_mech_on_fork(
    rpc_url: str,
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """An off-chain request to a mech with no endpoint is refused before paying.

    This is the reported failure, against real metadata: mech-client would
    discover the missing endpoint deep in its send path and report it as a
    metadata problem, which reads like a slow gateway. The pre-flight has to
    decide it up front, in unrestricted mode where nothing else would stop it,
    and leave the safe untouched.
    """
    _set_balance(rpc_url, account.address, 10 * 10**18)
    safe_address = _deploy_safe(rpc_url, funded_signer, account)
    _set_balance(rpc_url, safe_address, 10 * 10**18)
    fork_config.chains["gnosis"].safe_address = safe_address
    fork_store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))

    activity = ActivityLog(store_path)
    guard = Guard(fork_store, fork_config)
    assert guard.mode() == MODE_UNRESTRICTED  # the guardrail is not what refuses here
    mech_service = MechService(funded_signer, fork_config, activity, guard)

    picked, read = _pick_offchain_incapable_mech(mech_service)
    if picked is None:
        # say what was actually established: reading nothing proves nothing
        pytest.skip(f"all {read} gnosis mech(s) read published an off-chain endpoint")
    assert picked is not None  # mypy: pytest.skip's NoReturn isn't visible
    mech_address, info = picked

    w3 = funded_signer.w3("gnosis")
    eoa = Web3.to_checksum_address(funded_signer.address)
    nonce_before = w3.eth.get_transaction_count(eoa)
    with pytest.raises(MechError, match="cannot serve off-chain requests"):
        mech_service.request(
            "integration preflight",
            (info.get("tools") or ["prediction-online"])[0],
            chain="gnosis",
            priority_mech=mech_address,
            timeout=30,
            max_payment=10**18,
        )
    # refused before payment: nothing was broadcast, so no nonce was consumed
    assert w3.eth.get_transaction_count(eoa) == nonce_before


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
    with pytest.raises(MechError, match="retry it on-chain"):
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
        max_payment=10**18,  # live mech prices vary; the cap itself is unit-tested
    )
    assert result["tx_hash"], result
    assert result["request_ids"], result
    receipt = _wait_mined(funded_signer, result["tx_hash"])
    assert receipt["status"] == 1
