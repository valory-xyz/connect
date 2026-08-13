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

import contextlib
import json
import os
import secrets
import sys
import threading
import time
import typing as t
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
import uvicorn
from eth_account.signers.local import LocalAccount
from eth_typing import URI
from fastapi import FastAPI
from fastapi.testclient import TestClient
from mech_client.infrastructure.blockchain.abi_loader import get_abi
from mech_client.infrastructure.config import PaymentType
from safe_eth.eth import EthereumClient
from safe_eth.safe import Safe
from safe_eth.safe.safe_deployments import safe_deployments
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AGENT_HTTP_PORT, AppConfig, ChainConfig
from connect.guard import Guard
from connect.mech import MechError, MechService
from connect.mech_allowances import deposit_tracker, request_digest
from connect.server.app import create_app
from connect.settings import (
    MODE_UNRESTRICTED,
    Protected,
    SETTINGS_FILE,
    Settings,
    SettingsStore,
    _mech_system_addresses,
    derive_mac_key,
)
from connect.signer import Signer
from connect.workspace import Workspace

from tests.conftest import TEST_PASSWORD, audit_kinds

RPC_ENV = "GNOSIS_TESTNET_RPC"
POLYGON_RPC_ENV = "POLYGON_TESTNET_RPC"
MIDDLEWARE_ENV_FILE = (
    Path(__file__).parent.parent.parent / "olas-operate-middleware" / ".env"
)


def _resolve_rpc(name: str = RPC_ENV) -> str | None:
    """Return a testnet RPC from the env, else the middleware repo's .env."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in MIDDLEWARE_ENV_FILE.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name and value.strip():
                return value.strip()
    except OSError:
        pass
    return None


RPC_URL = _resolve_rpc()
POLYGON_RPC_URL = _resolve_rpc(POLYGON_RPC_ENV)

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
    """Return the settings store for the fork; fresh -> unrestricted defaults."""
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


_SKILLS = Path(__file__).resolve().parent.parent / "connect" / "assets" / "skills"
_PEARL_SCRIPTS = _SKILLS / "pearl-connect" / "scripts"
_POLYMARKET_SCRIPTS = _SKILLS / "connect-polymarket" / "scripts"


@contextlib.contextmanager
def _serving(app: FastAPI) -> t.Iterator[str]:
    """Serve the app on a real loopback socket, yielding its base URL.

    signer_client talks HTTP through urllib, so TestClient's in-process ASGI
    transport never exercises it — and URL handling is exactly where it broke.
    Port 0 keeps this off the agent's own 8716 if one is running locally.
    """
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 30
    while not server.started:
        if time.time() > deadline:  # pragma: no cover - startup failure
            raise AssertionError("uvicorn did not start within 30s")
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{server.servers[0].sockets[0].getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(timeout=30)


def test_signer_client_reaches_the_server_that_provisioned_it(
    rpc_url: str,
    funded_signer: Signer,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
) -> None:
    """The bundled client, the real .mcp.json and a live server, end to end.

    Two field bugs lived in this seam and unit tests missed both, because each
    side was only ever tested against a fixture of the other: the workspace
    writes a URL ending in "/mcp/" that the client must strip, and the client
    must read the /wallet shape the server actually serves.
    """
    sys.path.insert(0, str(_PEARL_SCRIPTS))
    import signer_client  # pylint: disable=import-outside-toplevel

    _set_balance(rpc_url, account.address, 10 * 10**18)
    safe_address = _deploy_safe(rpc_url, funded_signer, account)
    fork_config.chains["gnosis"].safe_address = safe_address

    token = secrets.token_urlsafe(16)
    provisioned = Workspace(store_path, token)
    assert provisioned.ensure() is True, provisioned.reason

    # the file the server really wrote, parsed by the real client
    base_url, parsed_token, root = signer_client.load_mcp_config_dir(store_path)
    assert parsed_token == token
    assert root == store_path.resolve()
    assert base_url == f"http://127.0.0.1:{AGENT_HTTP_PORT}"

    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    with _serving(app) as served_url:
        client = signer_client.SignerClient(served_url, parsed_token, "gnosis")
        gnosis = client.chain_info("gnosis")
        assert gnosis["rpc"] == rpc_url
        assert gnosis["safe"] == safe_address
        assert gnosis["actionable"] is True
        # the misleading error the field report chased: a chain that is simply
        # absent must be named as absent, not blamed on operator configuration
        with pytest.raises(signer_client.SignerRequestError) as excinfo:
            client.chain_info("polygon")
        assert "not configured" in str(excinfo.value)
        assert "gnosis" in str(excinfo.value)


@pytest.mark.skipif(
    not POLYGON_RPC_URL, reason=f"{POLYGON_RPC_ENV} not set and .env not usable"
)
def test_polymarket_token_constants_are_the_tokens_they_claim() -> None:
    """Resolve the skill's hardcoded Polygon tokens against the real chain.

    These decide which balance the operator is shown; a wrong address reports
    someone else's token, or zero, and a funded safe then looks empty. Symbol
    alone cannot police them — native USDC and bridged USDC.e BOTH report
    "USDC" on-chain, which is exactly how a funded safe gets read as holding
    none — so each is pinned by address here.
    """
    assert POLYGON_RPC_URL is not None
    w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL, request_kwargs={"timeout": 45}))
    try:
        chain_id = w3.eth.chain_id
    except Exception as e:  # pylint: disable=broad-except
        # a configured-but-dead endpoint (an expired fork answers 400) is a
        # missing tool, not a failing assertion about the constants
        pytest.skip(f"{POLYGON_RPC_ENV} is unreachable: {e}")
    if chain_id != 137:  # pragma: no cover - misconfigured endpoint
        pytest.skip(f"{POLYGON_RPC_ENV} is not Polygon (chain {chain_id})")

    sys.path.insert(0, str(_POLYMARKET_SCRIPTS))
    # tox.ini excludes connect-polymarket from mypy (it needs py_clob_client_v2
    # and a runtime sys.path insert), so this import is unresolvable by design
    import pm_common  # type: ignore[import-not-found] # pylint: disable=import-outside-toplevel

    abi = [
        {
            "name": n,
            "type": "function",
            "stateMutability": "view",
            "inputs": [],
            "outputs": [{"name": "", "type": t}],
        }
        for n, t in (("symbol", "string"), ("decimals", "uint8"))
    ]
    for address, symbol in (
        (pm_common.USDC, "USDC"),
        (pm_common.USDC_E, "USDC"),
        (pm_common.PUSD, "pUSD"),
    ):
        token = w3.eth.contract(address=address, abi=abi)
        assert token.functions.symbol().call() == symbol, address
        # every amount in the skill is converted with PUSD_DECIMALS
        assert token.functions.decimals().call() == pm_common.PUSD_DECIMALS, address
    # the two USDCs are distinct contracts despite sharing a symbol
    assert pm_common.USDC != pm_common.USDC_E


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
    """Fresh settings boot unrestricted; the password-authed endpoint flips them.

    Covers: the unrestricted default, the live effect of an operator opt-in
    to restricted (blocked arbitrary transfer, blocked bare transfer to the
    safe, blocked raw digest signing — refusals that never name a mode
    system), wrong password 401, the flip back — and the floor surviving it.
    """
    monkeypatch.chdir(keystore_dir)  # POST /settings re-decrypts the keystore
    fork_config.chains["gnosis"].safe_address = "0x" + "33" * 20
    token = secrets.token_urlsafe(16)
    app = _fork_app(funded_signer, fork_config, fork_store, store_path, token)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        assert client.get("/settings").json()["protected"]["mode"] == "unrestricted"
        # the agent-facing wallet endpoint says nothing about modes
        assert "mode" not in client.get("/wallet", headers=headers).json()

        # the operator opts into restricted mode with their password
        restricted = client.patch(
            "/settings",
            json={"password": TEST_PASSWORD, "protected": {"mode": "restricted"}},
        )
        assert restricted.status_code == 200, restricted.text
        assert restricted.json()["protected"]["mode"] == "restricted"

        # arbitrary transfer: blocked with the violated rule in the message —
        # which names the guardrail, never the mode system
        blocked = client.post(
            "/sign-and-send",
            json={"chain": "gnosis", "to": account.address, "value": 1},
            headers=headers,
        )
        assert blocked.status_code == 400
        assert "only allow transactions targeting" in blocked.json()["detail"]
        assert "restricted" not in blocked.json()["detail"]

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
        assert "to be execTransaction" in bare.json()["detail"]

        # raw digest signing: off while restricted, refused without naming it
        digest_denied = client.post(
            "/sign-message", json={"digest": "0x" + "ab" * 32}, headers=headers
        )
        assert digest_denied.status_code == 400
        assert "digest signing is disabled" in digest_denied.json()["detail"]
        assert "restricted" not in digest_denied.json()["detail"]

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
    # restricted mode is an operator opt-in now; set it explicitly, keeping
    # the default whitelist so the marketplace flow stays reachable
    fork_store.patch({"protected": {"mode": "restricted"}})
    guard = Guard(fork_store, fork_config)
    assert guard.mode() == "restricted"
    mech_service = MechService(funded_signer, fork_config, activity, guard)

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

    # No mech serves a fork, so this is the timed-out case for real: the paid
    # request must come back pollable rather than stranded, and a poll that
    # finds nothing must say so without consuming the id.
    assert result["pending_request_ids"], result
    pending_id = result["pending_request_ids"][0]

    # The block the resumed watch will scan from, taken from a REAL receipt.
    # Asserting only "not delivered" cannot catch a wrong window: on a fork
    # nothing ever delivers, so scanning the right blocks and scanning the
    # wrong ones give the same answer. This value differs between the two.
    pending = mech_service._pending[pending_id]  # pylint: disable=protected-access
    assert pending.from_block == receipt["blockNumber"]

    polled = mech_service.result(pending_id, timeout=5)
    assert polled["delivered"] is False
    assert polled["mech"] == mech_address
    assert mech_service.result(pending_id, timeout=5)["delivered"] is False


def test_offchain_request_digest_matches_contract_on_fork(rpc_url: str) -> None:
    """The locally derived request digest equals the contract's getRequestId.

    Restricted-mode off-chain requests sign only the digest the server
    recomputes itself (connect.mech_allowances.request_digest); if the deployed
    marketplace's derivation ever drifts from it — a redeploy, a VERSION
    bump — the allowance would stop matching and every restricted off-chain
    request would be refused. This pins the two against each other on the
    real (forked) contract, with the unit-test golden vector as the offline
    fallback.
    """
    marketplace = Web3.to_checksum_address(_mech_system_addresses()["gnosis"][0])
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    contract = w3.eth.contract(address=marketplace, abi=get_abi("MechMarketplace.json"))

    mech = Web3.to_checksum_address("0x" + "11" * 20)
    requester = Web3.to_checksum_address("0x" + "22" * 20)
    data_hash = bytes.fromhex("33" * 32)
    rate, payment_type, nonce = 7, bytes.fromhex("44" * 32), 9

    onchain = contract.functions.getRequestId(
        mech, requester, data_hash, rate, payment_type, nonce
    ).call()
    local = request_digest(
        domain_separator=bytes(contract.functions.domainSeparator().call()),
        marketplace=marketplace,
        mech=mech,
        requester=requester,
        data_hash=data_hash,
        delivery_rate=rate,
        payment_type=payment_type,
        nonce=nonce,
    )
    assert local == bytes(onchain)


class _LocalMechEndpoint:
    """A protocol-faithful local mech server for the off-chain flow.

    Implements the two endpoints mech-client talks to — POST
    /send_signed_requests and GET /fetch_offchain_info — with the validation
    a real mech performs before serving a request: the request id must equal
    the marketplace's getRequestId over the payload's own fields (read from
    the forked contract), the signature must validate via the sender Safe's
    ERC-1271 isValidSignature (agent mode, since mech-client 0.21.3), and the
    first request is answered HTTP 402 until the prepaid deposit actually
    lands on the balance tracker on-chain.
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        w3: t.Any,
        marketplace_contract: t.Any,
        mech: str,
        payment_type_hex: str,
        tracker: str,
        required: int,
    ) -> None:
        """Initialize with the chain handles validation needs."""
        self._w3 = w3
        self._contract = marketplace_contract
        self._mech = mech
        self._payment_type_hex = payment_type_hex
        self._tracker = Web3.to_checksum_address(tracker)
        self.required = required
        self.paid = 0  # tracker balance growth observed since start
        self._tracker_balance_start = int(
            w3.eth.get_balance(Web3.to_checksum_address(tracker))
        )
        self.saw_402 = False
        self.validation_errors: list[str] = []
        self.delivered: dict[str, dict] = {}

    def _validate(self, form: dict[str, str]) -> None:
        """Run the mech-side checks; record rather than raise, for assertions.

        Since mech-client 0.21.3 the agent-mode ``sender`` is the requester
        Safe and the signature is ERC-1271: validated by calling the real
        Safe's ``isValidSignature(bytes32,bytes)`` on the fork and expecting
        the magic value — exactly what the marketplace does at settlement.
        """
        request_id = int(form["request_id"])
        expected = self._contract.functions.getRequestId(
            Web3.to_checksum_address(self._mech),
            Web3.to_checksum_address(form["sender"]),
            bytes.fromhex(form["ipfs_hash"].removeprefix("0x")),
            int(form["delivery_rate"]),
            bytes.fromhex(self._payment_type_hex.removeprefix("0x")),
            int(form["nonce"]),
        ).call()
        if int.from_bytes(bytes(expected), "big") != request_id:
            self.validation_errors.append("request id != contract getRequestId")
        signature = bytes.fromhex(form["signature"].removeprefix("0x"))
        erc1271 = self._w3.eth.contract(
            address=Web3.to_checksum_address(form["sender"]),
            abi=[
                {
                    "name": "isValidSignature",
                    "inputs": [{"type": "bytes32"}, {"type": "bytes"}],
                    "outputs": [{"type": "bytes4"}],
                    "stateMutability": "view",
                    "type": "function",
                }
            ],
        )
        try:
            magic = erc1271.functions.isValidSignature(
                request_id.to_bytes(32, "big"), signature
            ).call()
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.validation_errors.append(f"isValidSignature reverted: {e}")
            return
        if bytes(magic) != bytes.fromhex("1626ba7e"):
            self.validation_errors.append(f"isValidSignature returned {magic!r}")

    def handle_send(self, form: dict[str, str]) -> tuple[int, dict]:
        """POST /send_signed_requests: 402 until the deposit is on the tracker."""
        self._validate(form)
        self.paid = (
            int(self._w3.eth.get_balance(self._tracker)) - self._tracker_balance_start
        )
        if self.paid < self.required:
            self.saw_402 = True
            return 402, {
                "required": str(self.required),
                "currentBalance": str(self.paid),
                "payTo": self._tracker,
                "asset": "",
                "chainId": 100,
                "error": "payment required",
            }
        self.delivered[form["request_id"]] = {
            "requestId": form["request_id"],
            "result": json.dumps({"answer": "e2e", "tool": "integration"}),
        }
        return 200, {"request_id": form["request_id"]}

    def handle_fetch(self, form: dict[str, str]) -> tuple[int, dict]:
        """GET /fetch_offchain_info: {} until delivered, then the answer."""
        return 200, self.delivered.get(form.get("request_id", ""), {})


@contextlib.contextmanager
def _serving_mech_endpoint(endpoint: _LocalMechEndpoint) -> t.Iterator[str]:
    """Serve the local mech endpoint on a loopback socket, yielding its URL."""

    class _Handler(BaseHTTPRequestHandler):
        """Route the two mech endpoints to the stub, urlencoded like requests."""

        def _reply(self, status: int, payload: dict) -> None:
            """Serialize one JSON response."""
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _form(self) -> dict[str, str]:
            """Read the urlencoded body (requests sends data=dict that way)."""
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length).decode()
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def do_POST(self) -> None:  # noqa: N802
            """Handle /send_signed_requests."""
            assert self.path.endswith("/send_signed_requests"), self.path
            self._reply(*endpoint.handle_send(self._form()))

        def do_GET(self) -> None:  # noqa: N802
            """Handle /fetch_offchain_info."""
            assert self.path.endswith("/fetch_offchain_info"), self.path
            self._reply(*endpoint.handle_fetch(self._form()))

        def log_message(self, *args: t.Any) -> None:
            """Keep the test output quiet."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join(timeout=10)


def test_offchain_request_end_to_end_restricted_on_fork(  # pylint: disable=too-many-locals,too-many-statements
    rpc_url: str,
    fork_config: AppConfig,
    fork_store: SettingsStore,
    store_path: Path,
    account: LocalAccount,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The full restricted off-chain flow, request to delivery, on the fork.

    One guard instance shared by signer and mech service (the __main__
    wiring): the digest the flow signs is derived against the real forked
    marketplace and validated mech-side by the local endpoint, the HTTP 402
    triggers a real safe -> tracker deposit that must pass the guard through
    its one-shot allowance, and the retried request is served and delivered.
    A second request rides the now-funded balance straight through — the
    no-402 path — proving the deposit allowance is not needed twice.

    The mech endpoint is local (no live mech serves a fork); everything else
    — marketplace reads, nonces, digests, signing, the deposit transaction —
    is real chain state. Only the metadata document is stubbed to point the
    flow at the local endpoint, since its `url` field is exactly what is
    being stood in for.
    """
    _set_balance(rpc_url, account.address, 10**18)
    activity = ActivityLog(store_path)
    # restricted mode is an operator opt-in now; set it explicitly, keeping
    # the default whitelist so the marketplace flow stays reachable
    fork_store.patch({"protected": {"mode": "restricted"}})
    guard = Guard(fork_store, fork_config)
    signer = Signer(account=account, config=fork_config, activity=activity, guard=guard)
    safe_address = _deploy_safe(rpc_url, signer, account)
    _set_balance(rpc_url, safe_address, 10**18)
    fork_config.chains["gnosis"].safe_address = safe_address
    assert guard.mode() == "restricted"
    mech_service = MechService(signer, fork_config, activity, guard)

    picked = _pick_live_mech(mech_service)
    if picked is None:
        pytest.skip("no live native-payment mech found on gnosis")
    assert picked is not None  # mypy: pytest.skip's NoReturn isn't visible
    mech_address, tool = picked

    # price the mech as the flow will, and resolve the tracker our way
    service = mech_service._service("gnosis")  # pylint: disable=protected-access
    # pylint: disable-next=protected-access
    _, service_id, rate = service._fetch_mech_info(mech_address)
    tracker, is_token = deposit_tracker("gnosis", PaymentType.NATIVE.value)
    assert tracker is not None
    assert is_token is False

    w3 = signer.w3("gnosis")
    endpoint = _LocalMechEndpoint(
        w3=w3,
        # pylint: disable-next=protected-access
        marketplace_contract=service._get_marketplace_contract(),
        mech=mech_address,
        payment_type_hex="0x" + PaymentType.NATIVE.value,
        tracker=tracker,
        required=int(rate),
    )
    safe_balance_before = int(
        w3.eth.get_balance(Web3.to_checksum_address(safe_address))
    )
    with _serving_mech_endpoint(endpoint) as url:
        # the metadata document is the only stub: its `url` names the mech
        # endpoint, and reachability pre-flight + send both read it
        monkeypatch.setattr(
            service.tool_manager,
            "fetch_tools_metadata",
            lambda sid: {"tools": [tool], "url": url},
        )
        monkeypatch.setattr(service.tool_manager, "get_offchain_url", lambda sid: url)
        first = mech_service.request(
            f"integration offchain {secrets.token_hex(4)}",
            tool,
            chain="gnosis",
            priority_mech=mech_address,
            timeout=60,
            max_payment=10**18,
        )
        second = mech_service.request(
            f"integration offchain {secrets.token_hex(4)}",
            tool,
            chain="gnosis",
            priority_mech=mech_address,
            timeout=60,
            max_payment=10**18,
        )

    # the mech-side validation a real mech performs all passed
    assert endpoint.validation_errors == []
    # the 402 fired, and the deposit it demanded landed on the tracker; the
    # safe paid exactly the shortfall (the fork is shared, so the tracker's
    # own growth is only bounded from below)
    assert endpoint.saw_402 is True
    assert endpoint.paid >= endpoint.required
    assert (
        int(w3.eth.get_balance(Web3.to_checksum_address(safe_address)))
        == safe_balance_before - endpoint.required
    )
    # both requests were served and delivered
    for result in (first, second):
        assert result["request_ids"], result
        assert result["delivery_results"], result
        assert not result.get("pending_request_ids"), result
    # the audit trail shows the allowances, the signatures, and no refusal
    kinds = audit_kinds(store_path)
    assert kinds.count("mech_offchain_digest") == 2
    assert kinds.count("mech_deposit_allowance") == 2  # armed per request
    assert kinds.count("sign_message") == 2
    assert kinds.count("mech_request") == 2
    assert "blocked" not in kinds
    assert "mech_request_blocked" not in kinds
