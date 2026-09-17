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

"""Shared pytest fixtures."""

import io
import json
import sys
import threading
import typing as t
import urllib.request
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import TimeExhausted, TransactionNotFound

from connect.activity import ACTIVITY_LOG_FILE, ActivityLog
from connect.config import AppConfig, ChainConfig
from connect.guard import Guard
from connect.mech import MechService
from connect.server.app import create_app
from connect.settings import (
    MODE_UNRESTRICTED,
    Protected,
    SETTINGS_FILE,
    Settings,
    SettingsStore,
    derive_mac_key,
)
from connect.signer import Signer, _ChainState
from connect.workspace import Workspace

TEST_PASSWORD = "test-password"  # nosec B105

ASSETS = Path(__file__).resolve().parent.parent / "connect" / "assets"
PONS_SCRIPTS = ASSETS / "skills" / "connect-pons" / "scripts"
sys.path.insert(0, str(ASSETS / "lib"))
sys.path.insert(0, str(PONS_SCRIPTS))

import curve  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import discovery  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import ipfs  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import launch  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import pons  # noqa: E402  pylint: disable=wrong-import-position
import router  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import tokens  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import trade  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import
import uniswap  # noqa: E402  pylint: disable=wrong-import-position
import web  # noqa: E402,F401  pylint: disable=wrong-import-position,unused-import

TOKEN = to_checksum_address("0x19D861Fc391E70a7FA49f4FBf56588dFC5572BB0")
OTHER = to_checksum_address("0x51250B135174Ca09450EC01c4afF73CF69DBb590")
CURVE = to_checksum_address("0x470701688607CC0583417b07a2C8E5c675c31305")
DEPLOYER = to_checksum_address("0x490c9a6E2784243C435d21F79448283085C26fc1")
V3_FACTORY = uniswap.DEPLOYMENTS[4663]["v3_factory"]
STATE_VIEW = uniswap.DEPLOYMENTS[4663]["v4_state_view"]


def _word(value: int) -> bytes:
    """One ABI word."""
    return value.to_bytes(32, "big")


def _text(value: str) -> bytes:
    """Encode a string return."""
    return abi_encode(["string"], [value])


def _v2_record(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    token: str = TOKEN,
    pair: str = pons.USDG,
    phase: int = 0,
    exists: bool = True,
    fee: int = 0,
    spacing: int = 200,
    creator: str = DEPLOYER,
) -> bytes:
    """Encode a V2 factory LaunchedToken return."""
    record = pons.V2Record(
        token=token,
        curve=CURVE,
        deployer=DEPLOYER,
        creatorFeeRecipient=creator,
        pairToken=pair,
        graduationThreshold=8090,
        poolFee=fee,
        tickSpacing=spacing,
        creatorTaxBps=100,
        buybackEnabled=True,
        phase=phase,
        sweptQuote=0,
        sweptTokens=0,
        sweptAt=0,
        exists=exists,
    )
    return abi_encode([pons.V2_RECORD], [record])


def _v1_record(
    token: str = TOKEN, paired: str = pons.WETH, exists: bool = True
) -> bytes:
    """Encode a V1 factory LaunchedToken return."""
    record = pons.V1Record(
        token=token,
        deployer=DEPLOYER,
        pairedToken=paired,
        positionManager=DEPLOYER,
        positionId=1,
        dexId=0,
        launchConfigId=0,
        restrictionsEndBlock=0,
        supply=10**27,
        isToken0=False,
        poolFee=10000,
        exists=exists,
        initialBuyAmount=0,
    )
    return abi_encode([pons.V1_RECORD], [record])


class _Eth:
    """A scripted eth namespace: calls answered by (to, calldata prefix)."""

    def __init__(self, chain: "Chain") -> None:
        """Bind to the chain script."""
        self._chain = chain
        self.block_number = chain.head

    def call(self, tx: dict) -> bytes:
        """Answer an eth_call from the script."""
        return self._chain.answer(tx["to"], bytes(tx["data"]))

    def get_logs(self, query: dict) -> list:
        """Answer a log query from the script."""
        return self._chain.logs(query)


class Chain:
    """Scripted chain state for one test."""

    def __init__(self) -> None:
        """Start empty: every unknown call is a test bug."""
        self.head = 30_000_000
        self.calls: dict[tuple[str, bytes], bytes] = {}
        self.names: dict[str, tuple[str, str]] = {}
        self.feed_logs: dict[bytes, list[tuple[int, str]]] = {}
        self.log_queries: list[dict] = []
        self.log_errors: list[Exception] = []
        self.multicall_short = False
        self.eth = _Eth(self)

    def on(self, to: str, data: bytes, result: bytes) -> None:
        """Script one call; data is matched as a prefix."""
        self.calls[(to_checksum_address(to), data)] = result

    def answer(self, to: str, data: bytes) -> bytes:
        """Find the scripted answer for a call."""
        to = to_checksum_address(to)
        if to == evm.MULTICALL3:
            return self._multicall(data)
        for (where, prefix), result in self.calls.items():
            if where == to and data.startswith(prefix):
                return result
        raise AssertionError(f"unscripted eth_call to {to}: {data.hex()}")

    def _multicall(self, data: bytes) -> bytes:
        """Answer an aggregate3 of name()/symbol() reads."""
        assert data.startswith(evm.SEL_AGGREGATE3)
        (calls,) = abi_decode(["(address,bool,bytes)[]"], data[4:])
        results = []
        for target, _, calldata in calls:
            known = self.names.get(to_checksum_address(target))
            if known is None:
                results.append((False, b""))
            elif known == ("bad", "bad"):
                results.append((True, b"\x01"))
            else:
                text = known[0] if calldata == evm.SEL_NAME else known[1]
                results.append((True, _text(text)))
        if self.multicall_short:
            results = results[:-1]
        return abi_encode(["(bool,bytes)[]"], [results])

    def logs(self, query: dict) -> list:
        """Answer a log query, or raise a scripted error first."""
        self.log_queries.append(query)
        if self.log_errors:
            raise self.log_errors.pop(0)
        topic = bytes.fromhex(query["topics"][0][2:])
        return [
            {
                "blockNumber": block,
                "topics": [topic, bytes(12) + bytes.fromhex(tok[2:])],
            }
            for block, tok in self.feed_logs.get(topic, [])
            if query["fromBlock"] <= block <= query["toBlock"]
        ]


def _identity(chain: Chain, token: str) -> None:
    """Script a token's name, symbol and decimals."""
    chain.on(token, evm.SEL_NAME, _text("Pons"))
    chain.on(token, evm.SEL_SYMBOL, _text("PONS"))
    chain.on(token, evm.SEL_DECIMALS, _word(18))


def _not_v2(chain: Chain, token: str) -> None:
    """Script the V2 factory to know nothing of a token."""
    chain.on(
        pons.V2_FACTORY,
        pons.SEL_GET_LAUNCHED + abi_encode(["address"], [token]),
        _v2_record(exists=False),
    )


def _v2(chain: Chain, token: str = TOKEN, **record: t.Any) -> None:
    """Script a V2 launch on a USDG curve (unless overridden)."""
    chain.on(
        pons.V2_FACTORY,
        pons.SEL_GET_LAUNCHED + abi_encode(["address"], [token]),
        _v2_record(token=token, **record),
    )
    _identity(chain, token)
    chain.on(pons.USDG, evm.SEL_SYMBOL, _text("USDG"))
    chain.on(pons.USDG, evm.SEL_DECIMALS, _word(6))
    chain.on(CURVE, pons.SEL_FEE_BPS, _word(100))
    chain.on(
        pons.V2_FACTORY,
        pons.SEL_FEE_POLICY + abi_encode(["address"], [token]),
        abi_encode([pons.FEE_POLICY], [(DEPLOYER, 3000, 5000, 250, 300)]),
    )


def _v1(chain: Chain, token: str = TOKEN, factory: int = 0, **record: t.Any) -> None:
    """Script a V1 launch whose v3 pool the Uniswap factory agrees with."""
    _not_v2(chain, token)
    lookup = pons.SEL_GET_LAUNCHED + abi_encode(["address"], [token])
    for position, where in enumerate(pons.V1_FACTORIES):
        found = position == factory
        chain.on(where, lookup, _v1_record(token=token, exists=found, **record))
    _identity(chain, token)
    chain.on(pons.WETH, evm.SEL_DECIMALS, _word(18))
    pool = uniswap.pool_address(4663, token, pons.WETH, 10000)
    chain.on(V3_FACTORY, uniswap.SEL_GET_POOL, _word(int(pool, 16)))


@pytest.fixture(name="chain")
def chain_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Chain:
    """Provide a scripted chain, a clean cwd and no pauses between requests."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(discovery, "REQUEST_PAUSE_S", 0)
    monkeypatch.setattr(discovery.time, "sleep", lambda _s: None)
    return Chain()


@pytest.fixture
def account() -> LocalAccount:
    """Throwaway agent EOA."""
    return Account.create()


@pytest.fixture
def keystore_dir(tmp_path: Path, account: LocalAccount) -> Path:
    """Directory holding an encrypted keystore for the throwaway EOA."""
    keystore = Account.encrypt(account.key, TEST_PASSWORD)
    (tmp_path / "ethereum_private_key.txt").write_text(json.dumps(keystore))
    return tmp_path


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    """Temporary persistent_data dir."""
    store = tmp_path / "persistent_data"
    store.mkdir()
    return store


def audit_entries(store_path: Path) -> list[dict]:
    """Read the audit trail as the operator reads it: the log file on disk.

    The one source of truth for what was recorded — the server keeps no
    in-memory copy to assert against, so a test that passes here passes
    against the artifact itself.
    """
    path = store_path / ACTIVITY_LOG_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def audit_kinds(store_path: Path) -> list[str]:
    """Return the recorded kinds, in order."""
    return [entry["kind"] for entry in audit_entries(store_path)]


@pytest.fixture
def app_config(store_path: Path) -> AppConfig:
    """Config with one fake chain."""
    return AppConfig(
        chains={
            "testchain": ChainConfig(
                rpc_url="http://127.0.0.1:9",  # never actually contacted in unit tests
                safe_address="0x" + "22" * 20,
            )
        },
        store_path=store_path,
    )


class FakeEth:
    """Minimal Web3.eth stand-in for signer tests."""

    def __init__(self) -> None:
        """Initialize."""
        self.sent: list[bytes] = []
        self.pending_nonce = 5
        self.receipt: dict | None = None
        self.balance = 12345
        self.fail_broadcast = False
        self.base_fee: int | None = 10**9
        self.priority_fee_raises = False
        self._lock = threading.Lock()

    def get_balance(self, address: str) -> int:
        """Return the fixed balance."""
        return self.balance

    def get_transaction_receipt(self, tx_hash: object) -> dict:
        """Return the configured receipt or raise TransactionNotFound (as web3 does)."""
        if self.receipt is None:
            raise TransactionNotFound(f"{tx_hash!r} not mined")
        return self.receipt

    def wait_for_transaction_receipt(
        self, tx_hash: object, timeout: float = 120, poll_latency: float = 0.1
    ) -> dict:
        """Return the configured receipt or raise TimeExhausted."""
        if self.receipt is None:
            raise TimeExhausted(f"tx not mined within {timeout}s")
        return self.receipt

    def get_transaction_count(
        self, address: str, block_identifier: str | None = None
    ) -> int:
        """Return the fixed pending nonce."""
        return self.pending_nonce

    def estimate_gas(self, tx: dict) -> int:
        """Return a fixed gas estimate."""
        return 21_000

    def get_block(self, _: str) -> dict:
        """Return a block, with a base fee unless configured legacy."""
        if self.base_fee is None:
            return {}
        return {"baseFeePerGas": self.base_fee}

    @property
    def max_priority_fee(self) -> int:
        """Return a fixed priority fee, or raise if configured to."""
        if self.priority_fee_raises:
            raise RuntimeError("no eth_maxPriorityFeePerGas")
        return 10**9

    @property
    def gas_price(self) -> int:
        """Return a fixed legacy gas price."""
        return 2 * 10**9

    def send_raw_transaction(self, raw: bytes) -> HexBytes:
        """Record the raw tx and return its keccak hash."""
        if self.fail_broadcast:
            raise ValueError("nonce too low")
        with self._lock:
            self.sent.append(bytes(raw))
        return HexBytes(Web3.keccak(bytes(raw)))


class FakeMiddlewareOnion:
    """Records middleware injections (the signer adds the PoA middleware)."""

    def __init__(self) -> None:
        """Initialize."""
        self.injected: list = []

    def inject(self, middleware: object, layer: int = 0) -> None:
        """Record an injection."""
        self.injected.append((middleware, layer))


class FakeW3:
    """Minimal Web3 stand-in for signer tests."""

    def __init__(self) -> None:
        """Initialize."""
        self.eth = FakeEth()
        self.middleware_onion = FakeMiddlewareOnion()

    def to_wei(self, value: float, unit: str) -> int:
        """Convert gwei to wei."""
        assert unit == "gwei"
        return int(value * 10**9)


@pytest.fixture
def fake_w3() -> FakeW3:
    """Fake Web3 client."""
    return FakeW3()


@pytest.fixture
def activity(store_path: Path) -> ActivityLog:
    """Activity log writing into the temp store."""
    return ActivityLog(store_path)


@pytest.fixture
def test_signer(
    account: LocalAccount, app_config: AppConfig, activity: ActivityLog, fake_w3: FakeW3
) -> Signer:
    """Signer wired to the fake Web3 client."""
    signer = Signer(account=account, config=app_config, activity=activity)
    signer._chains._states["testchain"] = (  # pylint: disable=protected-access
        _ChainState(w3=t.cast(Web3, fake_w3), lock=threading.Lock(), chain_id=31337)
    )
    return signer


@pytest.fixture
def settings_store(
    account: LocalAccount, store_path: Path, activity: ActivityLog
) -> SettingsStore:
    """Build a settings store pre-set to unrestricted so legacy tests keep signing.

    Pre-saving (rather than relying on the unrestricted defaults) keeps the
    file's whitelist empty and deterministic; restricted mode and its rules
    are exercised explicitly by the guard/settings tests.
    """
    store = SettingsStore(store_path / SETTINGS_FILE, derive_mac_key(account), activity)
    store.save(Settings(protected=Protected(mode=MODE_UNRESTRICTED, whitelist={})))
    return store


@pytest.fixture
def guard(settings_store: SettingsStore, app_config: AppConfig) -> Guard:
    """Guard over the unrestricted test settings store."""
    return Guard(settings_store, app_config)


@pytest.fixture
def mech_service(
    test_signer: Signer, app_config: AppConfig, activity: ActivityLog, guard: Guard
) -> MechService:
    """Mech service over the fake-backed signer (never contacts a chain)."""
    return MechService(test_signer, app_config, activity, guard)


@pytest.fixture
def make_app(
    guard: Guard, settings_store: SettingsStore, mech_service: MechService
) -> t.Callable:
    """Return an app factory threading the guard/settings/mech wiring."""

    def _make(
        signer: Signer,
        config: AppConfig,
        activity: ActivityLog,
        token: str = "tok",  # nosec B107
    ) -> t.Any:
        # the app's signing endpoints must honor the same guard the app serves
        signer.set_guard(guard)
        return create_app(
            signer=signer,
            config=config,
            activity=activity,
            token=token,
            guard=guard,
            settings_store=settings_store,
            mech=mech_service,
            # unpopulated, as at boot: the first /healthcheck or /session
            # populates it — so a test that needs it broken breaks populate(),
            # rather than reaching into the app's state to fake a flag
            workspace=Workspace(config.store_path, token),
        )

    return _make


class _Response(io.BytesIO):
    """A urlopen response."""

    def __init__(self, body: bytes, status: int = 200) -> None:
        """Hold a body and status."""
        super().__init__(body)
        self.status = status


def _item(token: str = TOKEN, **fields: t.Any) -> dict:
    """One search item as the API returns it."""
    item = {
        "factory": pons.V2_FACTORY,
        "token": token,
        "deployer": DEPLOYER,
        "pairToken": pons.USDG,
        "name": "Pons",
        "symbol": "PONS",
        "blockNumber": 1,
        "graduated": False,
        "logo": "ipfs://x",
        "description": None,
        "launchedAt": "2026-09-12T17:42:50.000Z",
        "priceUsd": 1e-6,
        "marketCapUsd": 5000,
        "liquidityUsd": None,
        "graduationProgressPct": 0,
        "version": "v2",
        "venue": "curve",
        "quoteAsset": {"address": pons.USDG, "symbol": "USDG"},
    }
    item.update(fields)
    return item


@pytest.fixture(name="api")
def api_fixture(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Serve scripted HTTP answers and record the URLs asked for."""
    state: dict[str, t.Any] = {
        "urls": [],
        "search": {"page": 1, "pageSize": 24, "total": 1, "items": [_item()]},
        "docs": b"<p>Read this</p><p>No audit has closed. Treat v2 as unaudited</p>",
        "error": None,
        "status": 200,
    }

    def _open(request: urllib.request.Request, timeout: float) -> _Response:
        """Answer from the script."""
        assert timeout == pons.HTTP_TIMEOUT_S
        assert request.get_header("User-agent") == pons.USER_AGENT
        state["urls"].append(request.full_url)
        if state["error"] is not None:
            raise state["error"]
        if request.full_url == pons.DOCS_V2_URL:
            return _Response(state["docs"], state["status"])
        body = state["search"]
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return _Response(raw, state["status"])

    monkeypatch.setattr(urllib.request, "urlopen", _open)
    return state
