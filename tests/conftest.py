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

import json
import threading
import typing as t
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes
from web3 import Web3

from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig, ChainConfig
from pearl_connect.signer import Signer, _ChainState

TEST_PASSWORD = "test-password"  # nosec B105


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
        from web3.exceptions import TransactionNotFound

        if self.receipt is None:
            raise TransactionNotFound(f"{tx_hash!r} not mined")
        return self.receipt

    def wait_for_transaction_receipt(
        self, tx_hash: object, timeout: float = 120, poll_latency: float = 0.1
    ) -> dict:
        """Return the configured receipt or raise TimeExhausted."""
        from web3.exceptions import TimeExhausted

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


class FakeW3:
    """Minimal Web3 stand-in for signer tests."""

    def __init__(self) -> None:
        """Initialize."""
        self.eth = FakeEth()

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
def make_app() -> t.Callable:
    """Return an app factory."""
    from pearl_connect.server.app import create_app

    def _make(
        signer: Signer,
        config: AppConfig,
        activity: ActivityLog,
        token: str = "tok",  # nosec B107
    ) -> t.Any:
        return create_app(signer=signer, config=config, activity=activity, token=token)

    return _make
