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

"""Tests for the supported-chain table (OPE-2035 T8)."""

import threading
import typing as t

from eth_account.signers.local import LocalAccount
from web3 import Web3

from connect import chains, wallet
from connect.activity import ActivityLog
from connect.config import AppConfig, ChainConfig
from connect.signer import Signer, _ChainState

from tests.conftest import FakeW3


def test_arbitrum_and_celo_are_supported_without_a_marketplace() -> None:
    """Both new chains are listed with their ids and natives, and no marketplace."""
    assert chains.chain_info("arbitrum_one") == {
        "chain_id": 42161,
        "native_symbol": "ETH",
        "marketplace": False,
        "facilitator": False,
    }
    assert chains.chain_info("CELO") == {
        "chain_id": 42220,
        "native_symbol": "CELO",
        "marketplace": False,
        "facilitator": False,
    }


def test_marketplace_follows_mech_client_config() -> None:
    """A chain is a marketplace chain exactly when mech-client has a contract there."""
    assert t.cast(dict, chains.chain_info("gnosis"))["marketplace"] is True
    marketplaces = {"arbitrum": "0x" + "11" * 20, "celo": chains.ZERO_ADDRESS}
    # Connect's arbitrum_one is mech-client's arbitrum
    assert chains._has_marketplace("arbitrum_one", marketplaces) is True
    assert chains._has_marketplace("celo", marketplaces) is False
    assert chains._has_marketplace("unknown", marketplaces) is False


def test_unknown_chain_has_no_info() -> None:
    """A chain outside the table reports nothing rather than guessing."""
    assert chains.chain_info("testchain") is None


def test_wallet_overview_reports_chain_info(
    account: LocalAccount,
    activity: ActivityLog,
    fake_w3: FakeW3,
    store_path: t.Any,
) -> None:
    """wallet_info carries each supported chain's id, native and marketplace flag."""
    config = AppConfig(
        chains={"celo": ChainConfig(rpc_url="http://127.0.0.1:9")},
        store_path=store_path,
    )
    signer = Signer(account=account, config=config, activity=activity)
    signer._chains._states["celo"] = _ChainState(  # pylint: disable=protected-access
        w3=t.cast(Web3, fake_w3), lock=threading.Lock(), chain_id=42220
    )

    entry = wallet.wallet_overview(config, signer)["chains"]["celo"]

    assert entry["chain_id"] == 42220
    assert entry["native_symbol"] == "CELO"
    assert entry["marketplace"] is False
    assert entry["facilitator"] is False
