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
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.signers.local import LocalAccount

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
