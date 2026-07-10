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

"""Test keystore signer module."""

from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount

from pearl_connect.keystore import KeystoreError, load_account

from tests.conftest import TEST_PASSWORD


class TestKeystore:
    """TestKeystore."""

    def test_decrypt(self, keystore_dir: Path, account: LocalAccount) -> None:
        """Test decrypt."""
        loaded = load_account(TEST_PASSWORD, keystore_dir)
        assert loaded.address == account.address

    def test_wrong_password(self, keystore_dir: Path) -> None:
        """Test wrong password."""
        with pytest.raises(KeystoreError, match="decrypt"):
            load_account("wrong", keystore_dir)

    def test_missing_file(self, tmp_path: Path) -> None:
        """Test missing file."""
        with pytest.raises(KeystoreError, match="not found"):
            load_account(TEST_PASSWORD, tmp_path / "nope")
