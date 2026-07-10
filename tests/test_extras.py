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

"""Tests for config and keystore edge cases."""

from pathlib import Path

import pytest

from pearl_connect.config import (
    FUND_REQUIREMENTS_ENV,
    SAFES_ENV,
    STORE_PATH_ENV,
    load_config,
)
from pearl_connect.keystore import KeystoreError, load_account

from tests.conftest import TEST_PASSWORD


class TestConfigExtras:
    """Config parsing edge cases."""

    def test_safes_json_non_dict_raises(self, tmp_path: Path) -> None:
        """A JSON array of safes is a misconfiguration and fails loudly."""
        env = {STORE_PATH_ENV: str(tmp_path), SAFES_ENV: '["0xabc"]'}
        with pytest.raises(ValueError, match="JSON object"):
            load_config(env)

    def test_fund_requirements_non_dict_raises(self, tmp_path: Path) -> None:
        """A JSON array for fund requirements raises."""
        env = {STORE_PATH_ENV: str(tmp_path), FUND_REQUIREMENTS_ENV: "[1]"}
        with pytest.raises(ValueError, match="JSON object"):
            load_config(env)

    def test_fund_requirements_invalid_json_names_the_var(self, tmp_path: Path) -> None:
        """Malformed JSON names the offending env var, like the safes parser."""
        env = {STORE_PATH_ENV: str(tmp_path), FUND_REQUIREMENTS_ENV: "{nope"}
        with pytest.raises(ValueError, match=FUND_REQUIREMENTS_ENV):
            load_config(env)


def test_keystore_invalid_json(tmp_path: Path) -> None:
    """A non-JSON keystore raises KeystoreError."""
    (tmp_path / "ethereum_private_key.txt").write_text("not json")
    with pytest.raises(KeystoreError, match="not valid JSON"):
        load_account(TEST_PASSWORD, tmp_path)


def test_keystore_valid_json_but_not_keystore(tmp_path: Path) -> None:
    """Valid JSON that is not a keystore raises KeystoreError, not KeyError."""
    (tmp_path / "ethereum_private_key.txt").write_text('{"hello": "world"}')
    with pytest.raises(KeystoreError, match="failed to decrypt"):
        load_account(TEST_PASSWORD, tmp_path)
