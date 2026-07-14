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

"""Test config module."""

import json
import logging
from pathlib import Path

import pytest

from connect.config import (
    FUND_REQUIREMENTS_ENV,
    LOG_LEVEL_ENV,
    SAFES_ENV,
    STORE_PATH_ENV,
    load_config,
)


def base_env(tmp_path: Path) -> dict:
    """Return a base environment with two RPC vars and a store path."""
    return {
        "CONNECTION_LEDGER_CONFIG_LEDGER_APIS_GNOSIS_ADDRESS": "http://rpc.gnosis",
        "CONNECTION_LEDGER_CONFIG_LEDGER_APIS_BASE_ADDRESS": "http://rpc.base",
        STORE_PATH_ENV: str(tmp_path / "store"),
    }


def test_rpc_discovery(tmp_path: Path) -> None:
    """Test rpc discovery."""
    config = load_config(base_env(tmp_path))
    assert set(config.chains) == {"gnosis", "base"}
    assert config.chains["gnosis"].rpc_url == "http://rpc.gnosis"


def test_unrelated_env_ignored(tmp_path: Path) -> None:
    """Test unrelated env ignored."""
    env = base_env(tmp_path) | {
        "PATH": "/usr/bin",
        "CONNECTION_LEDGER_CONFIG_LEDGER_APIS_X": "y",
    }
    config = load_config(env)
    assert set(config.chains) == {"gnosis", "base"}


def test_safes_json_format(tmp_path: Path) -> None:
    """Test safes json format."""
    safe = "0x" + "11" * 20
    env = base_env(tmp_path) | {SAFES_ENV: json.dumps({"gnosis": safe})}
    config = load_config(env)
    assert config.chains["gnosis"].safe_address == safe
    assert config.chains["base"].safe_address is None


def test_safe_for_unconfigured_chain_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A safe whose chain has no RPC is dropped with a warning, never silently."""
    safe = "0x" + "11" * 20
    env = base_env(tmp_path) | {SAFES_ENV: json.dumps({"gnosiss": safe})}
    with caplog.at_level(logging.WARNING):
        config = load_config(env)
    assert config.chains["gnosis"].safe_address is None
    assert "gnosiss" in caplog.text


def test_safes_invalid_json_raises(tmp_path: Path) -> None:
    """A non-JSON safes value is a misconfiguration and fails loudly."""
    env = base_env(tmp_path) | {SAFES_ENV: "gnosis:0x" + "11" * 20}
    with pytest.raises(ValueError, match="not valid JSON"):
        load_config(env)


def test_store_path_required(tmp_path: Path) -> None:
    """Test store path required."""
    env = base_env(tmp_path)
    del env[STORE_PATH_ENV]
    with pytest.raises(ValueError, match=STORE_PATH_ENV):
        load_config(env)


def test_fund_requirements(tmp_path: Path) -> None:
    """Test fund requirements."""
    reqs = {
        "gnosis": {"agent": {"0x" + "00" * 20: "100"}, "safe": {"0x" + "00" * 20: 5}}
    }
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: json.dumps(reqs)}
    config = load_config(env)
    assert config.fund_requirements["gnosis"]["agent"]["0x" + "00" * 20] == 100
    assert config.fund_requirements["gnosis"]["safe"]["0x" + "00" * 20] == 5


def test_fund_requirements_non_dict_chain_entry_raises(tmp_path: Path) -> None:
    """A scalar chain entry is a misconfiguration and fails loudly."""
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: '{"gnosis": 5}'}
    with pytest.raises(ValueError, match="must be an object"):
        load_config(env)


def test_fund_requirements_unknown_role_raises(tmp_path: Path) -> None:
    """Literal addresses (or typos) as requirement keys fail loudly."""
    reqs = {"gnosis": {"0x" + "cc" * 20: {"0x" + "00" * 20: 1}}}
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: json.dumps(reqs)}
    with pytest.raises(ValueError, match="must be roles"):
        load_config(env)


def test_log_level_default_custom_and_invalid(tmp_path: Path) -> None:
    """LOG_LEVEL defaults to info, accepts known levels, rejects junk."""
    env = base_env(tmp_path)
    assert load_config(env).log_level == "info"
    assert load_config(env | {LOG_LEVEL_ENV: "DEBUG"}).log_level == "debug"
    assert load_config(env | {LOG_LEVEL_ENV: " Warning "}).log_level == "warning"
    assert load_config(env | {LOG_LEVEL_ENV: "verbose"}).log_level == "info"


def test_unknown_chain_lookup_raises(tmp_path: Path) -> None:
    """Test unknown chain lookup raises."""
    config = load_config(base_env(tmp_path))
    with pytest.raises(ValueError, match="unknown chain"):
        config.chain("solana")
