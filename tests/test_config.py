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
import os
from pathlib import Path

import pytest

from connect.config import (
    CUSTOM_ENV_VARS_PREFIX,
    FUND_REQUIREMENTS_ENV,
    LOG_LEVEL_ENV,
    MECH_GAP_RETRIES_ENV,
    MECH_HARD_CANCEL_AFTER_ENV,
    MECH_INDEXER_ENV_VARS,
    MECH_NONCE_MODE_ENV,
    MECH_NONCE_MODE_EXPLICIT,
    MECH_NONCE_MODE_SEQUENTIAL,
    MECH_SETTLE_TIMEOUT_ENV,
    MINUTES_PER_RUN_ENV,
    SAFES_ENV,
    STORE_PATH_ENV,
    configure_mech_indexers,
    load_config,
)


@pytest.fixture(autouse=True)
def _clean_indexer_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore indexer variables even when production code creates them."""
    for name in MECH_INDEXER_ENV_VARS:
        for key in (name, CUSTOM_ENV_VARS_PREFIX + name):
            monkeypatch.setenv(key, "")
            monkeypatch.delenv(key)


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


@pytest.mark.parametrize(
    ("safes", "expected"),
    [
        ({"gnosis": "0x" + "11" * 20}, "gnosis"),
        ({}, None),
        ({"gnosis": "0x" + "11" * 20, "base": "0x" + "22" * 20}, None),
    ],
)
def test_instance_chain_is_the_one_chain_with_a_safe(
    tmp_path: Path, safes: dict, expected: str | None
) -> None:
    """Every chain has an RPC; only the instance's own chain has a safe."""
    env = base_env(tmp_path) | {SAFES_ENV: json.dumps(safes)}
    assert load_config(env).instance_chain == expected


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


NATIVE = "0x" + "00" * 20


def test_fund_requirements_funds_manager_shape(tmp_path: Path) -> None:
    """The funds-manager shape parses to ints, from strings or ints."""
    reqs = {
        "Polygon": {
            "agent": {
                NATIVE: {"threshold": "1600000000000000000", "topup": 8 * 10**18}
            },
            "safe": {NATIVE: {"threshold": "3", "topup": 15}},
        }
    }
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: json.dumps(reqs)}
    config = load_config(env)
    assert config.fund_requirements == {
        "polygon": {
            "agent": {NATIVE: {"threshold": 16 * 10**17, "topup": 8 * 10**18}},
            "safe": {NATIVE: {"threshold": 3, "topup": 15}},
        }
    }


@pytest.mark.parametrize(
    ("requirement", "match"),
    [
        ({"threshold": "1"}, "must be an object of exactly"),
        ({"topup": "1"}, "must be an object of exactly"),
        ({"threshold": "1", "topup": "1", "top_up": "1"}, "exactly"),
        ({"threshold": "1", "topup": "1", "min_tx_balance": "1"}, "exactly"),
        ("100", "must be an object of exactly"),
        (100, "must be an object of exactly"),
        ({"threshold": "1", "topup": "1.5"}, "topup must be a whole number"),
        ({"threshold": "-1", "topup": "1"}, "threshold must be >= 0"),
        ({"threshold": True, "topup": "1"}, "threshold must be a whole number"),
        ({"threshold": "1", "topup": 1.0}, "topup must be a whole number"),
        ({"threshold": "ten", "topup": "1"}, "threshold must be a whole number"),
    ],
)
def test_fund_requirements_bad_requirement_raises(
    tmp_path: Path, requirement: object, match: str
) -> None:
    """A malformed requirement fails loudly, naming the var and the entry."""
    reqs = {"gnosis": {"agent": {NATIVE: requirement}}}
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: json.dumps(reqs)}
    with pytest.raises(ValueError, match=FUND_REQUIREMENTS_ENV) as error:
        load_config(env)
    assert f"agent {NATIVE} on gnosis" in str(error.value)
    error.match(match)


def test_fund_requirements_non_dict_role_entry_raises(tmp_path: Path) -> None:
    """A role mapped to anything but an asset object fails loudly."""
    env = base_env(tmp_path) | {FUND_REQUIREMENTS_ENV: '{"gnosis": {"agent": 5}}'}
    with pytest.raises(ValueError, match="asset -> requirement"):
        load_config(env)


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


def test_minutes_per_run_default_and_custom(tmp_path: Path) -> None:
    """MINUTES_PER_RUN defaults to 15 and accepts any whole number >= 0."""
    env = base_env(tmp_path)
    assert load_config(env).minutes_per_run == 15
    assert load_config(env | {MINUTES_PER_RUN_ENV: ""}).minutes_per_run == 15
    assert load_config(env | {MINUTES_PER_RUN_ENV: " 30 "}).minutes_per_run == 30
    assert load_config(env | {MINUTES_PER_RUN_ENV: "0"}).minutes_per_run == 0


@pytest.mark.parametrize("raw", ["-1", "1.5", "a while"])
def test_invalid_minutes_per_run_is_a_configuration_error(
    tmp_path: Path, raw: str
) -> None:
    """A value that is not a whole number >= 0 fails like any other bad config."""
    with pytest.raises(ValueError, match=MINUTES_PER_RUN_ENV):
        load_config(base_env(tmp_path) | {MINUTES_PER_RUN_ENV: raw})


def test_mech_settle_timeout_and_gap_retries_are_configurable(tmp_path: Path) -> None:
    """Both default as before; any whole number >= 0 is taken; junk is refused."""
    env = base_env(tmp_path)
    config = load_config(env)
    assert (config.mech_settle_timeout, config.mech_gap_retries) == (1800, 3)
    config = load_config(
        env | {MECH_SETTLE_TIMEOUT_ENV: " 600 ", MECH_GAP_RETRIES_ENV: "0"}
    )
    assert (config.mech_settle_timeout, config.mech_gap_retries) == (600, 0)
    for name in (MECH_SETTLE_TIMEOUT_ENV, MECH_GAP_RETRIES_ENV):
        for raw in ("-1", "1.5", "soon"):
            with pytest.raises(ValueError, match=name):
                load_config(env | {name: raw})


def test_mech_nonce_mode_defaults_to_explicit(tmp_path: Path) -> None:
    """Unset is explicit, either mode is taken in any case, junk is refused."""
    env = base_env(tmp_path)
    assert load_config(env).mech_nonce_mode == MECH_NONCE_MODE_EXPLICIT
    for raw, mode in (
        (" Sequential ", MECH_NONCE_MODE_SEQUENTIAL),
        ("explicit", MECH_NONCE_MODE_EXPLICIT),
    ):
        assert load_config(env | {MECH_NONCE_MODE_ENV: raw}).mech_nonce_mode == mode
    for raw in ("random", "1", "explicit,sequential"):
        with pytest.raises(ValueError, match=MECH_NONCE_MODE_ENV):
            load_config(env | {MECH_NONCE_MODE_ENV: raw})


def test_unknown_chain_lookup_raises(tmp_path: Path) -> None:
    """Test unknown chain lookup raises."""
    config = load_config(base_env(tmp_path))
    with pytest.raises(ValueError, match="unknown chain"):
        config.chain("solana")


@pytest.mark.parametrize("name", MECH_INDEXER_ENV_VARS)
def test_pearl_indexers_override_direct_values(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    """Pearl values reach mech-client without mixing chains or reader types."""
    for key in MECH_INDEXER_ENV_VARS:
        monkeypatch.delenv(CUSTOM_ENV_VARS_PREFIX + key, raising=False)
        monkeypatch.setenv(key, "https://old.example/graphql")
    monkeypatch.setenv(CUSTOM_ENV_VARS_PREFIX + name, " https://squid.example/graphql ")
    configure_mech_indexers()
    assert os.environ[name] == "https://squid.example/graphql"
    for key in set(MECH_INDEXER_ENV_VARS) - {name}:
        assert os.environ[key] == "https://old.example/graphql"


@pytest.mark.parametrize("raw", [None, "", "  ", "null", " NULL ", "None", " nOnE "])
def test_unset_pearl_indexers_preserve_standalone(
    monkeypatch: pytest.MonkeyPatch, raw: str | None
) -> None:
    """Template defaults neither erase direct URLs nor invent endpoints."""
    for index, name in enumerate(MECH_INDEXER_ENV_VARS):
        monkeypatch.delenv(CUSTOM_ENV_VARS_PREFIX + name, raising=False)
        if raw is not None:
            monkeypatch.setenv(CUSTOM_ENV_VARS_PREFIX + name, raw)
        monkeypatch.delenv(name, raising=False)
        if index == 0:
            monkeypatch.setenv(name, "https://direct.example/graphql")
    configure_mech_indexers()
    assert os.environ[MECH_INDEXER_ENV_VARS[0]] == "https://direct.example/graphql"
    assert all(name not in os.environ for name in MECH_INDEXER_ENV_VARS[1:])


def test_the_hard_cancel_window_outlasts_the_settle_timeout(tmp_path: Path) -> None:
    """Six hours by default; configurable, but never within the settle timeout."""
    env = base_env(tmp_path)
    assert load_config(env).mech_hard_cancel_after == 21600
    config = load_config(env | {MECH_HARD_CANCEL_AFTER_ENV: "3600"})
    assert config.mech_hard_cancel_after == 3600
    for raw in ("1800", "60"):
        with pytest.raises(ValueError, match="must be longer than"):
            load_config(env | {MECH_HARD_CANCEL_AFTER_ENV: raw})
    with pytest.raises(ValueError, match=MECH_HARD_CANCEL_AFTER_ENV):
        load_config(env | {MECH_HARD_CANCEL_AFTER_ENV: "soon"})


@pytest.mark.parametrize("source", ["template", "direct", "override", "unset"])
def test_indexer_sources_are_logged_without_urls(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, source: str
) -> None:
    """Log each configured source once, without leaking endpoint credentials."""
    for name in MECH_INDEXER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(CUSTOM_ENV_VARS_PREFIX + name, raising=False)
    name = MECH_INDEXER_ENV_VARS[0]
    if source in ("template", "override"):
        monkeypatch.setenv(
            CUSTOM_ENV_VARS_PREFIX + name, "https://squid.example/private-template-key"
        )
    if source in ("direct", "override"):
        monkeypatch.setenv(name, "https://squid.example/private-direct-key")
    with caplog.at_level(logging.INFO, logger="agent"):
        configure_mech_indexers()
    messages = [record.getMessage() for record in caplog.records]
    if source == "unset":
        assert not messages
    else:
        expected = "template (overrides direct)" if source == "override" else source
        assert messages == [f"mech indexer {name} source={expected}"]
    assert "https://" not in caplog.text
    assert "private-template-key" not in caplog.text
    assert "private-direct-key" not in caplog.text
    if source in ("template", "override"):
        assert os.environ[name] == "https://squid.example/private-template-key"
    elif source == "direct":
        assert os.environ[name] == "https://squid.example/private-direct-key"
    else:
        assert name not in os.environ


@pytest.mark.parametrize("template", ["", "null", " NULL ", "None", " nOnE "])
@pytest.mark.parametrize("direct", ["", "null", " NULL ", "None", " nOnE "])
def test_unset_indexer_strings_are_removed(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    template: str,
    direct: str,
) -> None:
    """Pearl's prefixed None plus bare null must reach mech-client as unset."""
    for name in MECH_INDEXER_ENV_VARS:
        monkeypatch.setenv(CUSTOM_ENV_VARS_PREFIX + name, template)
        monkeypatch.setenv(name, direct)
    with caplog.at_level(logging.INFO, logger="agent"):
        configure_mech_indexers()
    assert all(name not in os.environ for name in MECH_INDEXER_ENV_VARS)
    assert not caplog.records


@pytest.mark.parametrize("direct", ["null", "None", " nOnE "])
def test_template_urls_replace_unset_direct_strings(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    direct: str,
) -> None:
    """A direct placeholder is not a configured URL or a logged override."""
    name = MECH_INDEXER_ENV_VARS[0]
    monkeypatch.setenv(name, direct)
    monkeypatch.setenv(CUSTOM_ENV_VARS_PREFIX + name, " https://squid.example/graphql ")
    with caplog.at_level(logging.INFO, logger="agent"):
        configure_mech_indexers()
    assert os.environ[name] == "https://squid.example/graphql"
    assert caplog.messages == [f"mech indexer {name} source=template"]


def test_ocb_chat_mech_overrides_are_read_per_chain(tmp_path: Path) -> None:
    """OCB_CHAT_MECH_<CHAIN> fills that chain's mech; empty means unset."""
    mech = "0x" + "ab" * 20
    env = base_env(tmp_path) | {
        "OCB_CHAT_MECH_GNOSIS": f" {mech} ",  # all lowercase: no checksum to fail
        "OCB_CHAT_MECH_POLYGON": "",
    }
    assert load_config(env).ocb_chat_mech_overrides == {"gnosis": mech}
    assert load_config(base_env(tmp_path)).ocb_chat_mech_overrides == {}
    checksummed = "0xABaBaBaBABabABabAbAbABAbABabababaBaBABaB"
    env = base_env(tmp_path) | {"OCB_CHAT_MECH_GNOSIS": checksummed}
    assert load_config(env).ocb_chat_mech_overrides == {"gnosis": checksummed}


@pytest.mark.parametrize(
    "value",
    [
        "0x1234",
        "gnosis",
        "0x" + "zz" * 20,
        "ab" * 20,  # hex without the 0x prefix
        "0x" + "aB" * 20,  # mixed case with a bad checksum
    ],
)
def test_an_ocb_chat_mech_override_must_be_an_address(
    tmp_path: Path, value: str
) -> None:
    """A typo must not reach the launch line as OCB's model."""
    env = base_env(tmp_path) | {"OCB_CHAT_MECH_GNOSIS": value}
    with pytest.raises(ValueError, match="OCB_CHAT_MECH_GNOSIS"):
        load_config(env)
