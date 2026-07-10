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

"""Environment-driven configuration.

All values arrive as environment variables injected by the Pearl middleware
(from the service template / agent.json). This module is the only place that
knows the env var names.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("agent")

AGENT_HTTP_PORT = 8716
BIND_HOST = "127.0.0.1"
NATIVE_ASSET = "0x0000000000000000000000000000000000000000"
KEYSTORE_FILE = "ethereum_private_key.txt"

RPC_ENV_PREFIX = "CONNECTION_LEDGER_CONFIG_LEDGER_APIS_"
RPC_ENV_SUFFIX = "_ADDRESS"
CUSTOM_ENV_VARS_PREFIX = "CONNECTION_CONFIGS_CONFIG_"
STORE_PATH_ENV = CUSTOM_ENV_VARS_PREFIX + "STORE_PATH"
SAFES_ENV = CUSTOM_ENV_VARS_PREFIX + "SAFE_CONTRACT_ADDRESSES"
FUND_REQUIREMENTS_ENV = CUSTOM_ENV_VARS_PREFIX + "FUND_REQUIREMENTS"
LOG_LEVEL_ENV = CUSTOM_ENV_VARS_PREFIX + "LOG_LEVEL"

LOG_LEVELS = ("critical", "error", "warning", "info", "debug")
DEFAULT_LOG_LEVEL = "info"


@dataclass
class ChainConfig:
    """Per-chain settings; the chain's name is the AppConfig.chains key."""

    rpc_url: str
    safe_address: str | None = None


@dataclass
class AppConfig:
    """AppConfig."""

    chains: dict[str, ChainConfig]
    store_path: Path
    # chain -> address -> asset -> threshold (wei / smallest unit)
    fund_requirements: dict[str, dict[str, dict[str, int]]] = field(
        default_factory=dict
    )
    log_level: str = DEFAULT_LOG_LEVEL

    def chain(self, name: str) -> ChainConfig:
        """Chain."""
        try:
            return self.chains[name.lower()]
        except KeyError:
            raise ValueError(
                f"unknown chain '{name}'; configured chains: {sorted(self.chains)}"
            ) from None


def _parse_safes(raw: str) -> dict[str, str]:
    """Parse safe addresses: a JSON dict of {chain: address}."""
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{SAFES_ENV} is not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError(f"{SAFES_ENV} must be a JSON object of chain -> address")
    return {str(k).lower(): str(v) for k, v in parsed.items()}


FUND_REQUIREMENT_ROLES = ("agent", "safe")


def _parse_fund_requirements(raw: str) -> dict[str, dict[str, dict[str, int]]]:
    """Parse {chain: {"agent"|"safe": {asset: threshold}}} with int-able values.

    Keys are roles, not addresses: the service template is static and cannot
    know the per-user agent EOA / safe addresses; funds_status() resolves the
    roles against the running deployment.
    """
    raw = raw.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{FUND_REQUIREMENTS_ENV} is not valid JSON: {e}") from e
    if not isinstance(parsed, dict):
        raise ValueError(f"{FUND_REQUIREMENTS_ENV} must be a JSON object")
    result: dict[str, dict[str, dict[str, int]]] = {}
    for chain, roles in parsed.items():
        if not isinstance(roles, dict):
            raise ValueError(
                f"{FUND_REQUIREMENTS_ENV} entry for chain '{chain}' must be an object"
            )
        unknown = set(roles) - set(FUND_REQUIREMENT_ROLES)
        if unknown:
            raise ValueError(
                f"{FUND_REQUIREMENTS_ENV} keys must be roles {FUND_REQUIREMENT_ROLES},"
                f" got {sorted(unknown)} for chain '{chain}'"
            )
        result[chain.lower()] = {
            str(role): {str(asset): int(amount) for asset, amount in assets.items()}
            for role, assets in roles.items()
        }
    return result


def load_config(env: dict[str, str] | None = None) -> AppConfig:
    """Load config."""
    env = dict(os.environ) if env is None else env

    chains: dict[str, ChainConfig] = {}
    for key, value in env.items():
        if (
            key.startswith(RPC_ENV_PREFIX)
            and key.endswith(RPC_ENV_SUFFIX)
            and value.strip()
        ):
            chain_name = key[len(RPC_ENV_PREFIX) : -len(RPC_ENV_SUFFIX)].lower()
            chains[chain_name] = ChainConfig(rpc_url=value.strip())

    for chain_name, safe in _parse_safes(env.get(SAFES_ENV, "")).items():
        if chain_name in chains:
            chains[chain_name].safe_address = safe
        else:
            # a typo'd chain key must not silently leave a chain safeless
            logger.warning(
                "safe address for chain '%s' ignored: no RPC configured for it",
                chain_name,
            )

    store_raw = env.get(STORE_PATH_ENV, "").strip()
    if not store_raw:
        raise ValueError(f"{STORE_PATH_ENV} is required")
    store_path = Path(store_raw).expanduser()

    fund_requirements = _parse_fund_requirements(env.get(FUND_REQUIREMENTS_ENV, ""))

    log_level = env.get(LOG_LEVEL_ENV, DEFAULT_LOG_LEVEL).strip().lower()
    if log_level not in LOG_LEVELS:
        log_level = DEFAULT_LOG_LEVEL

    return AppConfig(
        chains=chains,
        store_path=store_path,
        fund_requirements=fund_requirements,
        log_level=log_level,
    )
