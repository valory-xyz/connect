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

Values arrive as environment variables, almost all injected by the Pearl
middleware (from the service template / agent.json); the exception is the
QA-only OCB_CHAT_MECH_<CHAIN>, which Pearl never sets. This module is the only
place that knows the env var names.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TypedDict

from web3 import Web3

from connect.run_goal import check_target

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
MINUTES_PER_RUN_ENV = CUSTOM_ENV_VARS_PREFIX + "MINUTES_PER_RUN"
MECH_SETTLE_TIMEOUT_ENV = CUSTOM_ENV_VARS_PREFIX + "MECH_SETTLE_TIMEOUT"
MECH_GAP_RETRIES_ENV = CUSTOM_ENV_VARS_PREFIX + "MECH_GAP_RETRIES"
MECH_INDEXER_ENV_VARS = (
    "MECHX_MARKETPLACE_BASE_SQUID_URL",
    "MECHX_MARKETPLACE_POLYGON_SQUID_URL",
    "MECHX_REGISTRY_BASE_SQUID_URL",
    "MECHX_REGISTRY_POLYGON_SQUID_URL",
)
MECH_HARD_CANCEL_AFTER_ENV = CUSTOM_ENV_VARS_PREFIX + "MECH_HARD_CANCEL_AFTER"
# set by Pearl at deploy for the instance chain; the zero address means unstaked
STAKING_CONTRACT_ENV = CUSTOM_ENV_VARS_PREFIX + "STAKING_CONTRACT_ADDRESS"
ACTIVITY_CHECKER_ENV = CUSTOM_ENV_VARS_PREFIX + "ACTIVITY_CHECKER_CONTRACT_ADDRESS"
SERVICE_ID_ENV = CUSTOM_ENV_VARS_PREFIX + "SERVICE_ID"

# A QA override, never set by Pearl: OCB_CHAT_MECH_GNOSIS=0x... gives OCB that
# chat mech on that chain in place of the shipped one
OCB_CHAT_MECH_ENV_PREFIX = "OCB_CHAT_MECH_"

LOG_LEVELS = ("critical", "error", "warning", "info", "debug")
DEFAULT_LOG_LEVEL = "info"
DEFAULT_MINUTES_PER_RUN = 15
# seconds mapNonces may take to pass a delivered (or timed-out) mech request
# before its safe's queue stalls; and how often a 503 gap resends a nonce
DEFAULT_MECH_SETTLE_TIMEOUT = 1800
DEFAULT_MECH_GAP_RETRIES = 3
# seconds a safe's queue must have been stalled before the operator may hard
# cancel it (one paid on-chain request); longer than the settle timeout, so a
# queue gets the time to clear itself first
DEFAULT_MECH_HARD_CANCEL_AFTER = 21600


class FundRequirement(TypedDict):
    """One asset's funding rule for a role, in wei / smallest unit."""

    threshold: int
    topup: int


@dataclass(frozen=True)
class StakingConfig:
    """The staking program this instance is staked in, on its instance chain."""

    staking_contract: str
    activity_checker: str
    service_id: int


@dataclass
class ChainConfig:
    """Per-chain settings; the chain's name is the AppConfig.chains key."""

    rpc_url: str
    safe_address: str | None = None


@dataclass
class AppConfig:  # pylint: disable=too-many-instance-attributes
    """AppConfig."""

    chains: dict[str, ChainConfig]
    store_path: Path
    # chain -> role -> asset -> requirement
    fund_requirements: dict[str, dict[str, dict[str, FundRequirement]]] = field(
        default_factory=dict
    )
    log_level: str = DEFAULT_LOG_LEVEL
    # the starting run window; the first write stores it, and the stored value
    # wins from then on, so changing this never reaches an existing install
    minutes_per_run: int = DEFAULT_MINUTES_PER_RUN
    mech_settle_timeout: int = DEFAULT_MECH_SETTLE_TIMEOUT
    mech_gap_retries: int = DEFAULT_MECH_GAP_RETRIES
    mech_hard_cancel_after: int = DEFAULT_MECH_HARD_CANCEL_AFTER

    def __post_init__(self) -> None:
        """Refuse a hard-cancel window no longer than the settle timeout."""
        if self.mech_hard_cancel_after <= self.mech_settle_timeout:
            raise ValueError(
                f"{MECH_HARD_CANCEL_AFTER_ENV} ({self.mech_hard_cancel_after}s) "
                "must be longer than "
                f"{MECH_SETTLE_TIMEOUT_ENV} ({self.mech_settle_timeout}s): a "
                "stalled queue gets the settle timeout to clear itself first"
            )

    # chain -> OCB chat mech, from OCB_CHAT_MECH_<CHAIN>
    ocb_chat_mech_overrides: dict[str, str] = field(default_factory=dict)
    # None while unstaked, or when Pearl's staking values cannot be used
    staking: StakingConfig | None = None

    @property
    def safe_chains(self) -> list[str]:
        """The configured chains that carry a safe, in configuration order."""
        return [name for name, chain in self.chains.items() if chain.safe_address]

    @property
    def instance_chain(self) -> str | None:
        """The one chain this instance runs on: the chain carrying its safe.

        Pearl configures an RPC for every chain but a safe for one, so a
        config with no safe, or with several, names no instance chain.
        """
        chains = self.safe_chains
        return chains[0] if len(chains) == 1 else None

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


FUND_REQUIREMENT_KEYS = ("threshold", "topup")


def _parse_amount(value: object, where: str) -> int:
    """Parse one wei amount: a whole number >= 0, as an int or a decimal string."""
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(
            f"{FUND_REQUIREMENTS_ENV} amount for {where} must be a whole number, "
            f"got {value!r}"
        )
    try:
        amount = int(value)
    except ValueError as e:
        raise ValueError(
            f"{FUND_REQUIREMENTS_ENV} amount for {where} must be a whole number, "
            f"got {value!r}"
        ) from e
    if amount < 0:
        raise ValueError(
            f"{FUND_REQUIREMENTS_ENV} amount for {where} must be >= 0, got {value!r}"
        )
    return amount


def _parse_fund_requirement(value: object, where: str) -> FundRequirement:
    """Parse one asset's requirement, an object of exactly threshold and topup."""
    if not isinstance(value, dict) or set(value) != set(FUND_REQUIREMENT_KEYS):
        raise ValueError(
            f"{FUND_REQUIREMENTS_ENV} entry for {where} must be an object of "
            f"exactly {list(FUND_REQUIREMENT_KEYS)}, got {value!r}"
        )
    return FundRequirement(
        threshold=_parse_amount(value["threshold"], f"{where} threshold"),
        topup=_parse_amount(value["topup"], f"{where} topup"),
    )


def _parse_fund_requirements(
    raw: str,
) -> dict[str, dict[str, dict[str, FundRequirement]]]:
    """Parse {chain: {"agent"|"safe": {asset: requirement}}}.

    A requirement is {"threshold", "topup"}, the shape funds-manager reads,
    with amounts as decimal strings or ints.

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
    result: dict[str, dict[str, dict[str, FundRequirement]]] = {}
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
        for role, assets in roles.items():
            if not isinstance(assets, dict):
                raise ValueError(
                    f"{FUND_REQUIREMENTS_ENV} entry for {role} on chain '{chain}' "
                    "must be an object of asset -> requirement"
                )
        result[chain.lower()] = {
            str(role): {
                str(asset): _parse_fund_requirement(value, f"{role} {asset} on {chain}")
                for asset, value in assets.items()
            }
            for role, assets in roles.items()
        }
    return result


def _parse_minutes_per_run(raw: str) -> int:
    """Parse the default minutes per run; unset means the default."""
    raw = raw.strip()
    if not raw:
        return DEFAULT_MINUTES_PER_RUN
    try:
        return check_target(int(raw))
    except ValueError as e:
        raise ValueError(
            f"{MINUTES_PER_RUN_ENV} is not a whole number of minutes >= 0: {raw!r}"
        ) from e


def _parse_count(env: dict[str, str], name: str, default: int) -> int:
    """Parse a whole number >= 0 from the environment; unset means the default."""
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        raise ValueError(f"{name} is not a whole number >= 0: {raw!r}")
    return value


def _indexer_url(value: str | None) -> str | None:
    """Normalize unset endpoint values from Pearl and standalone environments."""
    value = (value or "").strip()
    return None if value.lower() in ("", "null", "none") else value


def configure_mech_indexers() -> None:
    """Forward Pearl squid settings and log their sources; see README."""
    for name in MECH_INDEXER_ENV_VARS:
        value = _indexer_url(os.environ.get(CUSTOM_ENV_VARS_PREFIX + name))
        direct = _indexer_url(os.environ.get(name))
        if value:
            os.environ[name] = value
            source = "template (overrides direct)" if direct else "template"
        elif direct:
            os.environ[name] = direct
            source = "direct"
        else:
            os.environ.pop(name, None)
            continue
        logger.info("mech indexer %s source=%s", name, source)


def _is_mech_address(value: str) -> bool:
    """Whether `value` is a 0x address, checksummed whenever it is mixed case.

    Web3.is_address alone takes bare hex and does not check a mixed-case
    checksum, and a typo here becomes OCB's model.
    """
    if not (value.startswith("0x") and Web3.is_address(value)):
        return False
    digits = value[2:]
    return digits in (digits.lower(), digits.upper()) or Web3.is_checksum_address(value)


def _parse_ocb_chat_mechs(env: dict[str, str]) -> dict[str, str]:
    """Collect OCB_CHAT_MECH_<CHAIN> overrides; an unset or empty one is ignored.

    :raises ValueError: on a value that is not an address.
    """
    overrides: dict[str, str] = {}
    for key, value in env.items():
        if not key.startswith(OCB_CHAT_MECH_ENV_PREFIX) or not value.strip():
            continue
        if not _is_mech_address(value.strip()):
            raise ValueError(f"{key} is not an address: {value!r}")
        chain = key[len(OCB_CHAT_MECH_ENV_PREFIX) :].lower()
        overrides[chain] = value.strip()
        logger.warning("OCB chat mech on %s overridden by %s", chain, key)
    return overrides


def _staking_address(env: dict[str, str], name: str) -> str | None:
    """Read one staking address; unset or the zero address is None.

    :raises ValueError: on a value that is not an address.
    """
    raw = env.get(name, "").strip()
    if not raw or raw.lower() == NATIVE_ASSET:
        return None
    if not Web3.is_address(raw):
        raise ValueError(f"{name} is not an address: {raw!r}")
    return Web3.to_checksum_address(raw)


def _parse_staking(env: dict[str, str]) -> StakingConfig | None:
    """Read the staking program Pearl configured; None while unstaked.

    Staking is optional and the wallet must keep working without it, so a
    value Connect cannot use is logged and read as unstaked, never refused.
    """
    try:
        staking_contract = _staking_address(env, STAKING_CONTRACT_ENV)
        if staking_contract is None:
            return None
        activity_checker = _staking_address(env, ACTIVITY_CHECKER_ENV)
        service_id = _parse_count(env, SERVICE_ID_ENV, 0)
    except ValueError as e:
        logger.warning("staking read as unstaked: %s", e)
        return None
    if activity_checker is None or service_id == 0:
        logger.warning(
            "staking read as unstaked: %s is set but %s or %s is not",
            STAKING_CONTRACT_ENV,
            ACTIVITY_CHECKER_ENV,
            SERVICE_ID_ENV,
        )
        return None
    return StakingConfig(
        staking_contract=staking_contract,
        activity_checker=activity_checker,
        service_id=service_id,
    )


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
        minutes_per_run=_parse_minutes_per_run(env.get(MINUTES_PER_RUN_ENV, "")),
        mech_settle_timeout=_parse_count(
            env, MECH_SETTLE_TIMEOUT_ENV, DEFAULT_MECH_SETTLE_TIMEOUT
        ),
        mech_gap_retries=_parse_count(
            env, MECH_GAP_RETRIES_ENV, DEFAULT_MECH_GAP_RETRIES
        ),
        mech_hard_cancel_after=_parse_count(
            env, MECH_HARD_CANCEL_AFTER_ENV, DEFAULT_MECH_HARD_CANCEL_AFTER
        ),
        ocb_chat_mech_overrides=_parse_ocb_chat_mechs(env),
        staking=_parse_staking(env),
    )
