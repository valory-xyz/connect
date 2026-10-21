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

"""Balance queries shared by /funds-status, /wallet and the MCP wallet_info tool.

Also the agent top-up rule: how much native token the safe moves to the agent
EOA, and the deficits /funds-status reports once it has. It is Connect's own
copy of funds-manager's get_agent_topup, so both report the same table.
"""

import logging
from dataclasses import dataclass
from enum import Enum

from web3 import Web3

from connect.config import AppConfig, FundRequirement, NATIVE_ASSET
from connect.signer import Signer

logger = logging.getLogger("agent")

ERC20_ABI = [
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "name": "decimals",
        "type": "function",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint8"}],
    },
]

_decimals_cache: dict[tuple[str, str], int] = {}


def asset_balance(w3: Web3, asset: str, address: str, chain: str) -> tuple[int, int]:
    """Return (balance, decimals) for a native or ERC-20 asset."""
    address = Web3.to_checksum_address(address)
    if asset.lower() == NATIVE_ASSET:
        return w3.eth.get_balance(address), 18
    token = w3.eth.contract(address=Web3.to_checksum_address(asset), abi=ERC20_ABI)
    key = (chain, asset.lower())
    if key not in _decimals_cache:
        _decimals_cache[key] = token.functions.decimals().call()
    return token.functions.balanceOf(address).call(), _decimals_cache[key]


class TopUpAction(str, Enum):
    """What the agent top-up does on a chain."""

    NONE = "none"  # nothing due, or a balance could not be read
    MOVE = "move"  # move `move` wei from the safe to the agent EOA
    SIGNER_ALERT = "signer_alert"  # agent EOA below min_tx_balance
    SAFE_ALERT = "safe_alert"  # safe native at 0, agent EOA short


@dataclass(frozen=True)
class AgentTopUp:
    """One chain's top-up; a deficit of None leaves the one read as it is."""

    action: TopUpAction
    move: int  # wei; 0 unless action is MOVE
    signer_deficit: int | None
    safe_deficit: int | None


_NO_TOPUP = AgentTopUp(TopUpAction.NONE, 0, None, None)


def _native_requirement(assets: dict[str, FundRequirement]) -> FundRequirement | None:
    """Return the native-token requirement among a role's assets, if any."""
    for asset, requirement in assets.items():
        if asset.lower() == NATIVE_ASSET:
            return requirement
    return None


def plan_agent_topup(
    requirements: dict[str, dict[str, FundRequirement]],
    agent_balance: int | None,
    safe_balance: int | None,
) -> AgentTopUp:
    """Apply the top-up rule to one chain's requirements and native balances.

    Native token only. Without a `min_tx_balance` on the agent's native entry,
    or a native entry for both roles, nothing moves and the deficits stay as
    read. A balance of None is one that could not be read.
    """
    agent = _native_requirement(requirements.get("agent", {}))
    safe = _native_requirement(requirements.get("safe", {}))
    if (
        agent is None
        or safe is None
        or "min_tx_balance" not in agent
        or agent_balance is None
        or safe_balance is None
    ):
        return _NO_TOPUP
    need = (
        max(0, agent["topup"] - agent_balance)
        if agent_balance < agent["threshold"]
        else 0
    )
    if need == 0:
        return _NO_TOPUP
    if agent_balance < agent["min_tx_balance"]:
        return AgentTopUp(TopUpAction.SIGNER_ALERT, 0, need, None)
    if safe_balance >= need:
        return AgentTopUp(TopUpAction.MOVE, need, 0, None)
    if safe_balance > 0:
        return AgentTopUp(
            TopUpAction.MOVE, safe_balance, 0, need - safe_balance + safe["topup"]
        )
    return AgentTopUp(TopUpAction.SAFE_ALERT, 0, 0, need + safe["topup"])


def agent_topup(config: AppConfig, signer: Signer) -> dict[str, AgentTopUp]:
    """Read native balances and plan the top-up on every chain with a safe."""
    plans: dict[str, AgentTopUp] = {}
    for chain, requirements in config.fund_requirements.items():
        chain_config = config.chains.get(chain)
        if chain_config is None or not chain_config.safe_address:
            continue
        agent_balance: int | None = None
        safe_balance: int | None = None
        try:
            w3 = signer.w3(chain)
            agent_balance = w3.eth.get_balance(Web3.to_checksum_address(signer.address))
            safe_balance = w3.eth.get_balance(
                Web3.to_checksum_address(chain_config.safe_address)
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.warning(
                "agent top-up: could not read native balances on %s",
                chain,
                exc_info=True,
            )
        plans[chain] = plan_agent_topup(requirements, agent_balance, safe_balance)
    return plans


def funds_status(config: AppConfig, signer: Signer) -> dict:
    """SDK-shape funding report: {chain: {address: {asset: {balance, deficit, decimals}}}}.

    A deficit is what is left once the agent top-up has moved what it can.
    """
    report: dict = {}
    for chain, requirements in config.fund_requirements.items():
        if chain not in config.chains:
            continue
        w3 = signer.w3(chain)
        # role -> (address, native asset key, native balance)
        native: dict[str, tuple[str, str, int]] = {}
        for role, assets in requirements.items():
            if role == "agent":
                address: str | None = signer.address
            else:  # "safe" — the only other role _parse_fund_requirements admits
                address = config.chains[chain].safe_address
            if not address:  # no safe configured on this chain
                continue
            for asset, requirement in assets.items():
                balance, decimals = asset_balance(w3, asset, address, chain)
                report.setdefault(chain, {}).setdefault(address, {})[asset] = {
                    "balance": str(balance),
                    "deficit": str(max(0, requirement["threshold"] - balance)),
                    "decimals": decimals,
                }
                if asset.lower() == NATIVE_ASSET:
                    native[role] = (address, asset, balance)
        if "agent" in native and "safe" in native:
            _report_after_topup(report[chain], requirements, native)
    return report


def _report_after_topup(
    chain_report: dict,
    requirements: dict[str, dict[str, FundRequirement]],
    native: dict[str, tuple[str, str, int]],
) -> None:
    """Replace the native deficits the top-up rule decides, in place."""
    plan = plan_agent_topup(requirements, native["agent"][2], native["safe"][2])
    for role, deficit in (("agent", plan.signer_deficit), ("safe", plan.safe_deficit)):
        if deficit is not None:
            address, asset, _ = native[role]
            chain_report[address][asset]["deficit"] = str(deficit)


def _not_actionable_because(safe: str | None, balances: dict) -> str | None:
    """Why this chain is not one to act on, or None if it is."""
    # first: config, so it holds even when the RPC below never answered
    if not safe:
        return "not deployed here: no service safe"
    if "error" in balances:
        return f"balances unreadable: {balances['error']}"
    if int(balances.get("agent_eoa", "0")) == 0:
        return "not funded here: agent EOA has no gas"
    return None


def wallet_overview(config: AppConfig, signer: Signer) -> dict:
    """Agent addresses and, per chain, whether it can actually be acted on.

    The launcher sets an RPC per supported chain but safes come from the
    operator's list, so a one-chain agent sees many chains. `actionable_chains`
    states the verdict rather than leaving it to be inferred.
    """
    chains: dict = {}
    for chain, chain_config in config.chains.items():
        safe = chain_config.safe_address
        try:
            w3 = signer.w3(chain)
            balances = {
                "agent_eoa": str(
                    w3.eth.get_balance(Web3.to_checksum_address(signer.address))
                )
            }
            if safe:
                balances["safe"] = str(
                    w3.eth.get_balance(Web3.to_checksum_address(safe))
                )
        except Exception as e:  # pylint: disable=broad-exception-caught
            balances = {"error": str(e)}
        reason = _not_actionable_because(safe, balances)
        entry: dict = {
            "rpc": chain_config.rpc_url,
            "safe": safe,
            "balances": balances,
            "actionable": reason is None,
        }
        if reason is not None:
            entry["not_actionable_because"] = reason
        chains[chain] = entry
    actionable = [chain for chain, entry in chains.items() if entry["actionable"]]
    return {
        "agent_eoa": signer.address,
        "actionable_chains": actionable,
        "chains": chains,
    }
