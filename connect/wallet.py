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

"""Balance queries shared by /funds-status, /wallet and the MCP wallet_info tool."""

from web3 import Web3

from connect.config import AppConfig, NATIVE_ASSET
from connect.signer import Signer

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


def funds_status(config: AppConfig, signer: Signer) -> dict:
    """SDK-shape funding report: {chain: {address: {asset: {balance, deficit, decimals}}}}."""
    report: dict = {}
    for chain, requirements in config.fund_requirements.items():
        if chain not in config.chains:
            continue
        w3 = signer.w3(chain)
        for role, assets in requirements.items():
            if role == "agent":
                address: str | None = signer.address
            else:  # "safe" — the only other role _parse_fund_requirements admits
                address = config.chains[chain].safe_address
            if not address:  # no safe configured on this chain
                continue
            for asset, threshold in assets.items():
                balance, decimals = asset_balance(w3, asset, address, chain)
                report.setdefault(chain, {}).setdefault(address, {})[asset] = {
                    "balance": str(balance),
                    "deficit": str(max(0, threshold - balance)),
                    "decimals": decimals,
                }
    return report


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
