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

"""DepositWallet (DW) lifecycle: the transient CLOB trading wallet.

The DW is an ERC-1967 proxy owned by the agent EOA, deployed by Polymarket's
factory through the relayer proxy. It funds POLY_1271 orders; it is NOT the
treasury — funds are topped up from the service safe per trade and swept back
after (see funds.py).

Usage:
    python deposit_wallet.py status   # DW address, owner, approvals
    python deposit_wallet.py ensure   # deploy if needed + grant approvals
"""

import argparse
import sys
import time

import pm_common as pm
from relayer_proxy import RelayerProxyClient, extract_dw_from_receipt

# Retries for reading a just-deployed DW's owner() while the node indexes it.
OWNER_CONFIRM_ATTEMPTS = 6
OWNER_CONFIRM_BACKOFF = 5


def _resolve_dw(cs: pm.ConnectSigner) -> str | None:
    """Return the persisted DW if its on-chain owner is still the agent EOA.

    Returns None only when there is NO usable record (none persisted, or a
    persisted one owned by a different EOA — a restored/foreign workspace —
    which is discarded so a fresh deploy is safe). A persisted record whose
    owner cannot be read is a hard error, NOT a silent None: treating it as
    "deploy a new one" would orphan the recorded DW and any funds in it. RPC
    failures propagate out of ``contract_owner`` for the same reason.
    """
    state = pm.load_state(cs)
    dw = (state.get("deposit_wallet") or {}).get("address")
    if not dw:
        return None
    owner = pm.contract_owner(cs.w3, dw)  # raises on RPC failure
    if owner is None:
        raise SystemExit(
            f"persisted DepositWallet {dw} has no readable owner() on-chain "
            "(no code there, or the node returned empty). Refusing to deploy a "
            "replacement, which would orphan it — investigate before retrying."
        )
    if owner.lower() != cs.agent_eoa.lower():
        print(
            f"WARNING: persisted DepositWallet {dw} is owned by {owner}, not the "
            f"agent EOA {cs.agent_eoa}; discarding the record. Residual funds in "
            "it are NOT recoverable by this agent.",
            file=sys.stderr,
        )
        state.pop("deposit_wallet", None)
        state.pop("approvals_done", None)
        pm.save_state(cs, state)
        return None
    return dw


def _deploy(cs: pm.ConnectSigner, proxy: RelayerProxyClient) -> str:
    """Deploy a fresh DW via the relayer proxy and persist its address."""
    tx_id = proxy.deploy_dw()
    print(f"deploy_dw submitted (relayer tx {tx_id}); waiting to mine...")
    ok, tx_state, tx_hash = proxy.wait_terminal(tx_id)
    if not ok or not tx_hash:
        raise SystemExit(f"DW deploy did not mine: state={tx_state} hash={tx_hash}")
    # Confirm the deploy tx actually succeeded on-chain, not just that the
    # relayer classified it "mined".
    pm.check_mined(cs.wait_receipt(tx_hash), "DW deploy")
    dw = extract_dw_from_receipt(cs, tx_hash)
    if not dw:
        raise SystemExit(
            f"could not find the DW address in deploy receipt {tx_hash}; "
            "re-run `ensure` once the tx is indexed"
        )
    # Require a POSITIVE owner match before persisting — a None owner (indexing
    # lag) is retried, then treated as failure, never skipped.
    owner = None
    for _ in range(OWNER_CONFIRM_ATTEMPTS):
        owner = pm.contract_owner(cs.w3, dw)  # raises on RPC failure
        if owner is not None:
            break
        time.sleep(OWNER_CONFIRM_BACKOFF)
    if owner is None or owner.lower() != cs.agent_eoa.lower():
        raise SystemExit(
            f"deployed DW {dw} owner reads as {owner}, expected the agent EOA "
            f"{cs.agent_eoa}; not persisting an unverified DW"
        )
    state = pm.load_state(cs)
    state["deposit_wallet"] = {"address": dw, "owner": cs.agent_eoa}
    pm.save_state(cs, state)
    return dw


def dw_or_exit(cs: pm.ConnectSigner) -> str:
    """Resolve the DW or exit with a clear message (shared by sibling scripts)."""
    dw = _resolve_dw(cs)
    if not dw:
        raise SystemExit("no DepositWallet yet — run `deposit_wallet.py ensure` first")
    return dw


def _approve(cs: pm.ConnectSigner, proxy: RelayerProxyClient, dw: str) -> dict:
    """Grant the DW whatever of the canonical approval set it lacks.

    Up to 3 pUSD allowances + 3 CTF operator grants (see pm_common), relayed
    as one owner-signed batch. `approvals_done` is persisted only once the
    relayer tx is confirmed mined AND its on-chain receipt shows success — a
    submitted-but-unmined or reverted batch must not look done.
    """
    calls = pm.missing_approval_calls(cs.w3, dw)
    if not calls:
        state = pm.load_state(cs)
        state["approvals_done"] = True
        pm.save_state(cs, state)
        return {"approvals": "already complete"}
    nonce = pm.dw_nonce(cs.w3, dw)
    tx_id = proxy.exec_wallet_batch(dw, nonce, calls)
    print(f"approval batch of {len(calls)} calls submitted (relayer tx {tx_id})...")
    ok, tx_state, tx_hash = proxy.wait_terminal(tx_id)
    if not ok or not tx_hash:
        raise SystemExit(f"approval batch failed: state={tx_state} hash={tx_hash}")
    pm.check_mined(cs.wait_receipt(tx_hash), "approval batch")  # relayer-agnostic
    state = pm.load_state(cs)
    state["approvals_done"] = True
    pm.save_state(cs, state)
    return {"approvals": f"granted {len(calls)} missing", "tx_hash": tx_hash}


def cmd_status(cs: pm.ConnectSigner) -> None:
    """Print the DW address, owner, relayer registration and approvals."""
    proxy = RelayerProxyClient(cs)
    dw = _resolve_dw(cs)
    result: dict = {"agent_eoa": cs.agent_eoa, "deposit_wallet": dw}
    if dw:
        result["owner"] = pm.contract_owner(cs.w3, dw)
        result["relayer_registered"] = proxy.deployed(dw)
        result["approvals"] = pm.approvals_status(cs.w3, dw)
        result["pusd_balance"] = pm.units_to_usd(
            pm.erc20_balance_of(cs.w3, pm.PUSD, dw)
        )
    pm.print_json(result)


def cmd_ensure(cs: pm.ConnectSigner) -> None:
    """Deploy the DW if absent and grant any missing approvals (idempotent)."""
    proxy = RelayerProxyClient(cs)
    dw = _resolve_dw(cs)
    deployed_now = False
    if not dw:
        dw = _deploy(cs, proxy)
        deployed_now = True
    approvals = _approve(cs, proxy, dw)
    pm.print_json(
        {
            "deposit_wallet": dw,
            "deployed_now": deployed_now,
            **approvals,
        }
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["status", "ensure"])
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    {"status": cmd_status, "ensure": cmd_ensure}[args.command](cs)


if __name__ == "__main__":
    main()
