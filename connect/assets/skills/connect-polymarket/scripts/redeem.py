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

"""Redeem resolved positions — from the SERVICE SAFE, never the DW.

The funds flow sweeps bought positions DW→safe after every trade, so the
safe is where winnings sit at resolution. Redemption is a safe call to a
Polymarket collateral adapter, which burns the CTF position and pushes pUSD
back to the safe. (The production trader redeems its safe's positions
through Polymarket's legacy relayer; that relayer only serves
Polymarket-factory safes, so here the service safe calls the adapter
directly via connect — same custody, the EOA pays the POL gas.)

One-time prerequisite per safe: `approve` grants the two adapters ERC-1155
operator rights on the safe's CTF positions. The adapters never pull ERC-20
from the safe, so no pUSD allowance is needed.

A binary Protocol V2 position is claimed through the Router instead, which
`approve` grants operator rights on the safe's PositionManager positions.

Usage:
    python redeem.py list                # redeemable positions in the safe
    python redeem.py approve             # one-time adapter and Router operator rights
    python redeem.py redeem --condition-id 0x... --outcome-index 0 [--neg-risk]
    python redeem.py all                 # approve + redeem everything listed
"""

import argparse

import pm_common as pm
from polymarket.calls import router_redeem_call

POSITIONS_PAGE_LIMIT = 500


def _redeemable(cs: pm.ConnectSigner) -> list:
    """Return every redeemable safe position, across all data-API pages."""
    return pm.fetch_all_positions(
        {"user": cs.safe_address},
        label="redeemable-position",
        page_limit=POSITIONS_PAGE_LIMIT,
        redeemable=True,
    )


def _ensure_adapter_approvals(
    cs: pm.ConnectSigner,
    token: str = pm.CTF,
    adapters: tuple = (pm.CTF_COLLATERAL_ADAPTER, pm.NEG_RISK_CTF_COLLATERAL_ADAPTER),
) -> list:
    """Grant `adapters` operator rights on the safe's `token` positions (idempotent)."""
    results = []
    for adapter in adapters:
        if pm.is_approved_for_all(cs.w3, token, cs.safe_address, adapter):
            results.append({"adapter": adapter, "approved": "already"})
            continue
        tx_hash = cs.safe_transaction(
            token, pm.encode_set_approval_for_all(adapter, True)
        )
        receipt = cs.wait_receipt(tx_hash)
        results.append({"adapter": adapter, **receipt})
        if receipt["status"] != 1:
            raise SystemExit(f"adapter approval failed: {receipt}")
    return results


def _redeem_one(
    cs: pm.ConnectSigner, condition_id: str, outcome_index: int, neg_risk: bool
) -> dict:
    """One safe call to the matching adapter's redeemPositions.

    Returns the receipt dict (including `status`); the caller decides whether
    a `status != 1` is fatal (single redeem) or collected (batch redeem).
    """
    adapter = (
        pm.NEG_RISK_CTF_COLLATERAL_ADAPTER if neg_risk else pm.CTF_COLLATERAL_ADAPTER
    )
    # The deployed adapters ignore the index-set argument (they read both
    # position balances themselves); [1 << outcomeIndex] documents intent.
    data = pm.encode_redeem_positions(condition_id, [1 << outcome_index])
    tx_hash = cs.safe_transaction(adapter, data)
    return {
        "condition_id": condition_id,
        "adapter": adapter,
        **cs.wait_receipt(tx_hash),
    }


def _ensure_router_approval(cs: pm.ConnectSigner) -> list:
    """Grant the Router operator rights on the safe's PositionManager positions."""
    return _ensure_adapter_approvals(cs, pm.POSITION_MANAGER, (pm.ROUTER,))


def _redeem_v2(cs: pm.ConnectSigner, position_id: int) -> dict | None:
    """Redeem the safe's whole binary V2 position via the Router; None if none held."""
    # the exact on-chain balance: the data API rounds sizes and lags a claim
    amount = pm.erc1155_balance_of(
        cs.w3, pm.POSITION_MANAGER, cs.safe_address, position_id
    )
    if not amount:
        return None
    condition_id = f"0x{position_id >> 8:062x}00"
    call = router_redeem_call(
        router=pm.ROUTER,
        condition_id=condition_id,
        outcome_index=position_id & 0xFF,
        amount=amount,
    )
    _ensure_router_approval(cs)
    tx_hash = cs.safe_transaction(call.to, call.data)
    return {
        "condition_id": condition_id,
        "adapter": pm.ROUTER,
        **cs.wait_receipt(tx_hash),
    }


def cmd_list(cs: pm.ConnectSigner) -> None:
    """Redeemable positions held by the safe."""
    pm.print_json(
        [
            {
                "title": p.get("title"),
                "outcome": p.get("outcome"),
                "condition_id": p.get("conditionId"),
                "outcome_index": p.get("outcomeIndex"),
                "size": p.get("size"),
                "neg_risk": p.get("negativeRisk"),
            }
            for p in _redeemable(cs)
        ]
    )


def cmd_redeem(
    cs: pm.ConnectSigner, condition_id: str, outcome_index: int, neg_risk: bool
) -> None:
    """Redeem one resolved position from the safe."""
    position_id = int(condition_id, 16) + outcome_index
    module = pm.v2_module(position_id)
    if module > 1:
        raise SystemExit("this skill claims no neg-risk or combinatorial V2 position")
    if module == 1:
        result = _redeem_v2(cs, position_id)
        if result is None:
            raise SystemExit(f"the safe holds no position {position_id}")
    else:
        _ensure_adapter_approvals(cs)
        result = _redeem_one(cs, condition_id, outcome_index, neg_risk)
    pm.check_mined(result, f"redemption of {condition_id}")
    pm.print_json(result)


def cmd_all(cs: pm.ConnectSigner) -> None:
    """Redeem every redeemable position the data API lists for the safe.

    Attempts each position, then fails loudly if ANY did not confirm on-chain
    — a reverted/timed-out redemption must not hide inside a summary shaped
    identically to full success.
    """
    positions = _redeemable(cs)
    if not positions:
        pm.print_json({"redeemed": [], "note": "nothing redeemable"})
        return
    # the data API marks a resolved V2 market's losing side redeemable too
    binary_v2 = [
        p
        for p in positions
        if pm.v2_module(p.get("asset")) == 1 and p.get("currentValue")
    ]
    results = []
    for position in positions:
        condition_id = position.get("conditionId")
        outcome_index = int(position.get("outcomeIndex") or 0)
        neg_risk = bool(position.get("negativeRisk"))
        if position in binary_v2:
            result = _redeem_v2(cs, int(position["asset"]))
            results.extend([result] if result else [])
        elif condition_id and not pm.v2_module(position.get("asset")):
            _ensure_adapter_approvals(cs)
            results.append(_redeem_one(cs, condition_id, outcome_index, neg_risk))
    failed = [r for r in results if r.get("status") != 1]
    pm.print_json({"redeemed": results, "failed": len(failed)})
    if failed:
        raise SystemExit(
            f"{len(failed)}/{len(results)} redemption(s) did not confirm on-chain; "
            "the listed positions may still be unredeemed — re-run `redeem.py all`"
        )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    sub.add_parser("approve")
    sub.add_parser("all")
    redeem = sub.add_parser("redeem")
    redeem.add_argument("--condition-id", required=True)
    redeem.add_argument("--outcome-index", type=int, required=True)
    redeem.add_argument("--neg-risk", action="store_true")
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    if args.command == "list":
        cmd_list(cs)
    elif args.command == "approve":
        pm.print_json(_ensure_adapter_approvals(cs) + _ensure_router_approval(cs))
    elif args.command == "redeem":
        cmd_redeem(cs, args.condition_id, args.outcome_index, args.neg_risk)
    elif args.command == "all":
        cmd_all(cs)


if __name__ == "__main__":
    main()
