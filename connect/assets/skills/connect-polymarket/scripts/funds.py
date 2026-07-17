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

"""Treasury flows between the service safe and the DepositWallet.

The funds-flow contract (mirrors the production trader, for recoverability):
the SERVICE SAFE is the treasury — the only wallet recoverable if the agent
EOA is lost. The DW holds funds only transiently, during a trade. Therefore:
wrap USDC.e→pUSD in the safe, top the DW up per trade, and always sweep the
DW (pUSD AND positions) back to the safe afterwards.

Usage:
    python funds.py balances                       # safe / DW / EOA balances
    python funds.py wrap [--amount 25.0]           # safe: USDC.e → pUSD (default: all)
    python funds.py top-up --amount 10.0           # safe → DW pUSD for a trade
    python funds.py sweep [--token-ids ID ...]     # DW → safe: pUSD + positions
    python funds.py return-position --token-id ID [--shares N]
                                                   # safe → DW: stage a swept
                                                   # position for selling
"""

import argparse

import pm_common as pm
from deposit_wallet import _resolve_dw, dw_or_exit
from relayer_proxy import RelayerProxyClient


def cmd_balances(cs: pm.ConnectSigner) -> None:
    """Report pUSD / USDC.e / POL for the safe, the DW and the agent EOA."""
    w3 = cs.w3
    dw = _resolve_dw(cs)
    wallets = {"safe": cs.safe_address, "agent_eoa": cs.agent_eoa}
    if dw:
        wallets["deposit_wallet"] = dw
    report = {}
    for name, address in wallets.items():
        report[name] = {
            "address": address,
            "pusd": pm.units_to_usd(pm.erc20_balance_of(w3, pm.PUSD, address)),
            "usdc_e": pm.units_to_usd(pm.erc20_balance_of(w3, pm.USDC_E, address)),
            "pol": float(w3.from_wei(w3.eth.get_balance(address), "ether")),
        }
    pm.print_json(report)


def cmd_wrap(cs: pm.ConnectSigner, amount: float | None) -> None:
    """Wrap the safe's USDC.e into pUSD via the Collateral Onramp.

    Two sequential safe calls — approve, then wrap (the onramp pulls via
    transferFrom and mints pUSD back to the safe). NOT a multisend: connect's
    guardrail floor refuses delegatecall in every mode. The onramp accepts
    USDC.e only; native USDC must be swapped to USDC.e first.
    """
    safe = cs.safe_address
    balance = pm.erc20_balance_of(cs.w3, pm.USDC_E, safe)
    units = pm.usd_to_units(amount) if amount is not None else balance
    if units <= 0 or units > balance:
        raise SystemExit(
            f"safe USDC.e balance is {pm.units_to_usd(balance)}; nothing to wrap"
            if balance <= 0
            else f"requested {amount} exceeds safe USDC.e balance {pm.units_to_usd(balance)}"
        )
    steps = []
    approve_hash = cs.safe_transaction(
        pm.USDC_E, pm.encode_erc20_approve(pm.COLLATERAL_ONRAMP, units)
    )
    steps.append({"step": "approve", **cs.wait_receipt(approve_hash)})
    if steps[-1]["status"] != 1:
        pm.print_json({"wrapped": False, "steps": steps})
        raise SystemExit("USDC.e approve to the onramp did not succeed")
    wrap_hash = cs.safe_transaction(
        pm.COLLATERAL_ONRAMP, pm.encode_onramp_wrap(pm.USDC_E, safe, units)
    )
    wrap_receipt = {"step": "wrap", **cs.wait_receipt(wrap_hash)}
    steps.append(wrap_receipt)
    if wrap_receipt["status"] != 1:
        pm.print_json({"wrapped": False, "steps": steps})
        pm.check_mined(wrap_receipt, "onramp wrap")  # raises with detail
    pm.print_json({"wrapped": True, "amount": pm.units_to_usd(units), "steps": steps})


def cmd_top_up(cs: pm.ConnectSigner, amount: float) -> None:
    """Transfer pUSD from the safe to the DW to fund an imminent trade."""
    dw = dw_or_exit(cs)
    units = pm.usd_to_units(amount)
    safe_balance = pm.erc20_balance_of(cs.w3, pm.PUSD, cs.safe_address)
    if units <= 0:
        raise SystemExit("top-up amount must be positive")
    if units > safe_balance:
        raise SystemExit(
            f"safe pUSD balance {pm.units_to_usd(safe_balance)} < requested {amount}; "
            "wrap USDC.e first (funds.py wrap) or fund the safe"
        )
    tx_hash = cs.safe_transaction(pm.PUSD, pm.encode_erc20_transfer(dw, units))
    receipt = cs.wait_receipt(tx_hash)
    pm.check_mined(receipt, f"top-up of {pm.units_to_usd(units)} pUSD")
    pm.print_json({"topped_up": pm.units_to_usd(units), "to": dw, **receipt})


def _dw_position_token_ids(dw: str) -> list:
    """Outcome-token ids the DW currently holds, from the data API."""
    positions = pm.http_get_json(
        f"{pm.DATA_API}/positions", params={"user": dw, "sizeThreshold": 0}
    )
    ids = []
    for position in positions or []:
        asset = position.get("asset")
        if asset:
            ids.append(int(asset))
    return ids


def cmd_sweep(cs: pm.ConnectSigner, token_ids: list) -> None:
    """Sweep the DW's pUSD AND positions back to the safe ("whatever's there").

    The safe is the canonical store of persistent assets — bought positions
    must not linger in the transient DW, or redemption (which acts on the
    safe) never sees them.

    Position discovery, when --token-ids is not given, is the UNION of two
    sources: the tokens this skill recorded at buy time (`dw_open_tokens`,
    which is immediate) and the data-API's view (which can lag right after a
    buy). Relying on the indexer alone would silently drop a just-bought
    position from the sweep. If both come back empty the DW is reported empty
    but with a warning to pass --token-ids if a buy just happened.
    """
    dw = dw_or_exit(cs)
    safe = cs.safe_address
    calls = []
    pusd_balance = pm.erc20_balance_of(cs.w3, pm.PUSD, dw)
    if pusd_balance > 0:
        calls.append(
            {"target": pm.PUSD, "data": pm.encode_erc20_transfer(safe, pusd_balance)}
        )
    if token_ids:
        candidate_ids = list(dict.fromkeys(int(t) for t in token_ids))
        discovery = "explicit --token-ids"
    else:
        recorded = pm.dw_open_tokens(cs)
        indexed = _dw_position_token_ids(dw)
        candidate_ids = list(dict.fromkeys([*recorded, *indexed]))
        discovery = f"{len(recorded)} recorded + {len(indexed)} indexed"
    swept_tokens = {}
    for token_id in candidate_ids:
        balance = pm.erc1155_balance_of(cs.w3, pm.CTF, dw, token_id)
        if balance > 0:
            swept_tokens[str(token_id)] = balance
            calls.append(
                {
                    "target": pm.CTF,
                    "data": pm.encode_erc1155_safe_transfer(
                        dw, safe, token_id, balance
                    ),
                }
            )
    warning = None
    if not token_ids and not candidate_ids:
        warning = (
            "no positions discovered (recorded state and indexer both empty); "
            "if a buy just happened the indexer may lag — re-run with "
            "--token-ids <id> to be certain nothing is left in the DW"
        )
    if not calls:
        result = {"swept": False, "note": "DepositWallet is empty (pUSD and positions)"}
        if warning:
            result["warning"] = warning
        pm.print_json(result)
        return
    proxy = RelayerProxyClient(cs)
    nonce = pm.dw_nonce(cs.w3, dw)
    tx_id = proxy.exec_wallet_batch(dw, nonce, calls)
    ok, state, tx_hash = proxy.wait_terminal(tx_id)
    # Confirm on-chain, not just the relayer's self-reported state.
    receipt = cs.wait_receipt(tx_hash) if tx_hash else {"status": None}
    confirmed = ok and receipt.get("status") == 1
    if confirmed:
        # These tokens have left the DW — drop them from the holdings hint.
        pm.forget_dw_tokens(cs, [int(t) for t in swept_tokens])
    pm.print_json(
        {
            "swept": confirmed,
            "pusd": pm.units_to_usd(pusd_balance),
            "positions": swept_tokens,
            "discovery": discovery,
            "relayer_state": state,
            "onchain_status": receipt.get("status"),
            "tx_hash": tx_hash,
        }
    )
    if not confirmed:
        raise SystemExit(
            "sweep not confirmed on-chain — funds remain in the DW; "
            "re-run `funds.py sweep`"
        )


def cmd_return_position(
    cs: pm.ConnectSigner, token_id: int, shares: float | None
) -> None:
    """Move a swept position back safe → DW so it can be sold.

    The inverse of one sweep leg: an ERC-1155 transfer made BY the safe.
    Shares are whole outcome tokens (6-decimal base units on-chain); default
    is the safe's full balance of that token. Sell it, then sweep again.
    """
    dw = dw_or_exit(cs)
    safe = cs.safe_address
    balance = pm.erc1155_balance_of(cs.w3, pm.CTF, safe, token_id)
    units = pm.usd_to_units(shares) if shares is not None else balance
    if balance <= 0:
        raise SystemExit(f"the safe holds no position {token_id}")
    if units <= 0 or units > balance:
        raise SystemExit(
            f"requested {shares} shares exceeds the safe's balance "
            f"({pm.units_to_usd(balance)})"
        )
    tx_hash = cs.safe_transaction(
        pm.CTF, pm.encode_erc1155_safe_transfer(safe, dw, token_id, units)
    )
    receipt = cs.wait_receipt(tx_hash)
    pm.check_mined(receipt, f"return of position {token_id} to the DW")
    # The position now sits in the DW — record it so a later sweep won't miss
    # it. Best-effort: the transfer already confirmed, so a state-write hiccup
    # must not make this command look failed.
    pm.record_dw_token_best_effort(cs, int(token_id))
    pm.print_json(
        {
            "returned_shares": pm.units_to_usd(units),
            "token_id": str(token_id),
            "to": dw,
            **receipt,
        }
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("balances")
    wrap = sub.add_parser("wrap")
    wrap.add_argument("--amount", type=float, default=None, help="USDC.e; default all")
    top_up = sub.add_parser("top-up")
    top_up.add_argument("--amount", type=float, required=True, help="pUSD to send")
    sweep = sub.add_parser("sweep")
    sweep.add_argument("--token-ids", type=int, nargs="*", default=None)
    ret = sub.add_parser("return-position")
    ret.add_argument("--token-id", type=int, required=True)
    ret.add_argument("--shares", type=float, default=None, help="default: all")
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    if args.command == "balances":
        cmd_balances(cs)
    elif args.command == "wrap":
        cmd_wrap(cs, args.amount)
    elif args.command == "top-up":
        cmd_top_up(cs, args.amount)
    elif args.command == "sweep":
        cmd_sweep(cs, args.token_ids)
    elif args.command == "return-position":
        cmd_return_position(cs, args.token_id, args.shares)


if __name__ == "__main__":
    main()
