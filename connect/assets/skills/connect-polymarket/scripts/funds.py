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
    python funds.py sweep [--token-ids ID ...] [--force]
                                                   # DW → safe: pUSD + positions
                                                   # (blocked while orders rest)
    python funds.py return-position --token-id ID [--shares N]
                                                   # safe → DW: stage a swept
                                                   # position for selling
"""

import argparse

import pm_common as pm
from deposit_wallet import _resolve_dw, dw_or_exit
from relayer_proxy import RelayerProxyClient

POSITIONS_PAGE_LIMIT = 500
POSITIONS_MAX_OFFSET = 10_000


def cmd_balances(cs: pm.ConnectSigner) -> None:
    """Report pUSD / USDC.e / USDC / POL for the safe, DW and agent EOA."""
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
            "usdc": pm.units_to_usd(pm.erc20_balance_of(w3, pm.USDC, address)),
            "pol": float(w3.from_wei(w3.eth.get_balance(address), "ether")),
        }
    pm.print_json(report)


def _usdc_hint(cs: pm.ConnectSigner, safe: str) -> str:
    """Name the USDC the onramp just refused to see, if there is any.

    "Nothing to wrap" against a safe holding USDC is true but reads as
    unfunded; the balance and the reason it cannot be wrapped belong together.
    """
    try:
        native = pm.erc20_balance_of(cs.w3, pm.USDC, safe)
    except Exception:  # noqa: BLE001 - a hint must never replace the refusal
        return ""
    if native <= 0:
        return ""
    return (
        f" (the safe does hold {pm.units_to_usd(native)} USDC, which "
        "the onramp does not accept — it must be swapped to USDC.e first)"
    )


def cmd_wrap(cs: pm.ConnectSigner, amount: float | None) -> None:
    """Wrap the safe's USDC.e into pUSD via the Collateral Onramp.

    Two sequential safe calls — approve, then wrap (the onramp pulls via
    transferFrom and mints pUSD back to the safe). NOT a multisend: connect's
    guardrail floor refuses delegatecall in every mode. The onramp accepts
    USDC.e only; USDC must be swapped to USDC.e first.
    """
    safe = cs.safe_address
    balance = pm.erc20_balance_of(cs.w3, pm.USDC_E, safe)
    units = pm.usd_to_units(amount) if amount is not None else balance
    if units <= 0 or units > balance:
        raise SystemExit(
            f"safe USDC.e balance is {pm.units_to_usd(balance)}; nothing to "
            f"wrap{_usdc_hint(cs, safe)}"
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
    """Outcome-token ids the DW currently holds, across all data-API pages."""
    positions = pm.fetch_all_positions(
        {"user": dw, "sizeThreshold": 0},
        label="DW-position",
        page_limit=POSITIONS_PAGE_LIMIT,
        max_offset=POSITIONS_MAX_OFFSET,
    )
    return [int(p["asset"]) for p in positions if p.get("asset")]


def _abort_if_open_orders(cs: pm.ConnectSigner, dw: str) -> None:
    """Refuse to sweep while resting CLOB orders back the DW's assets.

    A live GTC/GTD buy reserves pUSD collateral and a live sell reserves
    outcome shares; sweeping those out would leave the order live but
    unsettleable. Bypass with --force only when you know none rest here.
    """
    from remote_signer import make_clob_client  # SDK import only needed here

    try:
        open_orders = make_clob_client(cs, dw).get_open_orders()
    except Exception as e:  # noqa: BLE001 - can't verify → don't sweep blind
        raise SystemExit(
            f"could not verify open CLOB orders before sweeping ({e}); cancel "
            "any resting orders (trade.py cancel) or re-run with --force if you "
            "are certain none rest against the DW"
        ) from e
    if open_orders:
        ids = ", ".join(str(o.get("id", "?")) for o in open_orders[:5])
        raise SystemExit(
            f"{len(open_orders)} open CLOB order(s) rest against the DW ({ids}) "
            "— sweeping could strand their collateral or shares and leave them "
            "unsettleable. Cancel them (trade.py cancel --id ...) first, or "
            "re-run with --force if they are safe to move."
        )


def _pending_buy_warning(
    pending_ids: set,
    checked_ids: set,
    visible_ids: set,
    sweep_confirmed: bool,
) -> str | None:
    """Describe every unresolved buy, including tokens with swept balances."""
    if not pending_ids:
        return None
    visible_ids = pending_ids & visible_ids
    hidden_ids = (pending_ids & checked_ids) - visible_ids
    unchecked_ids = pending_ids - checked_ids
    details = []
    if visible_ids:
        action = "was swept" if sweep_confirmed else "is still visible"
        details.append(
            f"a balance {action} for token(s) "
            f"{', '.join(str(t) for t in sorted(visible_ids))}, but pending "
            "submission state remains and additional balance may settle later"
        )
    if hidden_ids:
        details.append(
            "no position is visible on-chain yet for token(s) "
            f"{', '.join(str(t) for t in sorted(hidden_ids))}"
        )
    if unchecked_ids:
        details.append(
            "the explicit token filter did not check token(s) "
            f"{', '.join(str(t) for t in sorted(unchecked_ids))}"
        )
    return (
        "unresolved buy intent(s) remain for token(s) "
        f"{', '.join(str(t) for t in sorted(pending_ids))}; "
        f"{'; '.join(details)}. Re-run sweep after settlement/indexing before "
        "treating the DW as fully recovered"
    )


def cmd_sweep(cs: pm.ConnectSigner, token_ids: list, force: bool = False) -> None:
    """Sweep the DW's pUSD AND positions back to the safe ("whatever's there").

    The safe is the canonical store of persistent assets — bought positions
    must not linger in the transient DW, or redemption (which acts on the
    safe) never sees them.

    Refuses to run while any resting CLOB order is open (its collateral or
    shares must stay in the DW to settle); cancel those first, or pass
    --force. Position discovery, when --token-ids is not given, is the UNION
    of three sources: the tokens this skill recorded at buy time
    (`dw_open_tokens`, immediate), unresolved buy submissions, and the
    data-API's view (which can lag right after a buy). Relying on the indexer
    alone would silently drop a just-bought position. If all come back empty
    the DW is reported empty with a warning to pass --token-ids if a buy just
    happened.
    """
    dw = dw_or_exit(cs)
    if not force:
        _abort_if_open_orders(cs, dw)
    safe = cs.safe_address
    calls = []
    pusd_balance = pm.erc20_balance_of(cs.w3, pm.PUSD, dw)
    if pusd_balance > 0:
        calls.append(
            {"target": pm.PUSD, "data": pm.encode_erc20_transfer(safe, pusd_balance)}
        )
    pending_buy_ids = set(pm.dw_pending_buy_tokens(cs))
    if token_ids:
        candidate_ids = list(dict.fromkeys(int(t) for t in token_ids))
        discovery = "explicit --token-ids"
    else:
        recorded = pm.dw_open_tokens(cs)
        indexed = _dw_position_token_ids(dw)
        candidate_ids = list(
            dict.fromkeys([*recorded, *sorted(pending_buy_ids), *indexed])
        )
        discovery = (
            f"{len(recorded)} recorded + {len(pending_buy_ids)} pending + "
            f"{len(indexed)} indexed"
        )
    swept_tokens = {}
    visible_pending_ids = set()
    checked_pending_ids = pending_buy_ids & set(candidate_ids)
    for token_id in candidate_ids:
        balance = pm.erc1155_balance_of(cs.w3, pm.CTF, dw, token_id)
        if balance > 0:
            swept_tokens[str(token_id)] = balance
            if token_id in pending_buy_ids:
                visible_pending_ids.add(token_id)
            calls.append(
                {
                    "target": pm.CTF,
                    "data": pm.encode_erc1155_safe_transfer(
                        dw, safe, token_id, balance
                    ),
                }
            )
    empty_discovery_warning = None
    if not token_ids and not candidate_ids:
        empty_discovery_warning = (
            "no positions discovered (recorded state and indexer both empty); "
            "if a buy just happened the indexer may lag — re-run with "
            "--token-ids <id> to be certain nothing is left in the DW"
        )
    warning = (
        _pending_buy_warning(
            pending_buy_ids,
            checked_pending_ids,
            visible_pending_ids,
            sweep_confirmed=False,
        )
        or empty_discovery_warning
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
    state_warnings = []
    if confirmed and swept_tokens:
        # These tokens have left the DW — drop them from the holdings hint.
        try:
            pm.forget_dw_tokens(cs, [int(t) for t in swept_tokens])
        except (Exception, SystemExit) as e:  # noqa: BLE001
            state_warnings.append(
                "sweep confirmed on-chain, but state bookkeeping failed while "
                f"dropping swept holdings hints ({e}); the on-chain result is "
                "authoritative"
            )
    try:
        remaining_pending_ids = set(pm.dw_pending_buy_tokens(cs))
    except (Exception, SystemExit) as e:  # noqa: BLE001
        remaining_pending_ids = pending_buy_ids
        state_warnings.append(
            f"could not reload pending-buy state after sweep ({e}); using the "
            "pre-sweep pending state for the recovery warning"
        )
    warning = (
        _pending_buy_warning(
            remaining_pending_ids,
            checked_pending_ids,
            visible_pending_ids,
            sweep_confirmed=confirmed,
        )
        or empty_discovery_warning
    )
    if state_warnings:
        warning = " ".join(filter(None, [warning, *state_warnings]))
    result = {
        "swept": confirmed,
        "pusd": pm.units_to_usd(pusd_balance),
        "positions": swept_tokens,
        "discovery": discovery,
        "relayer_state": state,
        "onchain_status": receipt.get("status"),
        "tx_hash": tx_hash,
    }
    if warning:
        result["warning"] = warning
    pm.print_json(result)
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
    sweep.add_argument(
        "--force",
        action="store_true",
        help="sweep even with open CLOB orders resting against the DW",
    )
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
        cmd_sweep(cs, args.token_ids, args.force)
    elif args.command == "return-position":
        cmd_return_position(cs, args.token_id, args.shares)


if __name__ == "__main__":
    main()
