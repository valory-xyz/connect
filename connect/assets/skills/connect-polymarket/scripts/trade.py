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

"""Place, inspect and cancel CLOB orders (POLY_1271, funded by the DW).

Prerequisites: `deposit_wallet.py ensure` once, then `funds.py top-up` with
the pUSD the buy will spend. After trading, ALWAYS `funds.py sweep` — the
funds-flow contract keeps persistent assets in the recoverable service safe.

Usage:
    python trade.py buy   --token-id 123... --usd 10.0     # market buy (default FOK)
    python trade.py sell  --token-id 123... --shares 12.5  # market sell (default FAK)
    python trade.py limit --token-id 123... --side buy --price 0.42 --size 20
    python trade.py order --id 0x...                       # order status
    python trade.py cancel --id 0x...                      # cancel a resting order

Market orders take --order-type fok|fak (defaults match the production
trader: FOK buys, FAK sells). Limit orders take --order-type gtc|gtd
(--expires-in seconds is required for gtd). Amount semantics are the CLOB's
market-order convention: buys spend pUSD ("--usd"), sells move outcome
shares ("--shares").
"""

import argparse
import sys
import time

import pm_common as pm
from deposit_wallet import dw_or_exit
from py_clob_client_v2 import MarketOrderArgs, OrderArgs, OrderType
from py_clob_client_v2.clob_types import OpenOrderParams, OrderPayload, TradeParams
from py_clob_client_v2.exceptions import PolyApiException
from py_clob_client_v2.order_builder.constants import BUY, SELL
from py_clob_client_v2.order_utils.model.order_data_v2 import Side
from remote_signer import clear_cached_creds, make_clob_client


def _order_type(name: str):
    """Map a CLI order-type string to the SDK constant (plain str, not Enum)."""
    return getattr(OrderType, name.upper())


def _auth_failed(e: PolyApiException) -> bool:
    """Whether a CLOB rejection looks like stale/invalid API credentials."""
    code = getattr(e, "status_code", None)
    msg = str(getattr(e, "error_msg", "") or e).lower()
    return code == 401 or "unauthorized" in msg or "apikey" in msg or "api key" in msg


def _definitive_auth_rejection(e: PolyApiException) -> bool:
    """Whether the response proves authentication failed before submission."""
    return getattr(e, "status_code", None) == 401


def _run_client(cs: pm.ConnectSigner, op, retry_auth: bool = True) -> None:
    """Build a DW-funded CLOB client, run op(client, dw), print the result.

    Replay-safe operations may rebuild the client and retry once after an
    auth-class failure. Order placement disables that retry: rerunning its
    closure would construct a newly signed order and risk duplicate execution.
    Cached credentials are still cleared so an explicit operator retry starts
    with freshly derived credentials.
    """
    dw = dw_or_exit(cs)
    client = make_clob_client(cs, dw)
    try:
        result = op(client, dw)
    except PolyApiException as e:
        if not _auth_failed(e):
            pm.print_json({"error": str(getattr(e, "error_msg", "") or e)})
            raise SystemExit(1) from e
        clear_cached_creds(cs)
        if not retry_auth:
            error = {
                "error": str(getattr(e, "error_msg", "") or e),
                "retry": "not attempted automatically: operation is not replay-safe",
            }
            if not _definitive_auth_rejection(e):
                error["warning"] = (
                    "submission outcome may be ambiguous; reconcile before retrying"
                )
            pm.print_json(error)
            raise SystemExit(1) from e
        client = make_clob_client(cs, dw)  # re-derives creds
        try:
            result = op(client, dw)
        except PolyApiException as e2:
            pm.print_json({"error": str(getattr(e2, "error_msg", "") or e2)})
            raise SystemExit(1) from e2
    pm.print_json(result)


# Reconciliation pacing after an ambiguous submission: one immediate check,
# then one more after each delay. A real fill or resting order is normally
# visible well inside this window; a phantom match never shows up at all.
RECONCILE_DELAYS = (2, 5, 10)


def _trade_ids(trades: list) -> set:
    """Return the CLOB trade ids present in a ``get_trades`` result."""
    return {str(t["id"]) for t in trades if isinstance(t, dict) and t.get("id")}


def _asset_trades(client, token_id: str) -> list:
    """Fetch this signer's CLOB trades for one outcome token."""
    return client.get_trades(TradeParams(asset_id=str(token_id))) or []


def _asset_open_orders(client, token_id: str) -> list:
    """Fetch this signer's resting CLOB orders for one outcome token."""
    return client.get_open_orders(OpenOrderParams(asset_id=str(token_id))) or []


def _pre_submission_state(client, token_id: str):
    """Snapshot this signer's trade and open-order ids for the token.

    Anything seen after submission that is not in the snapshot is attributable
    to that submission. Best-effort: on a read failure return None, which
    disables the attribution (reconciliation then never claims "filled" or
    "resting" off pre-existing activity) without blocking the buy itself.
    """
    try:
        return {
            "trade_ids": _trade_ids(_asset_trades(client, token_id)),
            "order_ids": {
                str(o["id"])
                for o in _asset_open_orders(client, token_id)
                if isinstance(o, dict) and o.get("id")
            },
        }
    except Exception:  # noqa: BLE001 - the snapshot is advisory
        return None


def _venue_health(token_id: str) -> str:
    """Diagnose the venue after a failed submission (reads up, or all down).

    ``POST /order`` failing while public reads succeed is the degraded-order-
    endpoint pattern; naming it stops the failure reading as a client bug.
    """
    try:
        pm.http_get_json(f"{pm.CLOB_HOST}/book", params={"token_id": str(token_id)})
    except Exception:  # noqa: BLE001 - the diagnosis must not add a failure
        return (
            "CLOB reads fail too — the venue or the network path to it looks "
            "down, not just order submission"
        )
    return (
        "CLOB reads succeed while order submission failed — the order endpoint "
        "looks degraded; a timed-out submission can still fill"
    )


def _submission_outcome_unknown(e: PolyApiException) -> bool:
    """Whether the failure leaves the submission outcome genuinely unknown.

    No HTTP status (timeouts, connection drops), 408 and 5xx can all arrive
    after the order reached the matching engine. Any other 4xx is the CLOB
    application itself answering, so the outcome is knowable from it.
    """
    code = getattr(e, "status_code", None)
    if code is None:
        return True
    return code == 408 or 500 <= code < 600


def _confirm_buy_intent_best_effort(cs, token_id_int: int) -> None:
    """Resolve the pending marker without masking an already-settled action."""
    try:
        pm.confirm_dw_buy_intent(cs, token_id_int)
    except Exception as e:  # noqa: BLE001 - post succeeded; retain pending marker
        print(
            f"WARNING: could not mark buy {token_id_int} confirmed ({e}); "
            "the action itself succeeded and its recovery hint remains pending",
            file=sys.stderr,
        )


def _reconcile_lost_submission(client, cs, token_id: str, before, error):
    """Classify a submission whose response was lost, instead of crying failure.

    A transport failure on ``POST /order`` proves nothing: a timed-out
    submission can fill (a false negative), or hold a matching-engine
    reservation with no visible order. Poll this signer's trades and open
    orders for the token and report what is actually true — "filled" or
    "resting" resolve the pending marker; "unknown" keeps it and exits
    non-zero so a retry is a reconciled decision, not a reflex.
    """
    token_id_int = int(token_id)
    health = _venue_health(token_id)
    err_text = str(getattr(error, "error_msg", "") or error)
    if before is not None:
        for delay in (0, *RECONCILE_DELAYS):
            if delay:
                time.sleep(delay)
            try:
                trades = _asset_trades(client, token_id)
                new_trades = [
                    t for t in trades if str(t.get("id")) not in before["trade_ids"]
                ]
                if new_trades:
                    _confirm_buy_intent_best_effort(cs, token_id_int)
                    return {
                        "submission": "filled",
                        "warning": (
                            f"the CLOB response was lost ({err_text}) but "
                            "reconciliation found the fill — do NOT resubmit"
                        ),
                        "trades": new_trades,
                        "venue_health": health,
                    }
                resting = [
                    o
                    for o in _asset_open_orders(client, token_id)
                    if str(o.get("id")) not in before["order_ids"]
                ]
                if resting:
                    _confirm_buy_intent_best_effort(cs, token_id_int)
                    return {
                        "submission": "resting",
                        "warning": (
                            f"the CLOB response was lost ({err_text}) but the "
                            "order rests on the book — do NOT resubmit; manage "
                            "it with trade.py order/cancel"
                        ),
                        "open_orders": resting,
                        "venue_health": health,
                    }
            except Exception:  # nosec B112 # noqa: BLE001 - reads may share the outage
                continue
    pm.print_json(
        {
            "submission": "unknown",
            "error": err_text,
            "venue_health": health,
            "recovery": (
                "no fill or resting order became visible within "
                f"~{sum(RECONCILE_DELAYS)}s, but that does NOT prove the order "
                "was dropped — the engine can hold a reservation with nothing "
                "visible. The buy intent stays recorded; re-check trades, open "
                "orders and the DW balance before any retry — an immediate "
                "retry risks a double fill"
            ),
        }
    )
    raise SystemExit(1)


def _verify_matched_settlement(client, token_id: str, order_id, before_trade_ids):
    """Hold a "matched" response provisional until a backing trade appears.

    A ``success: true / status: matched`` payload with tradeIDs has been
    observed settling nothing, with an order id the CLOB later disowned (a
    phantom match). Only a trade attributed to this order id — or one that is
    new since submission — upgrades the match to settled.
    """
    want = str(order_id or "").lower()
    for delay in (0, *RECONCILE_DELAYS):
        if delay:
            time.sleep(delay)
        try:
            trades = _asset_trades(client, token_id)
        except Exception:  # nosec B112 # noqa: BLE001 - keep polling through blips
            continue
        backing = [
            t
            for t in trades
            if want and str(t.get("taker_order_id", "")).lower() == want
        ]
        if not backing and before_trade_ids is not None:
            backing = [t for t in trades if str(t.get("id")) not in before_trade_ids]
        if backing:
            return {"settlement": "settled", "settlement_trades": backing}
    return {
        "settlement": "unverified",
        "warning": (
            "the CLOB answered success/matched but no backing trade appeared "
            f"within ~{sum(RECONCILE_DELAYS)}s — treat this as a possible "
            "phantom match, not a position. The buy intent stays recorded; "
            "verify with trade.py order --id, the trade list and the DW "
            "balance before treating the funds as spent or retrying"
        ),
    }


def _post_buy_with_recovery_hint(client, cs, token_id: str, order, order_type):
    """Post a buy while preserving enough state to recover an unknown outcome.

    Persist the token before submission: the CLOB may accept and fill the order
    even if its response is lost. A later sweep can then check the DW's
    on-chain balance directly instead of depending on the lagging data API.

    A structured ``success: false`` response or status-code 401 authentication
    rejection proves that no order was submitted. Auth-class errors propagate
    for the credential refresh; other CLOB 4xx responses propagate as definite
    answers. What remains — timeouts, connection drops, 408/5xx — is genuinely
    ambiguous and is reconciled against trades and open orders rather than
    reported as failure. A "matched" success is likewise held provisional
    until a backing trade is visible: the venue has answered success for
    orders that never settled.
    """
    token_id_int = int(token_id)
    before = _pre_submission_state(client, token_id)
    # This happens before funds may move, so a state-write failure must abort
    # the submission rather than proceed without the recovery hint.
    pm.record_dw_buy_intent(cs, token_id_int)
    try:
        response = client.post_order(order, order_type)
    except PolyApiException as e:
        if _definitive_auth_rejection(e):
            pm.reject_dw_buy_intent(cs, token_id_int)
            raise
        if _auth_failed(e) or not _submission_outcome_unknown(e):
            raise
        return _reconcile_lost_submission(client, cs, token_id, before, e)
    if isinstance(response, dict) and response.get("success") is False:
        pm.reject_dw_buy_intent(cs, token_id_int)
        detail = response.get("errorMsg") or "CLOB rejected the buy"
        raise SystemExit(str(detail))
    status = (
        str(response.get("status") or "").lower() if isinstance(response, dict) else ""
    )
    if status == "matched":
        verdict = _verify_matched_settlement(
            client,
            token_id,
            response.get("orderID"),
            before["trade_ids"] if before is not None else None,
        )
        response = {**response, **verdict}
        if verdict["settlement"] == "settled":
            _confirm_buy_intent_best_effort(cs, token_id_int)
        # unverified: the pending marker deliberately stays for the sweep
        return response
    _confirm_buy_intent_best_effort(cs, token_id_int)
    return response


def cmd_buy(cs: pm.ConnectSigner, token_id: str, usd: float, order_type: str) -> None:
    """Market buy: spend `usd` pUSD on an outcome token (default FOK).

    The DW's live pUSD balance is passed as user_usdc_balance so the SDK
    sizes the order to amount - exact fee (the CLOB fee is price-dependent;
    a flat reserve both over- and under-shoots).
    """
    ot = _order_type(order_type)

    def op(client, dw):
        balance = pm.units_to_usd(pm.erc20_balance_of(cs.w3, pm.PUSD, dw))
        if balance <= 0:
            raise SystemExit(
                "the DepositWallet holds no pUSD — run `funds.py top-up` first"
            )
        # The CLOB rejects marketable buys under $1, and when the DW balance
        # is at/near the order amount the SDK shrinks the order by the
        # market's taker-fee reserve (fee = shares × rate × (p·(1-p))^exp;
        # rate is per-market, 0–7%) — a $1.00 bet on a $1.00 balance bounces
        # (verified live; the same mechanism breaks $1 bets in the trader).
        # Preflight with the SDK's own sizing so the error is exact.
        try:
            price = client.calculate_market_price(token_id, BUY, usd, ot)
            adjusted = client._adjust_buy_amount_for_balance(
                token_id, usd, price, balance, None
            )
            if adjusted < usd and adjusted < 1.0:
                # fee at full size = what a balance of exactly `usd` can't cover
                fee = usd - client._adjust_buy_amount_for_balance(
                    token_id, usd, price, usd, None
                )
                raise SystemExit(
                    f"a ${usd:.2f} buy against a {balance:.6f} pUSD balance "
                    f"would be fee-shrunk to ${adjusted:.2f}, below the CLOB's "
                    f"$1 marketable minimum — top the DW up to at least "
                    f"{usd + fee:.4f} pUSD, or raise the bet"
                )
        except SystemExit:
            raise
        # advisory preflight (empty book etc.): on any error, fall through and
        # let the CLOB itself validate the order.
        except Exception:  # noqa: BLE001 # nosec B110
            pass
        order = client.create_market_order(
            MarketOrderArgs(
                token_id=token_id,
                amount=usd,
                side=BUY,
                order_type=ot,
                user_usdc_balance=balance,
            )
        )
        return _post_buy_with_recovery_hint(client, cs, token_id, order, ot)

    _run_client(cs, op, retry_auth=False)


def cmd_sell(
    cs: pm.ConnectSigner, token_id: str, shares: float, order_type: str
) -> None:
    """Market sell of outcome shares (default FAK).

    Sign + post fresh on every call: once the CLOB has acknowledged a signed
    order its id is indexed server-side and a resubmit is rejected as a
    duplicate — re-signing is one remote ECDSA, cheap. The shares must be in
    the DW when the order matches (sell before sweeping them to the safe).
    """
    ot = _order_type(order_type)

    def op(client, dw):
        order = client.create_market_order(
            MarketOrderArgs(
                token_id=token_id,
                amount=shares,
                side=Side.SELL,
                order_type=ot,
            )
        )
        return client.post_order(order, ot)

    _run_client(cs, op, retry_auth=False)


def cmd_limit(  # pylint: disable=too-many-arguments
    cs: pm.ConnectSigner,
    token_id: str,
    side: str,
    price: float,
    size: float,
    order_type: str,
    expires_in: int | None,
) -> None:
    """Resting limit order (GTC, or GTD with --expires-in seconds).

    BUY funds must already sit in the DW when the order matches. A BUY token
    is recorded to the DW-holdings hint on placement: a resting order can
    fill before the data-API indexer reflects it, and a sweep run for any
    reason in that window would otherwise omit the just-filled position while
    still reporting success. The hint is dropped once the position is swept;
    an order that never fills leaves a harmless zero-balance hint that sweep
    simply skips.
    """
    order_side = BUY if side == "buy" else SELL
    ot = _order_type(order_type)
    expiration = 0
    if ot == OrderType.GTD:
        if not expires_in:
            raise SystemExit("--expires-in <seconds> is required for gtd orders")
        expiration = int(time.time()) + expires_in

    def op(client, dw):
        order = client.create_order(
            OrderArgs(
                token_id=token_id,
                price=price,
                size=size,
                side=order_side,
                expiration=expiration,
            )
        )
        if order_side == BUY:
            return _post_buy_with_recovery_hint(client, cs, token_id, order, ot)
        return client.post_order(order, ot)

    _run_client(cs, op, retry_auth=False)


def cmd_order(cs: pm.ConnectSigner, order_id: str) -> None:
    """Status of an order by id."""
    _run_client(cs, lambda client, dw: client.get_order(order_id))


def cmd_cancel(cs: pm.ConnectSigner, order_id: str) -> None:
    """Cancel a resting order by id."""
    _run_client(
        cs, lambda client, dw: client.cancel_order(OrderPayload(orderID=order_id))
    )


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    buy = sub.add_parser("buy")
    buy.add_argument("--token-id", required=True)
    buy.add_argument("--usd", type=float, required=True)
    buy.add_argument("--order-type", choices=["fok", "fak"], default="fok")
    sell = sub.add_parser("sell")
    sell.add_argument("--token-id", required=True)
    sell.add_argument("--shares", type=float, required=True)
    sell.add_argument("--order-type", choices=["fak", "fok"], default="fak")
    limit = sub.add_parser("limit")
    limit.add_argument("--token-id", required=True)
    limit.add_argument("--side", choices=["buy", "sell"], required=True)
    limit.add_argument("--price", type=float, required=True)
    limit.add_argument("--size", type=float, required=True)
    limit.add_argument("--order-type", choices=["gtc", "gtd"], default="gtc")
    limit.add_argument("--expires-in", type=int, default=None)
    order = sub.add_parser("order")
    order.add_argument("--id", required=True)
    cancel = sub.add_parser("cancel")
    cancel.add_argument("--id", required=True)
    args = parser.parse_args()
    cs = pm.ConnectSigner.from_workspace()
    if args.command == "buy":
        cmd_buy(cs, args.token_id, args.usd, args.order_type)
    elif args.command == "sell":
        cmd_sell(cs, args.token_id, args.shares, args.order_type)
    elif args.command == "limit":
        cmd_limit(
            cs,
            args.token_id,
            args.side,
            args.price,
            args.size,
            args.order_type,
            args.expires_in,
        )
    elif args.command == "order":
        cmd_order(cs, args.id)
    elif args.command == "cancel":
        cmd_cancel(cs, args.id)


if __name__ == "__main__":
    main()
