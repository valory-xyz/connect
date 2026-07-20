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
from py_clob_client_v2.clob_types import OrderPayload
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


def _run_client(cs: pm.ConnectSigner, op) -> None:
    """Build a DW-funded CLOB client, run op(client, dw), print the result.

    On an auth-class failure the cached creds are cleared and the client is
    rebuilt once (re-deriving fresh creds), so a server-side key rotation
    self-heals instead of failing every order. Other rejections print the
    API's error body and exit 1.
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
        client = make_clob_client(cs, dw)  # re-derives creds
        try:
            result = op(client, dw)
        except PolyApiException as e2:
            pm.print_json({"error": str(getattr(e2, "error_msg", "") or e2)})
            raise SystemExit(1) from e2
    pm.print_json(result)


def _post_buy_with_recovery_hint(client, cs, token_id: str, order, order_type):
    """Post a buy while preserving enough state to recover an unknown outcome.

    Persist the token before submission: the CLOB may accept and fill the order
    even if its response is lost. A later sweep can then check the DW's
    on-chain balance directly instead of depending on the lagging data API.

    Only a structured ``success: false`` response is treated as a definitive
    rejection. HTTP exceptions remain ambiguous: a timeout, rate limit, or
    intermediary response may arrive after the request reached the CLOB. A
    harmless zero-balance hint is safer than an undiscoverable filled position.
    """
    token_id_int = int(token_id)
    # This happens before funds may move, so a state-write failure must abort
    # the submission rather than proceed without the recovery hint.
    pm.record_dw_buy_intent(cs, token_id_int)
    response = client.post_order(order, order_type)
    if isinstance(response, dict) and response.get("success") is False:
        pm.reject_dw_buy_intent(cs, token_id_int)
        detail = response.get("errorMsg") or "CLOB rejected the buy"
        raise SystemExit(str(detail))
    try:
        pm.confirm_dw_buy_intent(cs, token_id_int)
    except Exception as e:  # noqa: BLE001 - post succeeded; retain pending marker
        print(
            f"WARNING: could not mark buy {token_id_int} confirmed ({e}); "
            "the action itself succeeded and its recovery hint remains pending",
            file=sys.stderr,
        )
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

    _run_client(cs, op)


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

    _run_client(cs, op)


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

    _run_client(cs, op)


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
