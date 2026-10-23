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

Prerequisites: `deposit_wallet.py ensure` first, then `funds.py top-up` with
the pUSD the buy will spend. After trading, ALWAYS `funds.py sweep` — the
funds-flow contract keeps persistent assets in the recoverable service safe.

Usage:
    python trade.py quote --token-id 123... --usd 10.0     # price a buy first
    python trade.py buy   --token-id 123... --usd 10.0     # market buy (default FOK)
    python trade.py sell  --token-id 123... --shares 12.5  # market sell (default FAK)
    python trade.py limit --token-id 123... --side buy --price 0.42 --size 20
    python trade.py order --id 0x...                       # order status
    python trade.py cancel --id 0x...                      # cancel a resting order

`quote` places nothing — it is `buy`'s preflight, readable before committing
rather than only as a rejected order's error message (see `pm.quote_buy`).

Market orders take --order-type fok|fak (defaults match the production
trader: FOK buys, FAK sells). Limit orders take --order-type gtc|gtd
(--expires-in seconds is required for gtd). Amount semantics are the CLOB's
market-order convention: buys spend pUSD ("--usd"), sells move outcome
shares ("--shares").
"""

import argparse
import sys
import time
from decimal import Decimal

import pm_common as pm
from deposit_wallet import dw_or_exit
from polymarket._internal.actions.orders.market import adjust_buy_amount_for_fees
from polymarket.errors import (
    RateLimitError,
    RequestRejectedError,
    TransportError,
    UnexpectedResponseError,
)
from remote_signer import clear_cached_creds, make_clob_client

_API_ERRORS = (
    RequestRejectedError,
    RateLimitError,
    TransportError,
    UnexpectedResponseError,
)

# Order-reply codes that prove the order was not placed. Any other refusal
# ("unmatched", "unknown", or a code a later SDK adds) leaves placement uncertain.
_REFUSED_CODES = (
    "market_not_ready",
    "not_enough_balance",
    "invalid_nonce",
    "invalid_expiration",
    "post_only_would_cross",
    "post_only_mode",
    "fok_not_filled",
    "fak_not_filled",
)
_UNCERTAIN = (
    "placement uncertain: the CLOB's reply does not show whether the order was "
    "placed ({}); before retrying, check the chain after a minute or so, since "
    "a fill settles there after the match (positions.py positions --wallet dw "
    "--token-ids {}): a limit order may instead rest unfilled on the book, "
    "where no position shows it"
)


def _auth_failed(e: Exception) -> bool:
    """Whether a CLOB rejection looks like stale/invalid API credentials."""
    code = getattr(e, "status", None)
    msg = str(e).lower()
    return code == 401 or "unauthorized" in msg or "apikey" in msg or "api key" in msg


def _definitive_auth_rejection(e: Exception) -> bool:
    """Whether the response proves authentication failed before submission."""
    return getattr(e, "status", None) == 401


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
    except _API_ERRORS as e:
        if not _auth_failed(e):
            pm.print_json({"error": str(e)})
            raise SystemExit(1) from e
        clear_cached_creds(cs)
        if not retry_auth:
            error = {
                "error": str(e),
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
        except _API_ERRORS as e2:
            pm.print_json({"error": str(e2)})
            raise SystemExit(1) from e2
    if hasattr(result, "model_dump"):
        result = result.model_dump()
    pm.print_json(result)


def _post(client, order, token_id: str):
    """Post a signed order; refuse when its reply leaves placement uncertain.

    Uncertain: a refusal code not in `_REFUSED_CODES`, no reply, an unreadable
    one, or a 5xx.
    """
    try:
        response = client.post_order(order)
    except (TransportError, UnexpectedResponseError) as e:
        raise SystemExit(_UNCERTAIN.format(e, token_id)) from e
    except RequestRejectedError as e:
        if e.status >= 500:
            raise SystemExit(_UNCERTAIN.format(e, token_id)) from e
        raise
    if not response.ok and response.code not in _REFUSED_CODES:
        raise SystemExit(_UNCERTAIN.format(response.message, token_id))
    return response


def _quote(client, token_id: str, usd: float, balance: float, order_type: str):
    """`pm.quote_buy` on the SDK's price estimate and fee-aware buy sizing."""
    price = client.estimate_market_price(
        token_id=token_id, side=pm.BUY_SIDE, amount=usd, order_type=order_type
    )
    # pylint: disable-next=protected-access
    market = client._ctx.order_metadata.resolve_market(client._ctx, token_id=token_id)

    def spend(funds: Decimal) -> Decimal:
        return adjust_buy_amount_for_fees(
            amount=Decimal(str(usd)), price=price, max_spend=funds, fee=market.fee_info
        )

    return pm.quote_buy(token_id, usd, balance, order_type, float(price), spend)


def _post_buy_with_recovery_hint(client, cs, token_id: str, order):
    """Post a buy; only a refusal code or a 401 drops its pending marker."""
    token_id_int = int(token_id)
    # This happens before funds may move, so a state-write failure must abort
    # the submission rather than proceed without the recovery hint.
    pm.record_dw_buy_intent(cs, token_id_int)
    try:
        response = _post(client, order, token_id)
    except _API_ERRORS as e:
        if _definitive_auth_rejection(e):
            pm.reject_dw_buy_intent(cs, token_id_int)
        raise
    if not response.ok:
        pm.reject_dw_buy_intent(cs, token_id_int)
        raise SystemExit(response.message)
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

    The DW's live pUSD balance is the SDK's spend cap, so it sizes the order
    to what the balance covers once the exact fee is held back, the way
    `pm.quote_buy` prices it (the CLOB fee is price-dependent; a flat reserve
    both over- and under-shoots).
    """
    ot = order_type.upper()
    pm.require_supported_market(token_id)

    def op(client, dw):
        balance = pm.units_to_usd(pm.erc20_balance_of(cs.w3, pm.PUSD, dw))
        if balance <= 0:
            raise SystemExit(
                "the DepositWallet holds no pUSD — run `funds.py top-up` first"
            )
        # Preflight with the SDK's own sizing (see pm.MIN_MARKETABLE_USD) so
        # the error names the exact top-up, not just the CLOB's bare refusal.
        try:
            quote = _quote(client, token_id, usd, balance, ot)
            if quote["blocked"]:
                raise SystemExit(
                    f"a ${usd:.2f} buy against a {balance:.6f} pUSD balance "
                    f"would be rejected: {quote['blocked_reason']}. "
                    "`trade.py quote` shows these numbers without placing "
                    "anything"
                )
        except SystemExit:
            raise
        # advisory preflight (empty book etc.): on any error, fall through and
        # let the CLOB itself validate the order.
        except Exception:  # noqa: BLE001 # nosec B110
            pass
        # dust: the SDK would size the order to nothing
        if balance < pm.MIN_MARKETABLE_USD:
            raise SystemExit(
                f"a ${usd:.2f} buy against a {balance:.6f} pUSD balance would be "
                f"rejected: under the CLOB's ${pm.MIN_MARKETABLE_USD:.0f} "
                "marketable minimum — run `funds.py top-up` first"
            )
        order = client.create_market_order(
            token_id=token_id,
            side=pm.BUY_SIDE,
            amount=usd,
            max_spend=balance,
            order_type=ot,
        )
        return _post_buy_with_recovery_hint(client, cs, token_id, order)

    _run_client(cs, op, retry_auth=False)


def cmd_quote(cs: pm.ConnectSigner, token_id: str, usd: float, order_type: str) -> None:
    """Price a buy against the live book without placing anything.

    Deliberately tolerates an empty DW: "how much do I need to top up?" is
    the question a quote is usually asked, and refusing on a zero balance
    the way `buy` does would withhold the answer exactly when it is needed.
    """
    ot = order_type.upper()

    pm.require_supported_market(token_id)

    def op(client, dw):
        balance = pm.units_to_usd(pm.erc20_balance_of(cs.w3, pm.PUSD, dw))
        return _quote(client, token_id, usd, balance, ot)

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
    ot = order_type.upper()
    pm.require_supported_market(token_id)

    def op(client, dw):
        order = client.create_market_order(
            token_id=token_id, side="SELL", shares=shares, order_type=ot
        )
        return _post(client, order, token_id)

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
    order_side = side.upper()
    ot = order_type.upper()
    expiration = None  # the SDK signs GTD when an expiration is set, else GTC
    if ot == "GTD":
        if not expires_in:
            raise SystemExit("--expires-in <seconds> is required for gtd orders")
        expiration = int(time.time()) + expires_in
    pm.require_supported_market(token_id)

    def op(client, dw):
        order = client.create_limit_order(
            token_id=token_id,
            price=price,
            size=size,
            side=order_side,
            expiration=expiration,
        )
        if order_side == pm.BUY_SIDE:
            return _post_buy_with_recovery_hint(client, cs, token_id, order)
        return _post(client, order, token_id)

    _run_client(cs, op, retry_auth=False)


def cmd_order(cs: pm.ConnectSigner, order_id: str) -> None:
    """Status of an order by id."""
    _run_client(cs, lambda client, dw: client.get_order(order_id=order_id))


def cmd_cancel(cs: pm.ConnectSigner, order_id: str) -> None:
    """Cancel a resting order by id."""
    _run_client(cs, lambda client, dw: client.cancel_order(order_id=order_id))


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    quote = sub.add_parser("quote")
    quote.add_argument("--token-id", required=True)
    quote.add_argument("--usd", type=float, required=True)
    quote.add_argument("--order-type", choices=["fok", "fak"], default="fok")
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
    if args.command == "quote":
        cmd_quote(cs, args.token_id, args.usd, args.order_type)
    elif args.command == "buy":
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
