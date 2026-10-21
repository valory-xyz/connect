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

"""CLOB SDK client with signing routed through the connect signer.

The unified SDK (``polymarket-client``) signs with the signer object its
client holds: it reads ``address`` and calls ``sign_typed_data`` (orders,
the CLOB's L1 auth) or ``sign_message``. :class:`RemoteSigner` hashes each
locally and has connect sign the digest, so no key material exists in this
process.
"""

import time

from eth_account.messages import _hash_eip191_message, encode_typed_data
from pm_common import ConnectSigner, load_state, save_state
from polymarket import ApiKeyCreds, PRODUCTION, SecureClient
from polymarket._internal.actions.auth import create_api_key_sync, derive_api_key_sync
from polymarket._internal.actions.orders.post import build_post_order_request
from polymarket._internal.environment import get_environment_config
from polymarket._internal.l1_auth import sign_api_key_auth
from polymarket.clients._transport import SyncTransport


class _Signed:
    """The one attribute the SDK reads off eth_account's signed result."""

    def __init__(self, signature_hex: str) -> None:
        self.signature = bytes.fromhex(signature_hex.removeprefix("0x"))


class RemoteSigner:
    """The SDK's signer object, signing through the connect signer."""

    def __init__(self, cs: ConnectSigner) -> None:
        """Initialize with a connect signer client."""
        self._cs = cs
        self.address = cs.agent_eoa

    def sign_typed_data(self, full_message: dict) -> _Signed:
        """Sign EIP-712 typed data (an order or the L1 auth) via connect."""
        return self.sign_message(encode_typed_data(full_message=full_message))

    def sign_message(self, signable) -> _Signed:
        """Sign an EIP-191 signable message via connect."""
        return _Signed(self._cs.sign_digest(_hash_eip191_message(signable)))


class ConnectClient(SecureClient):
    """The SDK client, answering order calls with the CLOB's own JSON.

    Also carries the buy sizing ``pm.quote_buy`` and ``buy`` share.
    """

    def post_order(self, signed_order) -> dict:
        """Post a signed order; return the CLOB's reply as it sent it.

        The SDK's reply model renames the fields, and it reads a placed
        ``success: true, status: unmatched`` order as a rejection.
        """
        path, payload = build_post_order_request(
            signed_order, owner_api_key=self._ctx.credentials.key
        )
        return self._ctx.secure_clob.post_json(path, json=payload)

    def get_order(self, *, order_id: str) -> dict:
        """One order's status, as the CLOB's JSON (times as it sent them)."""
        return self._ctx.secure_clob.get_json(f"/data/order/{order_id}")

    def get_open_orders(self) -> list:
        """Every open order, as the CLOB's JSON rows, read page by page.

        The SDK's strict order model rejects rows the CLOB does send (a null
        ``associate_trades``, missing fields), and those are still orders.
        Pages run from the CLOB's start cursor until its end marker; a page
        that is not a list of rows raises rather than reading as no orders.
        """
        orders: list = []
        cursor = "MA=="  # the CLOB's start-of-list cursor
        while cursor != "LTE=":  # the CLOB's no-more-pages marker
            page = self._ctx.secure_clob.get_json(
                "/data/orders", params={"next_cursor": cursor}
            )
            rows, cursor = page["data"], page["next_cursor"]
            if not isinstance(rows, list) or not all(
                isinstance(row, dict) for row in rows
            ):
                raise ValueError(f"malformed /data/orders page: {page!r}")
            orders.extend(rows)
        return orders

    def calculate_market_price(
        self, token_id: str, side: str, amount: float, order_type: str
    ) -> float:
        """Price level a market order of ``amount`` reaches on the live book."""
        return float(
            self.estimate_market_price(
                token_id=token_id, side=side, amount=amount, order_type=order_type
            )
        )

    def _adjust_buy_amount_for_balance(
        self, token_id: str, amount: float, price: float, balance: float, _builder: None
    ) -> float:
        """Spend what ``balance`` covers once the market's taker fee is held back.

        The fee is charged on min(amount, balance) and taken out of the
        balance, so a balance of exactly ``amount`` leaves amount - fee.
        """
        market = self._ctx.order_metadata.resolve_market(self._ctx, token_id=token_id)
        fee_info = market.fee_info
        rate = float(fee_info.rate) * (price * (1 - price)) ** float(fee_info.exponent)
        fee = min(amount, balance) / price * rate
        if balance > amount + fee:
            return amount
        return max(balance - fee, 0.0)


def make_clob_client(cs: ConnectSigner, funder: str) -> ConnectClient:
    """Build an SDK client signing POLY_1271 orders funded by ``funder`` (the DW).

    The agent EOA signs as the DW's owner, the signature the DW validates;
    it is set here rather than left to the SDK, which treats a DW it cannot
    derive from the EOA as a session key's. API creds are tied to the signer
    EOA (not the funder, matching the production trader); they are derived
    once via an L1 signature and cached in the workspace state (revocable
    API creds, not key material).
    """
    signer = RemoteSigner(cs)
    config = get_environment_config(PRODUCTION)
    state = load_state(cs)
    cached = state.get("clob_creds")
    if cached:
        creds = ApiKeyCreds(
            key=cached["api_key"],
            secret=cached["api_secret"],
            passphrase=cached["api_passphrase"],
        )
    else:
        # creates the key, or derives it when creating fails for any reason
        # (one exists already, or no answer); nonce 0 as before
        auth = sign_api_key_auth(
            signer, chain_id=config.chain_id, timestamp=int(time.time()), nonce=0
        )
        clob = SyncTransport(base_url=config.clob_url)
        try:
            creds = create_api_key_sync(clob, auth)
        except Exception:  # noqa: BLE001 - as the old client, on any failure
            creds = derive_api_key_sync(clob, auth)
        finally:
            clob.close()
        state["clob_creds"] = {
            "api_key": creds.key,
            "api_secret": creds.secret,
            "api_passphrase": creds.passphrase,
        }
        save_state(cs, state)
    return ConnectClient._construct_for_wallet(
        signer=signer,
        wallet=funder,
        wallet_type="DEPOSIT_WALLET",
        signer_type="OWNER",
        environment=PRODUCTION,
        config=config,
        credentials=creds,
        api_key=None,
        logger=None,
        on_rate_limit_update=None,
    )


def clear_cached_creds(cs: ConnectSigner) -> None:
    """Forget cached CLOB API creds so the next client re-derives them.

    Cached creds can go stale (e.g. server-side rotation); on an auth failure
    the caller clears them and rebuilds the client, which derives fresh creds
    via a new L1 signature.
    """
    state = load_state(cs)
    if state.pop("clob_creds", None) is not None:
        save_state(cs, state)
