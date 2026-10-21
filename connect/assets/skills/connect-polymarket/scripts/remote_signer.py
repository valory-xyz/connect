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
from polymarket._internal.actions.auth import create_or_derive_api_key_sync
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


def _refuse_direct_send(*args, **kwargs):
    """Refuse an SDK call that would send past Connect's relayer proxy."""
    raise NotImplementedError(
        "sends a transaction or order outside Connect's relayer proxy; use the "
        "skill's scripts instead"
    )


class ConnectClient(SecureClient):
    """The SDK client, with its own senders closed.

    Each signs through Connect and goes straight to Polymarket: the place_*
    calls post past the scripts' order flow, and the rest go to the relayer
    or builder gateway rather than through Connect's relayer proxy.
    """

    approve_erc20 = approve_erc1155_for_all = transfer_erc20 = _refuse_direct_send
    setup_trading_approvals = execute_transaction = _refuse_direct_send
    split_position = merge_positions = merge_multiple_positions = _refuse_direct_send
    redeem_positions = execute_collateral_return_plan = _refuse_direct_send
    place_limit_order = place_market_order = accept_combo_quote = _refuse_direct_send
    authorize_session_key = revoke_session_key = _refuse_direct_send


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
        # the SDK's create-or-derive (derives once creating answers 400);
        # nonce 0 as before
        auth = sign_api_key_auth(
            signer, chain_id=config.chain_id, timestamp=int(time.time()), nonce=0
        )
        clob = SyncTransport(base_url=config.clob_url)
        try:
            creds = create_or_derive_api_key_sync(clob, auth)
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
