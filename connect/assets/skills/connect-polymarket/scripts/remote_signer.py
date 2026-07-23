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

``py_clob_client_v2``'s ``Signer`` interface is ``address()``,
``get_chain_id()`` and ``sign(message_hash)``; L1 auth funnels through
``sign``. The order builders, however, bypass it and call
``Account._sign_hash / Account.sign_message`` with ``signer.private_key``
directly — so besides :class:`RemoteSigner` (the interface duck-type), the
builder modules' ``Account`` symbol is patched with a shim that routes to
connect when the "key" is a RemoteSigner sentinel. Both paths end in the
same remote ECDSA over a digest; no key material exists in this process.
"""

from eth_account import Account as _RealAccount
from eth_account.messages import _hash_eip191_message
from hexbytes import HexBytes
from pm_common import (
    CHAIN_ID,
    CLOB_HOST,
    ConnectSigner,
    load_state,
    save_state,
)
from py_clob_client_v2 import ClobClient
from py_clob_client_v2.clob_types import ApiCreds
from py_clob_client_v2.order_builder.builder import OrderBuilder
from py_clob_client_v2.order_utils import exchange_order_builder_v1 as _builder_v1
from py_clob_client_v2.order_utils import exchange_order_builder_v2 as _builder_v2

# CLOB v2 order-signing scheme: POLY_1271 (smart-contract 1271 signatures)
# with the DepositWallet as funder.
SIGNATURE_TYPE_POLY_1271 = 3


class RemoteSigner:
    """Duck-type of the SDK ``Signer`` that signs through the connect signer."""

    def __init__(self, cs: ConnectSigner, chain_id: int = CHAIN_ID) -> None:
        """Initialize with a connect signer client."""
        self._cs = cs
        self._chain_id = chain_id
        self._address = cs.agent_eoa

    def address(self) -> str:
        """Return the agent EOA address."""
        return self._address

    def get_chain_id(self) -> int:
        """Return the EVM chain id orders are signed for."""
        return self._chain_id

    def sign(self, message_hash) -> str:
        """Sign a 32-byte message hash (0x-hex or bytes) via connect."""
        return self._cs.sign_digest(message_hash)

    @property
    def private_key(self) -> "RemoteSigner":
        """Sentinel for the SDK's direct-Account paths (see _AccountShim)."""
        return self


class _Signed:
    """The one attribute the SDK reads off eth_account's signed result."""

    def __init__(self, signature_hex: str) -> None:
        self.signature = HexBytes(signature_hex)


class _AccountShim:
    """Drop-in for the order builders' ``Account``: remote-signs sentinels.

    The builders call ``Account._sign_hash(digest, private_key=...)`` (the
    POLY_1271 ERC-7739 path) and ``Account.sign_message(encoded, ...)``
    (the EOA path) with ``signer.private_key``. With a RemoteSigner sentinel
    the digest is signed through connect; a real key delegates to
    eth_account unchanged.
    """

    @staticmethod
    def _sign_hash(digest, private_key=None):
        if isinstance(private_key, RemoteSigner):
            return _Signed(private_key.sign(digest))
        return _RealAccount._sign_hash(digest, private_key=private_key)

    @staticmethod
    def sign_message(encoded, private_key=None):
        if isinstance(private_key, RemoteSigner):
            return _Signed(private_key.sign(_hash_eip191_message(encoded)))
        return _RealAccount.sign_message(encoded, private_key=private_key)


_builder_v1.Account = _AccountShim
_builder_v2.Account = _AccountShim


def make_clob_client(cs: ConnectSigner, funder: str) -> ClobClient:
    """Build a ClobClient signing POLY_1271 orders funded by ``funder`` (the DW).

    The client is built key-less, then its signer and order builder are bound
    to the :class:`RemoteSigner`. API creds are tied to the signer EOA (not
    the funder — matches the production trader); they are derived once via an
    L1 signature and cached in the workspace state (revocable API creds, not
    key material).
    """
    client = ClobClient(
        CLOB_HOST,
        chain_id=CHAIN_ID,
        signature_type=SIGNATURE_TYPE_POLY_1271,
        funder=funder,
    )
    signer = RemoteSigner(cs)
    client.signer = signer
    client.builder = OrderBuilder(
        signer=signer, signature_type=SIGNATURE_TYPE_POLY_1271, funder=funder
    )
    client.mode = client._get_client_mode()  # L1 now that a signer is bound

    state = load_state(cs)
    cached = state.get("clob_creds")
    if cached:
        creds = ApiCreds(
            api_key=cached["api_key"],
            api_secret=cached["api_secret"],
            api_passphrase=cached["api_passphrase"],
        )
    else:
        # create_or_derive tries create first and falls back to derive; the
        # SDK logs a harmless ERROR on the create path for an existing key.
        creds = client.create_or_derive_api_key()
        state["clob_creds"] = {
            "api_key": creds.api_key,
            "api_secret": creds.api_secret,
            "api_passphrase": creds.api_passphrase,
        }
        save_state(cs, state)
    client.set_api_creds(creds)
    client.mode = client._get_client_mode()  # L2 with creds bound
    return client


def clear_cached_creds(cs: ConnectSigner) -> None:
    """Forget cached CLOB API creds so the next client re-derives them.

    Cached creds can go stale (e.g. server-side rotation); on an auth failure
    the caller clears them and rebuilds the client, which derives fresh creds
    via a new L1 signature.
    """
    state = load_state(cs)
    if state.pop("clob_creds", None) is not None:
        save_state(cs, state)
