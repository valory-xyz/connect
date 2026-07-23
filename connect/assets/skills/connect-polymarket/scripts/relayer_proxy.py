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

"""Client for the predict-api relayer proxy (Polymarket CLOB v2 DepositWallet).

Polymarket's DepositWallet relayer requires a Verified-tier Builder key that
cannot ship in a desktop client, so all DW operations go through a proxy that
holds the credential (default: Valory's, ``https://mpp.valory.xyz``; override
with ``POLYMARKET_RELAYER_PROXY_URL``). Ported from the production trader's
``polymarket_client`` connection, with every signature routed through the
connect signer instead of a local key.

Endpoints (under ``{base_url}/polymarket/relayer/``)::

    POST /deploy_dw          deploy a DepositWallet owned by the agent EOA
    POST /exec_wallet_batch  relay a DW execute(Batch, sig) of calls
    GET  /deployed           whether a DW is registered
    GET  /transaction        relayer tx state (mined / failed)

Every call is authenticated with a challenge signed by the agent EOA
(EIP-191 personal_sign via the connect signer).
"""

import os
import secrets
import time
import typing as t

import requests
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from pm_common import (
    CHAIN_ID,
    ConnectSigner,
    DEFAULT_RELAYER_PROXY_URL,
    DW_FACTORY,
)

CHALLENGE_PREFIX = "wildcard-relayer:v2"
RELAYER_PATH_PREFIX = "/polymarket/relayer"
PROXY_REQUEST_TIMEOUT = 30

# EIP-712 typehashes for the DepositWallet ``Batch`` envelope.
_EIP712_DOMAIN_TYPEHASH = keccak(
    text=(
        "EIP712Domain(string name,string version,uint256 chainId,"
        "address verifyingContract)"
    )
)
_CALL_TYPEHASH = keccak(text="Call(address target,uint256 value,bytes data)")
_BATCH_TYPEHASH = keccak(
    text=(
        "Batch(address wallet,uint256 nonce,uint256 deadline,Call[] calls)"
        "Call(address target,uint256 value,bytes data)"
    )
)
_DW_DOMAIN_NAME_HASH = keccak(text="DepositWallet")
_DW_DOMAIN_VERSION_HASH = keccak(text="1")
# Calls are always value-0 (token transfers / approvals carry no native value).
_CALL_VALUE = 0
_BATCH_DEADLINE_SECONDS = 3600

# Relayer transaction states (GET /transaction). MINED/CONFIRMED are terminal
# success; FAILED/INVALID are terminal failure; anything else is in-flight.
TX_TERMINAL_OK = ("STATE_MINED", "STATE_CONFIRMED")
TX_TERMINAL_FAIL = ("STATE_FAILED", "STATE_INVALID")

# Cooperative-poll backoffs (seconds) for a relayer tx to mine — ~4 minutes
# total, comfortably above the observed relayer mining latency.
POLL_BACKOFFS = (5, 10, 15, 20, 30, 30, 60, 60)


class RelayerProxyError(Exception):
    """Raised when the relayer proxy returns an error or an unusable response."""


def proxy_url() -> str:
    """Return the proxy base URL (env override, else the production default)."""
    return os.environ.get(
        "POLYMARKET_RELAYER_PROXY_URL", DEFAULT_RELAYER_PROXY_URL
    ).rstrip("/")


class RelayerProxyClient:
    """Challenge-authenticated client for the relayer proxy.

    Stateless beyond the connect signer; each method issues one HTTP request.
    """

    def __init__(self, cs: ConnectSigner, base_url: str | None = None) -> None:
        """Initialize with a connect signer (the agent EOA signs challenges)."""
        self._cs = cs
        self.base_url = (base_url or proxy_url()).rstrip("/")

    @property
    def address(self) -> str:
        """The agent EOA used as the relayer ``from``."""
        return self._cs.agent_eoa

    def _path(self, endpoint: str) -> str:
        return f"{RELAYER_PATH_PREFIX}/{endpoint}"

    def _auth_headers(self, path: str) -> dict:
        """Challenge-auth headers binding caller, path, timestamp and nonce."""
        ts = str(int(time.time() * 1000))
        nonce = secrets.token_hex(16)
        challenge = f"{CHALLENGE_PREFIX}:{self.address}:{path}:{ts}:{nonce}"
        return {
            "X-Wallet-Signature": self._cs.personal_sign(challenge),
            "X-Wallet-Timestamp": ts,
            "X-Wallet-Nonce": nonce,
        }

    def _request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_body: dict | None = None,
    ) -> t.Any:
        path = self._path(endpoint)
        headers = self._auth_headers(path)
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        try:
            response = requests.request(
                method,
                self.base_url + path,
                params=params,
                json=json_body,
                headers=headers,
                timeout=PROXY_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise RelayerProxyError(
                f"Relayer proxy {method} {endpoint} failed: {e}"
            ) from e
        except ValueError as e:
            raise RelayerProxyError(
                f"Relayer proxy {method} {endpoint} returned non-JSON: {e}"
            ) from e

    # -- operations --------------------------------------------------------------

    def deployed(self, address: str, wallet_type: str = "WALLET") -> bool:
        """Whether the relayer's registry has indexed a DW at ``address``."""
        data = self._request(
            "GET",
            "deployed",
            params={"address": to_checksum_address(address), "type": wallet_type},
        )
        return bool(data.get("deployed"))

    def deploy_dw(self) -> str:
        """Deploy a DepositWallet owned by the agent EOA; returns the tx id."""
        body = {"type": "WALLET-CREATE", "from": self.address, "to": DW_FACTORY}
        data = self._request("POST", "deploy_dw", json_body=body)
        tx_id = data.get("transactionID")
        if not tx_id:
            raise RelayerProxyError(f"deploy_dw returned no transaction id: {data}")
        return str(tx_id)

    def exec_wallet_batch(
        self,
        dw_address: str,
        nonce: int,
        calls: list,
        deadline: int | None = None,
    ) -> str:
        """Relay a DepositWallet ``execute(Batch, sig)`` of ``calls``.

        Builds the EIP-712 ``Batch`` envelope, owner-signs it through the
        connect signer, then POSTs it for the relayer to submit (the DW's
        ``execute`` is ``onlyFactory``). ``calls`` are ``{"target", "data"}``
        dicts, each implicitly value 0; ``nonce`` is the DW's current on-chain
        ``nonce()``.
        """
        dw_address = to_checksum_address(dw_address)
        if deadline is None:
            deadline = int(time.time()) + _BATCH_DEADLINE_SECONDS
        signature = self._sign_batch(dw_address, nonce, deadline, calls)
        body = {
            "from": self.address,
            "to": DW_FACTORY,
            "nonce": str(nonce),
            "signature": signature,
            "depositWalletParams": {
                "depositWallet": dw_address,
                "deadline": str(deadline),
                "calls": [
                    {
                        "target": to_checksum_address(c["target"]),
                        "value": "0",
                        "data": _as_0x(c["data"]),
                    }
                    for c in calls
                ],
            },
        }
        data = self._request("POST", "exec_wallet_batch", json_body=body)
        tx_id = data.get("transactionID")
        if not tx_id:
            raise RelayerProxyError(
                f"exec_wallet_batch returned no transaction id: {data}"
            )
        return str(tx_id)

    def _sign_batch(
        self, dw_address: str, nonce: int, deadline: int, calls: list
    ) -> str:
        """Owner-sign the EIP-712 DepositWallet ``Batch`` digest via connect."""
        domain_separator = keccak(
            abi_encode(
                ["bytes32", "bytes32", "bytes32", "uint256", "address"],
                [
                    _EIP712_DOMAIN_TYPEHASH,
                    _DW_DOMAIN_NAME_HASH,
                    _DW_DOMAIN_VERSION_HASH,
                    CHAIN_ID,
                    dw_address,
                ],
            )
        )
        call_hashes = b"".join(
            keccak(
                abi_encode(
                    ["bytes32", "address", "uint256", "bytes32"],
                    [
                        _CALL_TYPEHASH,
                        to_checksum_address(c["target"]),
                        _CALL_VALUE,
                        keccak(_to_bytes(c["data"])),
                    ],
                )
            )
            for c in calls
        )
        struct_hash = keccak(
            abi_encode(
                ["bytes32", "address", "uint256", "uint256", "bytes32"],
                [_BATCH_TYPEHASH, dw_address, nonce, deadline, keccak(call_hashes)],
            )
        )
        digest = keccak(b"\x19\x01" + domain_separator + struct_hash)
        return self._cs.sign_digest(digest)

    def transaction(self, tx_id: str) -> tuple:
        """State of a relayer-submitted tx: ``(state, tx_hash_or_None)``.

        ``GET /transaction`` returns a list of matching records; only the
        entry whose ``transactionID`` equals ``tx_id`` is selected (a wrong
        match could bind the wrong DW address / tx hash).
        """
        data = self._request("GET", "transaction", params={"id": tx_id})
        if isinstance(data, list):
            record = next((r for r in data if r.get("transactionID") == tx_id), {})
        else:
            record = data
        state = str(record.get("state") or "")
        tx_hash = record.get("transactionHash") or record.get("hash")
        return state, tx_hash

    def wait_terminal(self, tx_id: str) -> tuple:
        """Poll a relayer tx to a terminal state: ``(ok, state, tx_hash)``."""
        state, tx_hash = "", None
        for backoff in POLL_BACKOFFS:
            state, tx_hash = self.transaction(tx_id)
            if state in TX_TERMINAL_OK:
                return True, state, tx_hash
            if state in TX_TERMINAL_FAIL:
                return False, state, tx_hash
            time.sleep(backoff)
        return False, state or "TIMEOUT", tx_hash


def extract_dw_from_receipt(cs: ConnectSigner, tx_hash: str) -> str | None:
    """Parse a mined DW-deploy receipt for the new DepositWallet address.

    The factory's deploy event carries the DW address in ``topic1``; the DW
    is sourced from the matching factory log, not a relayer response field.
    """
    try:
        receipt = cs.w3.eth.get_transaction_receipt(tx_hash)
    except Exception:  # noqa: BLE001 - not yet indexed
        return None
    if receipt is None:
        return None
    for log in receipt["logs"]:
        topics = log["topics"]
        if str(log["address"]).lower() == DW_FACTORY.lower() and len(topics) >= 2:
            topic1 = topics[1]
            topic1_hex = topic1.hex() if hasattr(topic1, "hex") else str(topic1)
            topic1_hex = topic1_hex.removeprefix("0x")
            return to_checksum_address("0x" + topic1_hex[-40:])
    return None


def _to_bytes(data: t.Any) -> bytes:
    if isinstance(data, bytes):
        return data
    text = data[2:] if str(data).startswith("0x") else str(data)
    return bytes.fromhex(text)


def _as_0x(data: t.Any) -> str:
    if isinstance(data, bytes):
        return "0x" + data.hex()
    return data if str(data).startswith("0x") else "0x" + str(data)
