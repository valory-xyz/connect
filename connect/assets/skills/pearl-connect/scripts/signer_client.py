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

"""web3.py client for the connect signer.

Routes eth_sendTransaction through the local signing service (which fills
nonce/gas, signs with the agent EOA and broadcasts); every other RPC method
goes straight to the chain RPC. No key material in this process.

Usage:
    from signer_client import connect
    w3, signer = connect("gnosis")
    tx_hash = w3.eth.send_transaction({"to": "0x...", "value": 0, "data": "0x"})
"""

import http.client
import json
import typing as t
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from web3 import HTTPProvider, Web3

MCP_SERVER_NAME = "connect"
SEND_ATTEMPTS = 3


class SignerRequestError(RuntimeError):
    """An HTTP error from the signer, carrying its `detail` message.

    The server explains rejections (guardrail rules, unknown chains, bad
    addresses) in the response body — losing that detail would leave only
    an opaque "HTTP Error 400".
    """


def _raise_with_detail(e: urllib.error.HTTPError) -> t.NoReturn:
    try:
        body = json.loads(e.read())
        detail = body.get("detail") or body.get("error")
    except Exception:  # pylint: disable=broad-exception-caught
        detail = None
    raise SignerRequestError(f"signer returned HTTP {e.code}: {detail or e.reason}")


def _to_int(value: object) -> int:
    """Parse ints that web3 formatters may have hex-encoded ("0x..") or str-ified."""
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return int(value)  # type: ignore[call-overload]


class SignerClient:
    """SignerClient."""

    def __init__(self, base_url: str, token: str, chain: str) -> None:
        """Initialize."""
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.chain = chain

    def _post(self, path: str, payload: dict) -> dict:
        request = urllib.request.Request(
            url=f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._token}",
            },
            method="POST",
        )
        # nosec B310: base_url comes from the local .mcp.json (http://127.0.0.1)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:  # nosec B310
                return json.loads(response.read())
        except urllib.error.HTTPError as e:
            _raise_with_detail(e)

    def send_transaction(self, tx: dict, request_id: str | None = None) -> str:
        """Send transaction; client-side timeouts retry with the same request_id.

        The signer may have broadcast before a timeout hit: replaying the same
        request_id returns the original tx_hash instead of double-spending. If
        all attempts fail, the raised error names the request_id so a manual
        retry can stay idempotent too.
        """
        request_id = request_id or str(uuid.uuid4())
        payload = {
            "chain": self.chain,
            "to": tx["to"],
            "value": _to_int(tx.get("value", 0)),
            "data": tx.get("data", "0x"),
            "request_id": request_id,
        }
        if tx.get("gas"):
            payload["gas"] = _to_int(tx["gas"])
        last_error: Exception | None = None
        for _ in range(SEND_ATTEMPTS):
            try:
                return self._post("/sign-and-send", payload)["tx_hash"]
            # OSError covers timeouts, URLError and connection resets;
            # HTTPException covers RemoteDisconnected on the response path
            # (urllib does not wrap those). HTTP-status errors become
            # SignerRequestError in _post and are NOT retried.
            except (OSError, http.client.HTTPException) as e:
                last_error = e
        raise SignerRequestError(
            f"send not confirmed after {SEND_ATTEMPTS} attempts ({last_error}); "
            f"retry with request_id='{request_id}' to avoid double-spending"
        ) from last_error

    def sign_digest(self, digest: str) -> str:
        """Sign a raw 32-byte digest (0x-hex), unprefixed."""
        return self._post("/sign-message", {"digest": digest})["signature"]

    def wallet_info(self) -> dict:
        """Wallet info."""
        request = urllib.request.Request(
            url=f"{self.base_url}/wallet",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # nosec B310
                return json.loads(response.read())
        except urllib.error.HTTPError as e:
            _raise_with_detail(e)


class SignerProvider(HTTPProvider):
    """HTTPProvider that diverts eth_sendTransaction to the signer service."""

    def __init__(self, rpc_url: str, signer: SignerClient) -> None:
        """Initialize."""
        super().__init__(rpc_url, request_kwargs={"timeout": 60})
        self._signer = signer

    def make_request(self, method: t.Any, params: t.Any) -> t.Any:
        """Make request."""
        if method == "eth_sendTransaction":
            tx_hash = self._signer.send_transaction(dict(params[0]))
            return {"jsonrpc": "2.0", "id": 1, "result": tx_hash}
        return super().make_request(method, params)


def load_mcp_config(start: Path | None = None) -> tuple[str, str]:
    """Find .mcp.json (cwd upwards) and return (server_base_url, token)."""
    directory = (start or Path.cwd()).resolve()
    for candidate in (directory, *directory.parents):
        path = candidate / ".mcp.json"
        if path.exists():
            entry = json.loads(path.read_text(encoding="utf-8"))["mcpServers"][
                MCP_SERVER_NAME
            ]
            base_url = entry["url"].removesuffix("/mcp")
            token = entry["headers"]["Authorization"].removeprefix("Bearer ")
            return base_url, token
    raise FileNotFoundError(".mcp.json not found in cwd or parents")


def connect(chain: str) -> tuple[Web3, SignerClient]:
    """Web3 instance whose sends go through the signer, plus the raw client."""
    base_url, token = load_mcp_config()
    signer = SignerClient(base_url, token, chain)
    rpc_url = signer.wallet_info()["rpcs"][chain]
    w3 = Web3(provider=SignerProvider(rpc_url, signer))
    return w3, signer
