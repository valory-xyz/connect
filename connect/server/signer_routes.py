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

"""Bearer-authed signing surface for skill scripts.

Routes: /safe-transaction (act as the service safe), /sign-and-send (act as the
EOA), /sign-message, /wallet.
"""

import logging
import typing as t

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from connect import wallet
from connect.signer import SignerError

logger = logging.getLogger("agent")

router = APIRouter()


class SignAndSendRequest(BaseModel):
    """SignAndSendRequest."""

    chain: str
    to: str
    value: int = Field(default=0, ge=0)
    data: str = "0x"
    request_id: str | None = None
    gas: int | None = Field(default=None, ge=0)

    @field_validator("value", "gas", mode="before")
    @classmethod
    def _coerce_int(cls, v: object) -> object:
        # web3 clients serialize numbers as hex or decimal strings
        if isinstance(v, str):
            return int(v, 16) if v.startswith("0x") else int(v)
        return v


class SignMessageRequest(BaseModel):
    """SignMessageRequest."""

    digest: str = Field(description="0x-hex 32-byte digest, signed unprefixed")


def _dispatch(method: t.Callable[..., str], body: SignAndSendRequest) -> dict:
    """Run one signer method and map its input errors to a 400.

    The address is passed positionally: `send` reads it as the EOA's outer
    recipient, `send_via_safe` as the safe's call target — the one field whose
    meaning the two endpoints deliberately keep distinct.
    """
    try:
        tx_hash = method(
            body.chain,
            body.to,
            value=body.value,
            data=body.data,
            request_id=body.request_id,
            gas=body.gas,
        )
    except (SignerError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"tx_hash": tx_hash}


@router.post("/sign-and-send")
def sign_and_send(body: SignAndSendRequest, request: Request) -> dict:
    """Sign and send one transaction from the agent EOA."""
    return _dispatch(request.app.state.signer.send, body)


@router.post("/safe-transaction")
def safe_transaction(body: SignAndSendRequest, request: Request) -> dict:
    """Have the service safe make one call; the server composes the safe's tx.

    The same body as /sign-and-send, read one level in: `to`, `value` and `data`
    are the call the *safe* makes, and the value leaves the safe.
    """
    return _dispatch(request.app.state.signer.send_via_safe, body)


@router.post("/sign-message")
def sign_message(body: SignMessageRequest, request: Request) -> dict:
    """Sign message."""
    try:
        digest = bytes.fromhex(body.digest.removeprefix("0x"))
        signature = request.app.state.signer.sign_digest(digest)
    except (SignerError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"signature": signature}


@router.get("/wallet")
def wallet_info(request: Request) -> dict:
    """Wallet info."""
    overview = wallet.wallet_overview(
        request.app.state.config, request.app.state.signer
    )
    overview["mode"] = request.app.state.guard.mode()
    return overview
