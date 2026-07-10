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

"""Bearer-authed signing surface for skill scripts: /sign-and-send, /sign-message, /wallet."""

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from pearl_connect import wallet
from pearl_connect.signer import SignerError

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


@router.post("/sign-and-send")
def sign_and_send(body: SignAndSendRequest, request: Request) -> dict:
    """Sign and send."""
    try:
        tx_hash = request.app.state.signer.send(
            chain=body.chain,
            to=body.to,
            value=body.value,
            data=body.data,
            request_id=body.request_id,
            gas=body.gas,
        )
    except (SignerError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"tx_hash": tx_hash}


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
