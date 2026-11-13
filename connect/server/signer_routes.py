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
from pydantic import Field, field_validator

from connect import settings as settings_config
from connect import wallet
from connect.server.auth import (
    GrantRefused,
    TokenGrant,
    authorize_route,
    refused_route,
    request_token,
)
from connect.server.receipts import settled
from connect.server.strict import StrictBody
from connect.signer import SignerError

logger = logging.getLogger("agent")

router = APIRouter()


class _SendBody(StrictBody):
    """Fields both signing routes share; unknown ones are refused by name."""

    chain: str
    value: int = Field(default=0, ge=0)
    data: str = "0x"
    request_id: str | None = None
    gas: int | None = Field(default=None, ge=0)
    # what the call may do; required when it moves value
    intent: dict | None = None
    # as the MCP send tools take them: wait up to `timeout` s for the receipt
    wait_for_receipt: bool = False
    timeout: int = Field(default=60, ge=0)

    @field_validator("value", "gas", mode="before")
    @classmethod
    def _coerce_int(cls, v: object) -> object:
        # web3 clients serialize numbers as hex or decimal strings
        if isinstance(v, str):
            return int(v, 16) if v.startswith("0x") else int(v)
        return v


class SignAndSendRequest(_SendBody):
    """A transaction the agent EOA sends: `to` is its recipient."""

    to: str


class SafeTransactionRequest(_SendBody):
    """A call the service safe makes: `target` is what the safe calls.

    The same name as the safe_transaction MCP tool's, so the two surfaces
    cannot be confused for one another.
    """

    target: str


class SignMessageRequest(StrictBody):
    """SignMessageRequest."""

    digest: str = Field(description="0x-hex 32-byte digest, signed unprefixed")


def _dispatch(  # pylint: disable=too-many-arguments
    request: Request,
    method: t.Callable[..., str],
    body: _SendBody,
    address: str,
    *,
    replay_only: bool,
) -> dict:
    """Run one signer method and map its input errors to a 400.

    The address is passed positionally: `send` reads it as the EOA's outer
    recipient, `send_via_safe` as the safe's call target — the one field whose
    meaning the two endpoints deliberately keep distinct. A value-capped
    token's intent is `intent.Capped`: no position may leave under it.
    `replay_only` is set for a retry whose draw was spared (`_authorize`).
    """
    intent = request.app.state.grants.intent_for(request_token(request), body.intent)
    try:
        tx_hash = method(
            body.chain,
            address,
            value=body.value,
            data=body.data,
            request_id=body.request_id,
            gas=body.gas,
            intent=intent,
            replay_only=replay_only,
        )
    except (SignerError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return settled(
        request.app.state.signer,
        body.chain,
        tx_hash,
        body.wait_for_receipt,
        body.timeout,
    )


def _authorize(request: Request, action: str, body: _SendBody | None = None) -> bool:
    """Hold this request's token to its grant; return whether it is a spared retry."""
    arguments = {} if body is None else body.model_dump()
    return authorize_route(request, request.app.state.activity, action, arguments)


@router.post("/sign-and-send")
def sign_and_send(body: SignAndSendRequest, request: Request) -> dict:
    """Sign and send one transaction from the agent EOA."""
    replay_only = _authorize(request, "send_transaction", body)
    return _dispatch(
        request, request.app.state.signer.send, body, body.to, replay_only=replay_only
    )


@router.post("/safe-transaction")
def safe_transaction(body: SafeTransactionRequest, request: Request) -> dict:
    """Have the service safe make one call; the server composes the safe's tx.

    `target`, `value` and `data` are the call the *safe* makes, and the value
    leaves the safe.
    """
    replay_only = _authorize(request, "safe_transaction", body)
    return _dispatch(
        request,
        request.app.state.signer.send_via_safe,
        body,
        body.target,
        replay_only=replay_only,
    )


@router.post("/sign-message")
def sign_message(body: SignMessageRequest, request: Request) -> dict:
    """Sign message."""
    _authorize(request, "sign_message")
    try:
        digest = bytes.fromhex(body.digest.removeprefix("0x"))
        signature = request.app.state.signer.sign_digest(digest)
    except (SignerError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"signature": signature}


@router.get("/wallet")
def wallet_info(request: Request) -> dict:
    """Wallet info."""
    _authorize(request, "wallet_info")
    overview = wallet.wallet_overview(
        request.app.state.config, request.app.state.signer
    )
    if settings_config.EXPOSE_MODE_TO_AGENT:
        overview["mode"] = request.app.state.guard.mode()
    return overview


@router.post("/tokens")
def mint_token(grant: TokenGrant, request: Request) -> dict:
    """Mint a token no wider than the one presented, for a harness's scripts.

    A wider grant is refused (rule "token-scope"): a token can narrow its own
    powers, never extend them.
    """
    try:
        token = request.app.state.grants.mint(request_token(request), grant)
    except GrantRefused as e:
        raise refused_route(request, request.app.state.activity, e) from e
    request.app.state.activity.record("token_minted", scopes=grant.scopes)
    return {"token": token, "grant": grant.model_dump()}
