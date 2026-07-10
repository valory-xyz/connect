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

"""Operator-facing Settings endpoints.

Reads are open (the whitelist is not a secret). Writes are authenticated with
the keystore password — NOT the bearer token: the agent session holds the
token and must not be able to lift its own restrictions, while only the human
operator knows the password. The password is verified by re-decrypting the
keystore the server booted from.
"""

import logging
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from pearl_connect.keystore import KeystoreError, load_account
from pearl_connect.settings import DEFAULT_HARNESS, Settings

logger = logging.getLogger("agent")

router = APIRouter()

WRONG_PASSWORD_DELAY_SECONDS = 1.0


class SettingsUpdate(BaseModel):
    """SettingsUpdate."""

    password: str
    mode: str
    whitelist: dict[str, list[str]] = {}
    harness: str = DEFAULT_HARNESS


@router.get("/settings")
def get_settings(request: Request) -> dict:
    """Return the enforced settings (post-verification)."""
    return request.app.state.settings_store.load().to_dict()


def _reject_password(request: Request) -> HTTPException:
    """Audit + brake a failed password attempt, returning the 401 to raise."""
    state = request.app.state
    state.activity.record("auth_failed", path="/settings", reason="bad password")
    state.auth_limiter.record_failure()
    time.sleep(WRONG_PASSWORD_DELAY_SECONDS)  # throttle guessing
    return HTTPException(status_code=401, detail="invalid password")


@router.post("/settings")
def update_settings(body: SettingsUpdate, request: Request) -> dict:
    """Update mode/whitelist after proving knowledge of the keystore password."""
    state = request.app.state
    if state.auth_limiter.blocked():
        raise HTTPException(
            status_code=429,
            detail="too many failed authentication attempts; retry later",
        )
    try:
        account = load_account(body.password)
    except KeystoreError as e:
        raise _reject_password(request) from e
    if account.address != state.signer.address:
        # a different keystore at the path than the one we booted from
        raise _reject_password(request)

    try:
        settings = Settings.from_raw(body.mode, body.whitelist, body.harness)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    unknown = sorted(set(settings.whitelist) - set(state.config.chains))
    if unknown:
        logger.warning("whitelist chains not configured: %s", ", ".join(unknown))
    state.settings_store.save(settings)
    state.activity.record("settings_changed", mode=settings.mode)
    logger.info("settings updated: mode=%s", settings.mode)
    return settings.to_dict()
