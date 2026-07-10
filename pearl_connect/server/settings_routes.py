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

Reads are open (the whitelist is not a secret). Writes go through one PATCH
speaking the canonical shape: changes to the `protected` object (mode,
whitelist) are authenticated with the keystore password — NOT the bearer
token: the agent session holds the token and must not be able to lift its own
restrictions, while only the human operator knows the password. The password
is verified by re-decrypting the keystore the server booted from. The
`harness` preference is not protected and needs no password.
"""

import logging
import time

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from pearl_connect.keystore import KeystoreError, load_account

logger = logging.getLogger("agent")

router = APIRouter()

WRONG_PASSWORD_DELAY_SECONDS = 1.0


class ProtectedPatch(BaseModel):
    """Partial update of the integrity-checked settings."""

    model_config = ConfigDict(extra="forbid")

    mode: str | None = None
    whitelist: dict[str, list[str]] | None = None  # replaced wholesale if given


class SettingsPatch(BaseModel):
    """JSON merge-patch over the canonical settings shape."""

    model_config = ConfigDict(extra="forbid")

    password: str | None = None  # required iff `protected` is present
    protected: ProtectedPatch | None = None
    harness: str | None = None


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


@router.patch("/settings")
def patch_settings(body: SettingsPatch, request: Request) -> dict:
    """Merge-patch the settings; the password gates the `protected` object.

    Omitted fields keep their current value. Changing `protected`
    (mode/whitelist) proves knowledge of the keystore password first; the
    `harness` preference needs no password — it is not integrity-protected
    and the worst a change can do is open the workspace in the other Claude
    Code. Origin locality applies to everything via the router dependency.
    """
    state = request.app.state
    if body.protected is None and body.harness is None:
        raise HTTPException(status_code=400, detail="nothing to update")

    if body.protected is not None:
        if state.auth_limiter.blocked():
            raise HTTPException(
                status_code=429,
                detail="too many failed authentication attempts; retry later",
            )
        if body.password is None:
            # no guess was made: audit the attempt, but don't burn a decrypt,
            # a delay or a brake count on it
            state.activity.record(
                "auth_failed", path="/settings", reason="missing password"
            )
            raise HTTPException(
                status_code=401,
                detail="the keystore password is required for protected settings",
            )
        try:
            account = load_account(body.password)
        except KeystoreError as e:
            raise _reject_password(request) from e
        if account.address != state.signer.address:
            # a different keystore at the path than the one we booted from
            raise _reject_password(request)

    try:
        # the store's patch holds one lock across read-merge-write, so two
        # concurrent PATCHes (the UI's two forms) cannot lose an update
        settings = state.settings_store.patch(
            body.model_dump(exclude={"password"}, exclude_none=True)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except OSError as e:
        raise HTTPException(
            status_code=503, detail="settings could not be persisted"
        ) from e
    if body.protected is not None:
        if body.protected.whitelist is not None:
            unknown = sorted(
                set(settings.protected.whitelist) - set(state.config.chains)
            )
            if unknown:
                logger.warning(
                    "whitelist chains not configured: %s", ", ".join(unknown)
                )
        state.activity.record("settings_changed", mode=settings.protected.mode)
        logger.info("settings updated: mode=%s", settings.protected.mode)
    if body.harness is not None:
        state.activity.record("harness_changed", harness=settings.harness)
        logger.info("harness updated: %s", settings.harness)
    return settings.to_dict()
