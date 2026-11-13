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
`harness` preference is not protected and needs no password. The mech queue's
hard cancel pays for one on-chain request, so it takes the password the same
way, and its status is read by the operator's UI.
"""

import logging
import time

from fastapi import APIRouter, HTTPException, Request
from mech_client import MechPriceExceeded, NonceRefused
from pydantic import BaseModel, ConfigDict, field_validator

from connect.keystore import KeystoreError, load_account
from connect.mech_types import MechError
from connect.server.strict import StrictBody
from connect.settings import SettingsPersistError

logger = logging.getLogger("agent")

router = APIRouter()

WRONG_PASSWORD_DELAY_SECONDS = 1.0
WHITELIST_FROZEN = "whitelist editing via the API is not supported yet"


class ProtectedPatch(BaseModel):
    """Partial update of the integrity-checked settings."""

    model_config = ConfigDict(extra="forbid")

    mode: str | None = None
    whitelist: dict[str, list[str]] | None = None

    @field_validator("whitelist")
    @classmethod
    def _whitelist_is_frozen(cls, value: object) -> object:
        """Refuse whitelist writes: the semantics are not specced yet.

        A patch replaces the whitelist wholesale, so a single-chain edit would
        silently drop the other chains — including their default marketplace
        entries — and the only validation available here is the address format:
        no chain check, no proof the address is even a contract. Until that is
        designed, an attempt is a loud 422 rather than a quiet misfire. The
        field stays declared (rather than left to extra="forbid") so a caller
        gets that answer instead of "extra inputs are not permitted"; the store
        still accepts whitelists internally, from defaults().
        """
        if value is not None:
            raise ValueError(WHITELIST_FROZEN)
        return value  # an explicit null is the merge-patch "keep", not an edit


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
    state.activity.record("auth_failed", path=request.url.path, reason="bad password")
    state.auth_limiter.record_failure()
    time.sleep(WRONG_PASSWORD_DELAY_SECONDS)  # throttle guessing
    return HTTPException(status_code=401, detail="invalid password")


def require_password(request: Request, password: str | None, purpose: str) -> None:
    """Prove the operator knows the keystore password, or raise.

    The one check every operator-only write makes: the rate limit first, a
    missing password audited without a guess counted, then the keystore the
    server booted from re-decrypted. A bearer token proves nothing here: the
    agent session holds one.
    """
    state = request.app.state
    if state.auth_limiter.blocked():
        raise HTTPException(
            status_code=429,
            detail="too many failed authentication attempts; retry later",
        )
    if not password:
        # no guess was made — an omitted password, or the empty string a
        # blank form field submits: audit the attempt, but don't burn a
        # decrypt, a delay or a brake count on it. Counting these would let
        # anyone 429-lock every authenticated surface for free.
        state.activity.record(
            "auth_failed", path=request.url.path, reason="missing password"
        )
        raise HTTPException(
            status_code=401,
            detail=f"the keystore password is required for {purpose}",
        )
    try:
        account = load_account(password)
    except KeystoreError as e:
        raise _reject_password(request) from e
    if account.address != state.signer.address:
        # a different keystore at the path than the one we booted from
        raise _reject_password(request)


@router.patch("/settings")
def patch_settings(body: SettingsPatch, request: Request) -> dict:
    """Merge-patch the settings; the password gates the `protected` object.

    Omitted fields keep their current value. Changing `protected`
    (mode/whitelist) proves knowledge of the keystore password first; the
    `harness` preference needs no password — it is not integrity-protected
    and the worst a change can do is open the workspace in another harness.
    Origin locality applies to everything via the router dependency.
    """
    state = request.app.state
    if body.protected is None and body.harness is None:
        raise HTTPException(status_code=400, detail="nothing to update")

    if body.protected is not None:
        require_password(request, body.password, "protected settings")

    try:
        # the store's patch holds one lock across read-merge-write, so two
        # concurrent PATCHes (the UI's two forms) cannot lose an update. The
        # None-means-keep rule lives there alone: dumping the body as-is keeps
        # HTTP callers and direct store callers on one merge semantics.
        previous, settings = state.settings_store.patch(
            body.model_dump(exclude={"password"})
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except SettingsPersistError as e:
        raise HTTPException(
            status_code=503, detail="settings could not be persisted"
        ) from e
    # audit what moved, not what was submitted: a patch restating the stored
    # values is a no-op, and an audit trail claiming guardrail changes that
    # never happened is worse than no entry at all
    if settings.protected != previous.protected:
        state.activity.record("settings_changed", mode=settings.protected.mode)
        logger.info("settings updated: mode=%s", settings.protected.mode)
    if settings.harness != previous.harness:
        state.activity.record("harness_changed", harness=settings.harness)
        logger.info("harness updated: %s", settings.harness)
    return settings.to_dict()


class HardCancelRequest(StrictBody):
    """The operator's confirmation of one hard cancel on a chain."""

    chain: str
    password: str | None = None


@router.get("/mech-queue")
def mech_queue(request: Request) -> dict:
    """Report each safe's mech queue per chain: stalled, since when, cancellable."""
    return request.app.state.mech.queue_status()


@router.post("/mech-queue/hard-cancel")
def hard_cancel(body: HardCancelRequest, request: Request) -> dict:
    """Consume a long-stalled queue's stuck nonce with one on-chain request (D27).

    Operator-only: the password, never a bearer token, authorizes it, since
    it pays a mech from the safe. Refused (409, the allocator's rule) unless
    the queue has been stalled for MECH_HARD_CANCEL_AFTER.
    """
    require_password(request, body.password, "a hard cancel")
    state = request.app.state
    try:
        state.config.chain(body.chain)
    except ValueError as e:  # Connect's own words: an unknown chain
        raise HTTPException(status_code=400, detail=str(e)) from e
    try:
        return state.mech.hard_cancel(body.chain)
    except NonceRefused as e:
        state.activity.record(
            "refusal", rule=e.rule, path=request.url.path, reason=str(e)
        )
        raise HTTPException(status_code=409, detail=f"rule '{e.rule}': {e}") from e
    except (MechError, MechPriceExceeded) as e:  # Connect's and the cap's words
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:  # a library's or an RPC's: its text stays in the log
        logger.exception("the hard cancel on %s failed", body.chain)
        state.activity.record("mech_hard_cancel_failed", chain=body.chain)
        raise HTTPException(
            status_code=502,
            detail="the hard cancel's on-chain request failed (the cause is in "
            "Connect's log); check the safe before trying again",
        ) from e
