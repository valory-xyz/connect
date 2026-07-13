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

"""Pearl SDK endpoints: /healthcheck, /funds-status and /session.

The pollers' endpoints are unauthenticated: the middleware has no token. They
must never expose the session token.
"""

import logging
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from pearl_connect import wallet, workspace
from pearl_connect.server.auth import require_local_origin
from pearl_connect.settings import validate_harness

logger = logging.getLogger("agent")

router = APIRouter()

FUNDS_STATUS_CACHE_SECONDS = 30


@router.get("/healthcheck")
def healthcheck(request: Request) -> dict:
    """Healthcheck.

    The middleware's HealthChecker reads only is_healthy. Asking the workspace
    is also what re-attempts a failed population: Pearl calls POST /session
    only once we report healthy, so a server that can never become healthy
    would never be asked to heal — the retry has to sit on the poller's path.
    """
    return {"is_healthy": request.app.state.workspace.ensure()}


@router.get("/funds-status")
def funds_status(request: Request) -> dict:
    """Funds status."""
    cache = request.app.state.funds_cache  # per-app, created by create_app
    now = time.monotonic()
    with cache["lock"]:
        if now - cache["at"] < FUNDS_STATUS_CACHE_SECONDS:
            return cache["value"]
    try:
        value = wallet.funds_status(request.app.state.config, request.app.state.signer)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("funds-status computation failed")
        return {}
    with cache["lock"]:
        cache["at"] = now
        cache["value"] = value
    return value


class SessionRequest(BaseModel):
    """Optional overrides for a single session launch."""

    model_config = ConfigDict(extra="forbid")

    # open in this harness instead of the saved preference, just this once
    harness: str | None = None


@router.post("/session", dependencies=[Depends(require_local_origin)])
def start_session(request: Request, body: SessionRequest | None = None) -> dict:
    """Open a Claude Code session in the configured harness, on demand.

    Pearl calls this once /healthcheck reports healthy; nothing is launched at
    boot, so a launch failure reaches the operator's UI instead of dying in
    this process's log.

    A deep link that will not open is the operator's environment, not a server
    fault, so it answers 200 with {launched: false, harness, error} for the UI
    to show — where a bad request does not: 503 before the workspace is ready,
    400 on an unknown harness, 403 cross-origin.

    An explicit `harness` overrides the saved preference for this launch only:
    the session opens where the caller asked without rewriting what the
    operator chose — PATCH /settings is how that preference changes.
    """
    state = request.app.state
    if not state.workspace.ensure():
        raise HTTPException(
            status_code=503,
            detail=f"the agent server is not ready: {state.workspace.reason}",
        )
    override = body.harness if body else None
    try:
        harness = (
            validate_harness(override)
            if override is not None
            else state.settings_store.load().harness
        )
        # a harness the operator may choose but nobody can open is a bug, not a
        # server fault to 500 over: answer the caller the same way as any other
        # unusable harness (a test pins DEEP_LINKS against HARNESSES so this
        # cannot go unnoticed)
        state.workspace.open_session(harness)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except workspace.LaunchError as e:
        logger.warning("session launch failed: %s", e)
        # the reason, not just the harness: log.txt rotates, and "not
        # installed" and "no handler for the deep link" need different answers
        state.activity.record("session_launch_failed", harness=harness, error=str(e))
        return {"launched": False, "harness": harness, "error": str(e)}
    state.activity.record("session_launched", harness=harness)
    return {"launched": True, "harness": harness}
