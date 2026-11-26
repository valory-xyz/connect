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
import typing as t
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from connect import staking, wallet, workspace
from connect.server.auth import require_local_origin
from connect.settings import validate_harness

logger = logging.getLogger("agent")

router = APIRouter()

FUNDS_STATUS_CACHE_SECONDS = 30
# how long a session launch waits on the staking reads for its reminder
REMINDER_READ_SECONDS = 5.0
# one worker for every launch: a read the launch gave up on keeps it, so a hung
# RPC leaves one thread behind, not one per launch, for shutdown to join
_REMINDER_READER = ThreadPoolExecutor(
    max_workers=1, thread_name_prefix="staking-reminder"
)


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
        value = wallet.funds_status(
            request.app.state.config,
            request.app.state.signer,
            request.app.state.topped_up,
        )
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


def _staking_reminder(state: t.Any) -> str | None:
    """Read the reminder within REMINDER_READ_SECONDS; past that, there is none.

    Its reads go to the chain's RPC, which can hang for its whole timeout per
    read, and the launch must not wait on them.
    """
    reading = _REMINDER_READER.submit(
        staking.staking_reminder, state.config, state.signer
    )
    try:
        return reading.result(timeout=REMINDER_READ_SECONDS)
    except FutureTimeout:
        # queued behind a hung read, it would run before the binary could exit
        reading.cancel()
        logger.warning(
            "staking reminder skipped: the staking state took over %ss to read",
            REMINDER_READ_SECONDS,
        )
        return None


def _write_session_notice(state: t.Any) -> None:
    """Leave the session its staking reminder, or clear an earlier one.

    A failure here never stops the launch: the session opens without it.
    """
    try:
        state.workspace.write_session_notice(_staking_reminder(state))
    except OSError:
        logger.exception("could not write the session notice")


@router.post("/session", dependencies=[Depends(require_local_origin)])
def start_session(request: Request, body: SessionRequest | None = None) -> dict:
    """Open an agent session in the configured harness, on demand.

    Pearl calls this once /healthcheck reports healthy; nothing is launched at
    boot, so a launch failure reaches the operator's UI instead of dying in
    this process's log.

    A deep link that will not open is the operator's environment, not a server
    fault, so it answers 200 with {launched: false, harness, requested, error}
    for the UI to show, with a `reason`: `install_failed` and `launch_failed`
    for OCB, `not_installed` for the rest. A bad request does not: 503 before
    the workspace is ready, 400 on an unknown harness or one this instance
    cannot use, 403 cross-origin.

    An explicit `harness` overrides the saved preference for this launch only:
    the session opens where the caller asked — and only there — without
    rewriting what the operator chose; PATCH /settings is how that preference
    changes. Naming none falls back instead (see Workspace.open_session), so
    the answer carries both harnesses: `requested` is the one asked for and
    `harness` the one that opened — equal unless a launch fell back, and equal
    again when nothing opened at all.
    """
    state = request.app.state
    if not state.workspace.ensure():
        raise HTTPException(
            status_code=503,
            detail=f"the agent server is not ready: {state.workspace.reason}",
        )
    override = body.harness if body else None
    try:
        requested = (
            validate_harness(override)
            if override is not None
            else state.settings_store.load().harness
        )
        state.settings_store.require_available(requested)
        _write_session_notice(state)
        # a harness the operator may choose but nobody can open is a bug, not a
        # server fault to 500 over: answer the caller the same way as any other
        # unusable harness (test_every_choosable_harness_can_be_opened pins
        # every launcher table against HARNESSES)
        harness = state.workspace.open_session(requested, fallback=override is None)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except workspace.LaunchError as e:
        logger.warning("session launch failed: %s", e)
        # the reason, not just the harness: log.txt rotates, and "not
        # installed" and "no handler for the deep link" need different answers
        state.activity.record(
            "session_launch_failed",
            harness=requested,
            requested=requested,
            reason=e.reason,
            error=str(e),
        )
        # the same harness under both names: nothing opened, and a caller
        # should not have to branch on `launched` to know which fields exist
        return {
            "launched": False,
            "harness": requested,
            "requested": requested,
            "reason": e.reason,
            "error": str(e),
        }
    # both: a trail naming only the harness that opened cannot show the
    # preference the operator has silently stopped getting
    state.activity.record("session_launched", harness=harness, requested=requested)
    return {"launched": True, "harness": harness, "requested": requested}
