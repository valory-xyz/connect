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

"""FastAPI application factory."""

import asyncio
import contextlib
import logging
import mimetypes
import threading
import typing as t
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response
from hexbytes import HexBytes
from starlette.middleware.trustedhost import TrustedHostMiddleware

from connect import wallet
from connect.activity import ActivityLog, PERFORMANCE_FILE
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech import MechService
from connect.server import pearl_routes, settings_routes, signer_routes
from connect.server.auth import (
    ALLOWED_HOSTS,
    AuthFailureLimiter,
    AuthMiddleware,
    RequireAuth,
    require_local_origin,
)
from connect.server.mcp_tools import (
    MAX_RECEIPT_TIMEOUT,
    RECEIPT_POLL_SECONDS,
    build_mcp,
)
from connect.settings import MODE_RESTRICTED, SettingsStore
from connect.signer import Signer
from connect.workspace import UI_INDEX, Workspace, load_ui_bundle

logger = logging.getLogger("agent")

# how often agent_performance.json is rewritten with nothing else happening:
# it bounds both how stale the activity goal Pearl sees can be and how long a
# session's edit of activity_goal.target waits to take effect
PERFORMANCE_REFRESH_SECONDS = 15.0

# how often the agent EOA's native balance is checked against its funding
# requirement
AGENT_TOPUP_INTERVAL_SECONDS = 3600.0


async def refresh_performance(activity: ActivityLog) -> None:
    """Rewrite agent_performance.json periodically, until cancelled."""
    while True:
        await asyncio.sleep(PERFORMANCE_REFRESH_SECONDS)
        try:
            await asyncio.to_thread(activity.write_performance)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("could not refresh %s", PERFORMANCE_FILE)


def _send_agent_topup(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    chain: str, amount: int, signer: Signer, guard: Guard, activity: ActivityLog
) -> bool:
    """Send one top-up and wait for it to be mined; audit it either way."""
    tx_hash: str | None = None
    try:
        # armed only while restricted: one armed in unrestricted mode would
        # outlive a switch back to restricted for its TTL
        if guard.mode() == MODE_RESTRICTED:
            guard.allow_agent_topup_once(chain=chain, amount_cap=amount)
        # audited below under its own kind, so Pearl's transactions metric and
        # last_activity show only what the agent did
        tx_hash = signer.send_via_safe(
            chain, signer.address, value=amount, data="0x", audit=False
        )
        receipt = signer.w3(chain).eth.wait_for_transaction_receipt(
            HexBytes(tx_hash),
            timeout=MAX_RECEIPT_TIMEOUT,
            poll_latency=RECEIPT_POLL_SECONDS,
        )
        if receipt["status"] != 1:
            raise RuntimeError("the transaction reverted")
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.exception("agent top-up of %d wei on %s failed", amount, chain)
        activity.record(
            "agent_topup_failed",
            chain=chain,
            value=str(amount),
            tx_hash=tx_hash,
            error=str(e),
        )
        return False
    activity.record("agent_topup", chain=chain, value=str(amount), tx_hash=tx_hash)
    return True


def top_up_agent_signer(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    config: AppConfig,
    signer: Signer,
    guard: Guard,
    activity: ActivityLog,
    topped_up: set[str],
) -> None:
    """Move native token from the safe to the agent EOA where the rule says so.

    `topped_up` keeps the chains whose last top-up succeeded, for /funds-status.
    """
    for chain, topup in wallet.agent_topup(config, signer).items():
        if topup.need == 0:
            continue
        if topup.move == 0:
            logger.info("agent top-up on %s: the safe holds no native token", chain)
            continue
        if _send_agent_topup(chain, topup.move, signer, guard, activity):
            topped_up.add(chain)
        else:
            topped_up.discard(chain)


async def top_up_agent(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    config: AppConfig,
    signer: Signer,
    guard: Guard,
    activity: ActivityLog,
    topped_up: set[str],
) -> None:
    """Top up the agent EOA at start, then every interval, until cancelled."""
    while True:
        try:
            await asyncio.to_thread(
                top_up_agent_signer, config, signer, guard, activity, topped_up
            )
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception("agent top-up check failed")
        await asyncio.sleep(AGENT_TOPUP_INTERVAL_SECONDS)


def create_app(  # pylint: disable=too-many-arguments
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    token: str,
    guard: Guard,
    settings_store: SettingsStore,
    mech: MechService,
    workspace: Workspace,
) -> FastAPI:
    """Create app."""
    mcp = build_mcp(
        signer,
        config,
        activity,
        guard=guard,
        mech=mech,
        settings_store=settings_store,
    )

    @asynccontextmanager
    async def lifespan(running: FastAPI) -> t.AsyncIterator[None]:
        tasks = (
            asyncio.create_task(refresh_performance(activity)),
            asyncio.create_task(
                top_up_agent(config, signer, guard, activity, running.state.topped_up)
            ),
        )
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            for task in tasks:
                task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="connect", lifespan=lifespan)
    # DNS-rebinding defense: a rebound hostname reaches the socket with the
    # attacker's Host header — refuse anything that isn't a loopback name
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
    limiter = AuthFailureLimiter()
    app.state.signer = signer
    app.state.config = config
    app.state.activity = activity
    app.state.guard = guard
    app.state.settings_store = settings_store
    app.state.mech = mech
    app.state.auth_limiter = limiter
    app.state.workspace = workspace
    # stale from the start: the monotonic clock can begin near 0 after a boot
    app.state.funds_cache = {
        "at": float("-inf"),
        "value": {},
        "lock": threading.Lock(),
    }
    # chains whose last agent top-up succeeded, for /funds-status
    app.state.topped_up = set()

    app.include_router(pearl_routes.router)
    app.include_router(
        settings_routes.router, dependencies=[Depends(require_local_origin)]
    )
    app.include_router(
        signer_routes.router,
        dependencies=[Depends(RequireAuth(token, activity, limiter))],
    )
    app.mount(
        "/mcp",
        AuthMiddleware(mcp.streamable_http_app(), token, activity, limiter),
    )

    # the agent UI last, so it can own / without shadowing an endpoint: routes
    # match in registration order, and this catch-all would swallow anything
    # registered below it. A bundle with no UI at all still serves the API
    # (see load_ui_bundle).
    ui = load_ui_bundle()
    if ui is not None:
        logger.info("serving the agent UI: %d file(s), read at boot", len(ui))
        # decided at boot, with the bytes: the module-level mimetypes.guess_type
        # answers from HKEY_CLASSES_ROOT on Windows, so the type served for .js
        # would be whatever the operator's machine says — and a box mapping it
        # to text/plain has the browser refuse to execute the script. An
        # instance is built from mimetypes' own table and reads no registry.
        types = mimetypes.MimeTypes()

        @app.get("/{asset_path:path}", include_in_schema=False)
        def agent_ui(asset_path: str) -> Response:
            """Serve the UI snapshot taken at boot.

            Every file in the build is published as-is: the drop-in directory
            is the contract, so a build that ships a sourcemap ships it here
            too (see docs/agent-ui.md).
            """
            name = asset_path or UI_INDEX
            body = ui.get(name)
            if body is None:
                raise HTTPException(status_code=404, detail="not found")
            media_type, _ = types.guess_type(name)
            return Response(body, media_type=media_type or "application/octet-stream")

    return app
