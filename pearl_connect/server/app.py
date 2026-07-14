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

import logging
import mimetypes
import threading
import typing as t
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig
from pearl_connect.guard import Guard
from pearl_connect.mech import MechService
from pearl_connect.server import pearl_routes, settings_routes, signer_routes
from pearl_connect.server.auth import (
    ALLOWED_HOSTS,
    AuthFailureLimiter,
    AuthMiddleware,
    RequireAuth,
    require_local_origin,
)
from pearl_connect.server.mcp_tools import build_mcp
from pearl_connect.settings import SettingsStore
from pearl_connect.signer import Signer
from pearl_connect.workspace import UI_INDEX, Workspace, load_ui_bundle

logger = logging.getLogger("agent")


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
    async def lifespan(_app: FastAPI) -> t.AsyncIterator[None]:
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="pearl-connect", lifespan=lifespan)
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
    app.state.funds_cache = {"at": 0.0, "value": {}, "lock": threading.Lock()}

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
    # registered below it. The bundle ships a stand-in page; a bundle with no
    # UI at all still serves the API (see load_ui_bundle).
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
