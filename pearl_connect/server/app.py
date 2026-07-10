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

import threading

from fastapi import Depends, FastAPI

from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig
from pearl_connect.server import pearl_routes, signer_routes
from pearl_connect.server.auth import RequireAuth
from pearl_connect.signer import Signer


def create_app(
    signer: Signer,
    config: AppConfig,
    activity: ActivityLog,
    *,
    token: str,
) -> FastAPI:
    """Create app."""
    app = FastAPI(title="pearl-connect")
    app.state.signer = signer
    app.state.config = config
    app.state.activity = activity
    app.state.funds_cache = {"at": 0.0, "value": {}, "lock": threading.Lock()}

    app.include_router(pearl_routes.router)
    app.include_router(
        signer_routes.router,
        dependencies=[Depends(RequireAuth(token, activity))],
    )
    return app
