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

"""Bearer-token auth and Origin validation.

The token is minted per run and reaches Claude Code only via the .mcp.json
file in STORE_PATH. Origin validation defends the localhost server against
DNS-rebinding: browsers always attach an Origin to cross-origin requests, so
anything non-local is rejected before auth.
"""

import hmac
import typing as t
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from pearl_connect.activity import ActivityLog

LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}


def origin_is_local(origin: str | None) -> bool:
    """Origin is local."""
    if not origin:
        return True  # non-browser clients (Claude Code, scripts) send no Origin
    hostname = urlparse(origin).hostname
    return hostname in LOCAL_HOSTNAMES


def token_matches(expected: str, header: str | None) -> bool:
    """Token matches."""
    if not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(
        expected.encode(), header.removeprefix("Bearer ").encode()
    )


class RequireAuth:
    """FastAPI dependency enforcing Origin locality + bearer token."""

    def __init__(self, token: str, activity: ActivityLog) -> None:
        """Initialize."""
        self._token = token
        self._activity = activity

    def __call__(self, request: Request) -> None:
        """Call."""
        if not origin_is_local(request.headers.get("origin")):
            raise HTTPException(
                status_code=403, detail="cross-origin requests are not allowed"
            )
        if not token_matches(self._token, request.headers.get("authorization")):
            raise HTTPException(
                status_code=401, detail="invalid or missing bearer token"
            )


class AuthMiddleware:
    """Pure-ASGI equivalent of RequireAuth for mounted sub-apps (the MCP mount)."""

    def __init__(self, app: t.Callable, token: str, activity: ActivityLog) -> None:
        """Initialize."""
        self._app = app
        self._token = token
        self._activity = activity

    async def __call__(self, scope: t.Any, receive: t.Any, send: t.Any) -> None:
        """Enforce Origin locality + bearer token, then delegate."""
        if scope["type"] == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope["type"] != "http":
            return  # drop anything else (e.g. websocket) — nothing serves it
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        if not origin_is_local(headers.get("origin")):
            await _reject(send, 403, "cross-origin requests are not allowed")
            return
        if not token_matches(self._token, headers.get("authorization")):
            await _reject(send, 401, "invalid or missing bearer token")
            return
        await self._app(scope, receive, send)


async def _reject(send: t.Any, status: int, message: str) -> None:
    body = f'{{"error": "{message}"}}'.encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})
