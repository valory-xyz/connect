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

"""Bearer-token auth, Origin validation and auth-failure braking.

The token is minted per run and reaches Claude Code only via the .mcp.json
file in STORE_PATH. Origin validation defends the localhost server against
DNS-rebinding: browsers always attach an Origin to cross-origin requests, so
anything non-local is rejected before auth. Repeated auth failures across
every authenticated surface are audited to the activity log and, past a
threshold, rate-limited — a stolen token or password being probed should be
loud and slow, not silent.
"""

import hmac
import threading
import time
import typing as t
from collections import deque
from urllib.parse import urlparse

from fastapi import HTTPException, Request

from pearl_connect.activity import ActivityLog

LOCAL_HOSTNAMES = {"localhost", "127.0.0.1", "[::1]", "::1"}
# TrustedHostMiddleware wants patterns, not a set; port is ignored by it.
# No IPv6 entry: the server binds IPv4 loopback only, and Starlette splits
# the Host header on ":" so a bracketed IPv6 literal could never match.
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

MAX_AUTH_FAILURES = 10
AUTH_FAILURE_WINDOW_SECONDS = 60.0
_RATE_LIMIT_MESSAGE = "too many failed authentication attempts; retry later"


class AuthFailureLimiter:
    """Global brake shared by every authenticated surface.

    After MAX_AUTH_FAILURES failed attempts (bad token or bad password)
    within the window, all authenticated requests are refused with 429 until
    the window drains. Local single-user server: a global (rather than
    per-client) brake is the honest model — source addresses on loopback
    carry no identity. Cross-origin rejections are audited but never counted:
    they require no secret, so counting them would let any webpage's simple
    requests hold the whole agent at 429.
    """

    def __init__(
        self,
        max_failures: int = MAX_AUTH_FAILURES,
        window_seconds: float = AUTH_FAILURE_WINDOW_SECONDS,
    ) -> None:
        """Initialize."""
        self._max_failures = max_failures
        self._window = window_seconds
        self._lock = threading.Lock()
        self._failures: deque[float] = deque()

    def _prune(self) -> None:
        cutoff = time.monotonic() - self._window
        while self._failures and self._failures[0] < cutoff:
            self._failures.popleft()

    def blocked(self) -> bool:
        """Whether the brake is currently engaged."""
        with self._lock:
            self._prune()
            return len(self._failures) >= self._max_failures

    def record_failure(self) -> None:
        """Count one failed authentication attempt."""
        with self._lock:
            self._prune()
            self._failures.append(time.monotonic())


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

    def __init__(
        self, token: str, activity: ActivityLog, limiter: AuthFailureLimiter
    ) -> None:
        """Initialize."""
        self._token = token
        self._activity = activity
        self._limiter = limiter

    def __call__(self, request: Request) -> None:
        """Call."""
        if not origin_is_local(request.headers.get("origin")):
            # audited, never brake-counted: a webpage's simple request needs
            # no secret to arrive with a foreign Origin, while a bad token
            # cannot be sent cross-origin at all (the Authorization header
            # forces a CORS preflight, which fails with no CORS enabled)
            self._activity.record(
                "auth_failed", path=request.url.path, reason="cross-origin"
            )
            raise HTTPException(
                status_code=403, detail="cross-origin requests are not allowed"
            )
        if self._limiter.blocked():
            raise HTTPException(status_code=429, detail=_RATE_LIMIT_MESSAGE)
        if not token_matches(self._token, request.headers.get("authorization")):
            self._fail(request.url.path, "bad token")
            raise HTTPException(
                status_code=401, detail="invalid or missing bearer token"
            )

    def _fail(self, path: str, reason: str) -> None:
        self._activity.record("auth_failed", path=path, reason=reason)
        self._limiter.record_failure()


class AuthMiddleware:
    """Pure-ASGI equivalent of RequireAuth for mounted sub-apps (the MCP mount)."""

    def __init__(
        self,
        app: t.Callable,
        token: str,
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
    ) -> None:
        """Initialize."""
        self._app = app
        self._token = token
        self._activity = activity
        self._limiter = limiter

    async def __call__(self, scope: t.Any, receive: t.Any, send: t.Any) -> None:
        """Enforce Origin locality + bearer token, then delegate."""
        if scope["type"] == "lifespan":
            await self._app(scope, receive, send)
            return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close"})
            return  # nothing serves non-http scopes
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        path = scope.get("path", "")
        if not origin_is_local(headers.get("origin")):
            # audited, never brake-counted — see RequireAuth for the rationale
            self._activity.record("auth_failed", path=path, reason="cross-origin")
            await _reject(send, 403, "cross-origin requests are not allowed")
            return
        if self._limiter.blocked():
            await _reject(send, 429, _RATE_LIMIT_MESSAGE)
            return
        if not token_matches(self._token, headers.get("authorization")):
            self._fail(path, "bad token")
            await _reject(send, 401, "invalid or missing bearer token")
            return
        await self._app(scope, receive, send)

    def _fail(self, path: str, reason: str) -> None:
        self._activity.record("auth_failed", path=path, reason=reason)
        self._limiter.record_failure()


def require_local_origin(request: Request) -> None:
    """Router dependency: reject cross-origin requests (no token involved)."""
    if not origin_is_local(request.headers.get("origin")):
        raise HTTPException(
            status_code=403, detail="cross-origin requests are not allowed"
        )


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
