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
    return hmac.compare_digest(expected, header.removeprefix("Bearer "))


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
