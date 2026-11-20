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

"""The MCP mount's auth: each JSON-RPC `tools/call` checked before the MCP app.

`AuthMiddleware` enforces the local origin and the bearer token, refuses a
body the MCP server cannot serve (a batch, or JSON nested past the parser's
depth), runs the tool's own input check (`ToolBoundary.check_call`) and then
`GrantStore.authorize`, so a malformed call never draws on a budget. The rules
are the README's ("Scoped tokens").
"""

import json
import typing as t

from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import INVALID_REQUEST as JSONRPC_INVALID_REQUEST
from mcp.types import PARSE_ERROR as JSONRPC_PARSE_ERROR

from connect.activity import ActivityLog
from connect.server.auth import (
    AUTH_TOKEN,
    AuthFailureLimiter,
    GrantRefused,
    GrantStore,
    RATE_LIMIT_MESSAGE,
    REPLAYS,
    origin_is_local,
)
from connect.server.strict import AuditedRefusal
from connect.texts import BATCH_REFUSED, BODY_TOO_DEEP

_TOO_DEEP = object()  # a body nested past the JSON parser's recursion limit


# the JSON-RPC error code of a grant refusal, which the shipped client reads
GRANT_REFUSED_CODE = -32001

# the audit rules of a body the mount refused before authorizing anything
INPUT_REFUSED_RULE = "invalid-request"  # a call's own input check refused it
BATCH_REFUSED_RULE = "batch"  # a batch body: one message per request
BODY_TOO_DEEP_RULE = "body-too-deep"  # JSON nested past the parser's depth


class ToolBoundary(t.Protocol):
    """What the MCP mount reads of the MCP app: its tools and their input check."""

    def tool_names(self) -> frozenset[str]:
        """Return the names of the registered tools."""

    def check_call(self, name: str, arguments: dict[str, t.Any]) -> dict[str, t.Any]:
        """Refuse a registered tool's malformed arguments by raising `ToolError`."""


class AuthMiddleware:
    """Pure-ASGI equivalent of RequireAuth for mounted sub-apps (the MCP mount)."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        app: t.Callable,
        grants: GrantStore,
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
        *,
        boundary: ToolBoundary,
    ) -> None:
        """Initialize over the MCP app's `boundary`: its tools and input check.

        A call naming none of its tools authorizes nothing, so it is passed on
        unauthorized for the MCP app to answer as unknown. A registered tool
        always meets `check_call` and then `authorize`, so a malformed call
        never draws on a budget and one with no scope is refused.
        """
        self._app = app
        self._grants = grants
        self._activity = activity
        self._limiter = limiter
        self._tools = boundary.tool_names()
        self._check = boundary.check_call

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
            await _reject(send, 429, RATE_LIMIT_MESSAGE)
            return
        token = self._grants.lookup(headers.get("authorization"))
        if token is None:
            self._fail(path, "bad token")
            await _reject(send, 401, "invalid or missing bearer token")
            return
        body = await _read_body(receive)
        replays: set[tuple[str, str]] = set()
        refusal = self._refusal(token, body, replays)
        if refusal is not None:
            await _send_json(send, 200, refusal)
            return
        # read back by the send tools through the MCP request context
        scope.setdefault("state", {}).update({AUTH_TOKEN: token, REPLAYS: replays})
        await self._app(scope, _replay(body, receive), send)

    def _refusal(
        self, token: str, body: bytes, replays: set[tuple[str, str]]
    ) -> dict | None:
        """Return the answer to a tool call this token may not make, if any.

        A body `_refused_body` refuses answers first. A call's input refusal
        (the tool's own `check_call`) is answered as the tool's error would
        be, and a grant refusal as a JSON-RPC error. A call relieved as a retry
        is added to `replays` as (tool, request id).
        """
        call = _parsed(body)
        refused = self._refused_body(call)
        if refused is not None:
            return refused
        if not isinstance(call, dict) or call.get("method") != "tools/call":
            return None
        params = call.get("params")
        params = params if isinstance(params, dict) else {}
        arguments = params.get("arguments")
        arguments = arguments if isinstance(arguments, dict) else {}
        name = str(params.get("name"))
        if name not in self._tools:
            return None
        try:
            # authorized as the tool will read them: an unread extra (S3) is
            # not something the cap may count
            arguments = self._check(name, arguments)
            if self._grants.authorize(token, name, arguments):
                replays.add((name, str(arguments["request_id"])))
        except ToolError as e:
            reason = str(e)
            if not isinstance(e, AuditedRefusal):  # else recorded where refused
                self._activity.record(
                    "refusal", rule=INPUT_REFUSED_RULE, tool=name, reason=reason
                )
            return {
                "jsonrpc": "2.0",
                "id": call.get("id"),
                "result": {
                    "content": [{"type": "text", "text": reason}],
                    "isError": True,
                },
            }
        except GrantRefused as e:
            self._activity.record("refusal", rule=e.rule, tool=name, reason=str(e))
            return _rpc_error(call.get("id"), GRANT_REFUSED_CODE, e.message)
        return None

    def _refused_body(self, call: t.Any) -> dict | None:
        """Refuse a body the MCP server cannot serve, before anything is checked."""
        if call is _TOO_DEEP:
            self._activity.record(
                "refusal", rule=BODY_TOO_DEEP_RULE, reason=BODY_TOO_DEEP
            )
            return _rpc_error(None, JSONRPC_PARSE_ERROR, BODY_TOO_DEEP)
        if isinstance(call, list):
            self._activity.record(
                "refusal", rule=BATCH_REFUSED_RULE, reason=BATCH_REFUSED
            )
            return _rpc_error(None, JSONRPC_INVALID_REQUEST, BATCH_REFUSED)
        return None

    def _fail(self, path: str, reason: str) -> None:
        self._activity.record("auth_failed", path=path, reason=reason)
        self._limiter.record_failure()


def _parsed(body: bytes) -> t.Any:
    """Return a request body as JSON, None when it is not JSON at all.

    The MCP server answers a body that is not JSON itself. One nested past the
    parser's limit is `_TOO_DEEP`: the server's own parse would hit it too.
    """
    try:
        return json.loads(body or b"null")
    except ValueError:
        return None
    except RecursionError:
        return _TOO_DEEP


def _rpc_error(call_id: t.Any, code: int, message: str) -> dict:
    """Return a JSON-RPC error answer."""
    return {
        "jsonrpc": "2.0",
        "id": call_id,
        "error": {"code": code, "message": message},
    }


async def _reject(send: t.Any, status: int, message: str) -> None:
    await _send_json(send, status, {"error": message})


async def _send_json(send: t.Any, status: int, payload: t.Any) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": json.dumps(payload).encode()})


async def _read_body(receive: t.Any) -> bytes:
    """Read the whole request body, so its tool calls can be authorized."""
    chunks = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body"):
            break
    return b"".join(chunks)


def _replay(body: bytes, receive: t.Any) -> t.Callable[[], t.Awaitable[dict]]:
    """Return a receive that yields the read body, then the real stream."""
    sent = False

    async def replay() -> dict:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replay
