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

"""Bearer-token auth, scoped grants, Origin validation and auth-failure braking.

The workspace token is minted per run and reaches the agent harness only via
the .mcp.json and .codex/config.toml files in STORE_PATH. It is a *scoped*
token: `read` + `mech` + `tx` with no caps of its own, so a
session can do what it always could, and it is the root every narrower token
is minted from: a harness mints them for the scripts it runs (fewer scopes,
value caps per transaction and per session, a mech payment cap, an expiry).
Origin validation
defends the localhost server against DNS-rebinding: browsers always attach an
Origin to cross-origin requests, so anything non-local is rejected before
auth. Repeated auth failures across
every authenticated surface are audited to the activity log and, past a
threshold, rate-limited — a stolen token or password being probed should be
loud and slow, not silent.
"""

import hmac
import json
import math
import secrets
import threading
import time
import typing as t
from collections import deque
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from pydantic import field_validator

from connect import intent as intent_module
from connect.activity import ActivityLog
from connect.server.strict import StrictBody

Scope = t.Literal["read", "mech", "tx"]
SCOPES: tuple[Scope, ...] = ("read", "mech", "tx")

# what each action needs: MCP tools by name, HTTP routes by the same names
ACTION_SCOPES: dict[str, Scope] = {
    "wallet_info": "read",
    "mech_tools": "read",
    "mech_result": "read",
    "transaction_status": "read",
    "preflight_transaction": "read",
    "simulate_transaction": "read",
    "chain_call": "read",
    "get_abi": "read",
    "decode_calldata": "read",
    "settings": "read",
    "mech_request": "mech",
    "safe_transaction": "tx",
    "send_transaction": "tx",
    "sign_message": "tx",
}


class TokenGrant(StrictBody):
    """What a bearer token may do; a token can only mint a narrower one.

    Unknown fields are refused by name, like every other HTTP body.
    """

    scopes: list[Scope]
    max_value_per_tx: dict[str, int] | None = None
    max_value_per_session: dict[str, int] | None = None
    max_mech_payment: int | None = None
    expires_at: int | None = None  # unix seconds

    @field_validator("max_value_per_tx", "max_value_per_session")
    @classmethod
    def _cap_keys(cls, caps: dict[str, int] | None) -> dict[str, int] | None:
        """Key caps as the intent gate keys balances: "native", or an address."""
        if caps is None:
            return None
        keyed: dict[str, int] = {}
        for token, amount in caps.items():
            key = intent_module.balance_key(token)  # ValueError: not a token
            if amount < 0:
                raise ValueError(f"cap for {token} must be >= 0")
            if key in keyed:
                raise ValueError(f"caps name {key} twice")
            keyed[key] = amount
        return keyed

    def value_capped(self) -> bool:
        """Whether any value cap binds this grant."""
        return (
            self.max_value_per_tx is not None or self.max_value_per_session is not None
        )


WORKSPACE_GRANT = TokenGrant(scopes=list(SCOPES))

# the request-state key the MCP mount sets: the bearer token that authorized it
AUTH_TOKEN = "auth_token"  # nosec B105 - a state key, not a credential


class GrantRefused(Exception):
    """A token may not do this; `rule` names why."""

    def __init__(self, rule: str, detail: str, status: int = 403) -> None:
        """Initialize."""
        super().__init__(rule, detail, status)
        self.rule = rule
        self.detail = detail
        self.status = status

    def __str__(self) -> str:
        """Return the refusal a caller reads."""
        return self.detail


def _within(child: dict[str, int] | None, parent: dict[str, int] | None) -> bool:
    """Whether a child's caps are no wider than its parent's (None is no cap)."""
    if parent is None:
        return True
    if child is None:
        return False
    return all(
        token in parent and amount <= parent[token] for token, amount in child.items()
    )


def narrower(child: TokenGrant, parent: TokenGrant) -> bool:
    """Whether `child` allows nothing `parent` does not."""
    if not set(child.scopes) <= set(parent.scopes):
        return False
    if not _within(child.max_value_per_tx, parent.max_value_per_tx):
        return False
    if not _within(child.max_value_per_session, parent.max_value_per_session):
        return False
    if parent.max_mech_payment is not None and (
        child.max_mech_payment is None
        or child.max_mech_payment > parent.max_mech_payment
    ):
        return False
    if parent.expires_at is not None and (
        child.expires_at is None or child.expires_at > parent.expires_at
    ):
        return False
    return True


def _declared(
    arguments: t.Mapping[str, t.Any],
) -> tuple[dict[str, int], list[intent_module.IntentApproval]]:
    """Return what a call may spend, and the approvals its intent allows.

    The spend is the intent's `spend` and the call's native value.

    The intent is read exactly as the tool will read it: a JSON string is
    decoded first (FastMCP does the same before validating), and the intent
    gate's own parser decides what it declares, so the cap and the gate can
    never read two different intents.

    :raises GrantRefused: a malformed intent or a value that is not a whole
        number >= 0, before any budget is drawn on.
    """
    raw = arguments.get("intent")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            pass  # left as a string: parse_intent refuses it below
    parsed, problems = intent_module.parse_intent(raw)
    if problems:
        raise GrantRefused("bad-intent", problems[0]["detail"])
    declared = dict((parsed or {}).get("spend", {}))
    value = arguments.get("value") or 0
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        value = int(value)  # a JSON 5.0, which the tool's int field takes too
    try:
        value = intent_module.parse_amount(value)  # the gate's own amount rule
    except (TypeError, ValueError) as e:
        raise GrantRefused("bad-value", f"value: {e} (got {value!r})") from e
    declared[intent_module.NATIVE] = max(declared.get(intent_module.NATIVE, 0), value)
    return declared, list((parsed or {}).get("approvals", []))


class GrantStore:
    """The bearer tokens this process honours, and what each may do."""

    def __init__(self, workspace_token: str) -> None:
        """Hold the workspace token, the root every other token is minted from."""
        self._lock = threading.Lock()
        self._grants: dict[str, TokenGrant] = {workspace_token: WORKSPACE_GRANT}
        self._spent: dict[str, dict[str, int]] = {}
        # a minted token's parent: a session cap binds every descendant
        self._parents: dict[str, str] = {}

    def lookup(self, header: str | None) -> str | None:
        """Return the presented token if it is one we issued, else None."""
        if not header or not header.startswith("Bearer "):
            return None
        presented = header.removeprefix("Bearer ").encode()
        with self._lock:
            tokens = list(self._grants)
        found = None
        for token in tokens:  # compare against every token, in constant time
            if hmac.compare_digest(token.encode(), presented):
                found = token
        return found

    def grant(self, token: str) -> TokenGrant:
        """Return a known token's grant."""
        with self._lock:
            return self._grants[token]

    def mint(self, parent: str, grant: TokenGrant) -> str:
        """Mint a token for `grant`, which must be no wider than `parent`'s.

        :raises GrantRefused: rule "token-scope" for a wider grant.
        """
        if not narrower(grant, self._live(parent)):
            raise GrantRefused(
                "token-scope",
                "a token can only mint a narrower one: the requested grant "
                "allows something this token does not",
            )
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._grants[token] = grant
            self._parents[token] = parent
        return token

    def _live(self, token: str) -> TokenGrant:
        grant = self.grant(token)
        if grant.expires_at is not None and time.time() >= grant.expires_at:
            raise GrantRefused("token-expired", "this token has expired", 401)
        return grant

    def authorize(
        self, token: str, action: str, arguments: t.Mapping[str, t.Any]
    ) -> None:
        """Raise unless `token` may perform `action` with `arguments`.

        Value caps are checked against the spend the call's intent declares,
        which the intent gate then holds the transaction to, and bound the
        approvals it declares too. What a cap cannot bound, a capped token may
        not do: sign a raw digest (it can authorize any safe transaction), or
        move a position (`intent.Capped`, which the send surfaces apply).
        A capped token's per-session budget is drawn down when a call is
        authorized, whether or not the send then succeeds: it can be spent
        early, never exceeded.
        """
        grant = self._live(token)
        scope = ACTION_SCOPES.get(action)
        if scope is None or scope not in grant.scopes:
            raise GrantRefused(
                "token-scope",
                f"this token does not allow {action} (it needs the "
                f"'{scope or 'unknown'}' scope)",
            )
        if action == "mech_request":
            self._check_mech_payment(grant, arguments)
        if action == "sign_message" and grant.value_capped():
            raise GrantRefused(
                "token-cap-per-tx",
                "a value-capped token may not sign raw digests: a digest can "
                "authorize a safe transaction that no cap or intent sees",
            )
        if scope == "tx" and action != "sign_message":
            self._check_value(token, grant, arguments)

    def intent_for(self, token: str | None, intent: t.Any) -> t.Any:
        """Return the intent the gate holds a call to, for the calling token.

        A value-capped token's intent is `intent.Capped`, so the gate refuses
        any position the call moves out. The one rule for both surfaces, and
        it fails closed: a call with no known token is treated as capped.
        """
        with self._lock:
            grant = self._grants.get(token) if token else None
        if grant is None or grant.value_capped():
            return intent_module.Capped(intent)
        return intent

    @staticmethod
    def _check_mech_payment(
        grant: TokenGrant, arguments: t.Mapping[str, t.Any]
    ) -> None:
        cap = grant.max_mech_payment
        if cap is None:
            return
        asked = arguments.get("max_payment")
        if not isinstance(asked, int) or isinstance(asked, bool) or asked > cap:
            raise GrantRefused(
                "token-mech-payment-cap",
                f"this token pays a mech at most {cap} base units; pass a "
                f"max_payment no higher than that (got {asked})",
            )

    def _check_value(  # pylint: disable=too-many-locals
        self, token: str, grant: TokenGrant, arguments: t.Mapping[str, t.Any]
    ) -> None:
        declared, approvals = _declared(arguments)  # refuses malformed first
        self._check_approvals(grant, approvals)
        per_tx = grant.max_value_per_tx
        if per_tx is not None:
            for asset, amount in declared.items():
                if amount > per_tx.get(asset, 0):
                    raise GrantRefused(
                        "token-cap-per-tx",
                        f"this token spends at most {per_tx.get(asset, 0)} of "
                        f"{asset} per transaction (the call declares {amount})",
                    )
        # an approval is spend its spender may take later, outside any send this
        # token makes: it draws on the session budget like the spend itself.
        # Except an ERC-20 approval of Permit2: Permit2 moves the token only
        # for a Permit2 grant, which the gate makes the intent declare and
        # which draws here, or a signed permit, which a capped token cannot
        # sign. Drawing both would charge one swap's funds twice.
        drawn = dict(declared)
        for approval in approvals:
            if approval["spender"] == intent_module.PERMIT2:
                continue
            key = intent_module.balance_key(approval["token"])
            drawn[key] = drawn.get(key, 0) + approval["amount"]
        with self._lock:
            # this token and every ancestor it was minted from: minting more
            # children must not multiply a parent's session budget
            chain = [token]
            while chain[-1] in self._parents:
                chain.append(self._parents[chain[-1]])
            capped = [
                (holder, self._grants[holder].max_value_per_session)
                for holder in chain
                if self._grants[holder].max_value_per_session is not None
            ]
            for holder, per_session in capped:
                spent = self._spent.get(holder, {})
                for asset, amount in drawn.items():
                    cap = t.cast(dict, per_session).get(asset, 0)
                    if spent.get(asset, 0) + amount > cap:
                        raise GrantRefused(
                            "token-cap-per-session",
                            f"this token spends at most {cap} of {asset} in all "
                            f"(with every token minted from it); "
                            f"{spent.get(asset, 0)} is spent and this declares "
                            f"{amount} (spend and approvals)",
                        )
            for holder, _ in capped:
                spent = self._spent.setdefault(holder, {})
                for asset, amount in drawn.items():
                    spent[asset] = spent.get(asset, 0) + amount

    @staticmethod
    def _check_approvals(
        grant: TokenGrant, approvals: list[intent_module.IntentApproval]
    ) -> None:
        """Hold a capped token's declared approvals to its caps.

        An approval lets the spender move up to its amount later, outside any
        transaction this token sends, so it is held to the per-transaction and
        the per-session cap alike; a token with no cap may not be approved.
        """
        for caps in (grant.max_value_per_tx, grant.max_value_per_session):
            if caps is None:
                continue
            for approval in approvals:
                token = intent_module.balance_key(approval["token"])
                if approval["amount"] > caps.get(token, 0):
                    raise GrantRefused(
                        "token-cap-per-tx",
                        f"this token may approve at most {caps.get(token, 0)} of "
                        f"{token} (the intent approves {approval['amount']})",
                    )


def request_token(request: t.Any) -> str | None:
    """Return the bearer token the auth layer stamped on a request, if any.

    Both surfaces stamp it under AUTH_TOKEN: `RequireAuth` on an HTTP route's
    request, the MCP mount's middleware on the scope the tool's request reads.
    """
    return getattr(getattr(request, "state", None), AUTH_TOKEN, None)


def as_store(grants: "GrantStore | str") -> GrantStore:
    """Accept a GrantStore, or a bare workspace token for a store of one."""
    return GrantStore(grants) if isinstance(grants, str) else grants


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


class RequireAuth:
    """FastAPI dependency enforcing Origin locality + a bearer token we issued.

    The route itself then authorizes its action against the token's grant
    (`authorize_route`), because a cap is checked against the request body.
    """

    def __init__(
        self,
        grants: "GrantStore | str",
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
    ) -> None:
        """Initialize."""
        self._grants = as_store(grants)
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
        token = self._grants.lookup(request.headers.get("authorization"))
        if token is None:
            self._fail(request.url.path, "bad token")
            raise HTTPException(
                status_code=401, detail="invalid or missing bearer token"
            )
        setattr(request.state, AUTH_TOKEN, token)

    def _fail(self, path: str, reason: str) -> None:
        self._activity.record("auth_failed", path=path, reason=reason)
        self._limiter.record_failure()


class AuthMiddleware:
    """Pure-ASGI equivalent of RequireAuth for mounted sub-apps (the MCP mount)."""

    def __init__(
        self,
        app: t.Callable,
        grants: "GrantStore | str",
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
    ) -> None:
        """Initialize."""
        self._app = app
        self._grants = as_store(grants)
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
        token = self._grants.lookup(headers.get("authorization"))
        if token is None:
            self._fail(path, "bad token")
            await _reject(send, 401, "invalid or missing bearer token")
            return
        body = await _read_body(receive)
        refusal = self._refusal(token, body)
        if refusal is not None:
            await _send_json(send, 200, refusal)
            return
        # read back by the send tools through the MCP request context
        scope.setdefault("state", {})[AUTH_TOKEN] = token
        await self._app(scope, _replay(body, receive), send)

    def _refusal(self, token: str, body: bytes) -> dict | None:
        """Return a JSON-RPC error for the first tool call this token may not make."""
        try:
            message = json.loads(body or b"null")
        except ValueError:
            return None  # the MCP server answers a malformed body itself
        for call in message if isinstance(message, list) else [message]:
            if not isinstance(call, dict) or call.get("method") != "tools/call":
                continue
            params = call.get("params")
            params = params if isinstance(params, dict) else {}
            arguments = params.get("arguments")
            try:
                self._grants.authorize(
                    token,
                    str(params.get("name")),
                    arguments if isinstance(arguments, dict) else {},
                )
            except GrantRefused as e:
                self._activity.record(
                    "refusal", rule=e.rule, tool=params.get("name"), reason=str(e)
                )
                return {
                    "jsonrpc": "2.0",
                    "id": call.get("id"),
                    "error": {"code": -32001, "message": f"rule '{e.rule}': {e}"},
                }
        return None

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


def authorize_route(
    request: Request, activity: ActivityLog, action: str, arguments: dict
) -> None:
    """Authorize an HTTP route's action against the request's token.

    :raises HTTPException: 403 (401 for an expired token) naming the rule.
    """
    grants: GrantStore = request.app.state.grants
    try:
        grants.authorize(getattr(request.state, AUTH_TOKEN), action, arguments)
    except GrantRefused as e:
        activity.record("refusal", rule=e.rule, path=request.url.path, reason=str(e))
        raise HTTPException(status_code=e.status, detail=f"rule '{e.rule}': {e}") from e
