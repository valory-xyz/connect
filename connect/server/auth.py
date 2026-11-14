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
value caps per transaction and per session, mech payment caps, an expiry).
Origin validation
defends the localhost server against DNS-rebinding: browsers always attach an
Origin to cross-origin requests, so anything non-local is rejected before
auth. Repeated auth failures across
every authenticated surface are audited to the activity log and, past a
threshold, rate-limited — a stolen token or password being probed should be
loud and slow, not silent.
"""

import hashlib
import json
import math
import secrets
import threading
import time
import typing as t
from collections import OrderedDict, deque
from urllib.parse import urlparse

from fastapi import HTTPException, Request
from pydantic import ConfigDict, Field, field_validator

from connect import intent as intent_module
from connect.activity import ActivityLog
from connect.chain_read import UNIVERSAL_ROUTER_NAME, known_contract
from connect.chains import chain_info
from connect.server.strict import StrictBody
from connect.signer import MAX_CACHED_RESULTS

Scope = t.Literal["read", "mech", "tx"]
SCOPES: tuple[Scope, ...] = ("read", "mech", "tx")
# every rule a grant refusal names; clients branch on it (`GrantRefused.message`)
GrantRule = t.Literal[
    "token-scope",
    "token-expired",
    "token-expiry-required",
    "token-mech-cap-required",
    "token-limit",
    "token-cap-per-tx",
    "token-cap-per-session",
    "token-cap-sign",
    "token-mech-payment-cap",
    "token-mech-session-cap",
    "bad-intent",
    "bad-value",
]
# live tokens one token may have minted, and in all: minting is open to any
# token, so neither may grow without bound
MAX_CHILDREN_PER_TOKEN = 64
MAX_LIVE_TOKENS = 1024

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

    Unknown fields are refused by name, like every other HTTP body. Frozen,
    and stored and handed out as copies, so nothing widens a live grant
    without passing its validation again.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    scopes: tuple[Scope, ...]
    max_value_per_tx: dict[str, int] | None = None
    max_value_per_session: dict[str, int] | None = None
    max_mech_payment: int | None = Field(default=None, ge=0)
    max_mech_payment_per_session: int | None = Field(default=None, ge=0)
    expires_at: int | None = Field(default=None, gt=0)  # unix seconds

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


WORKSPACE_GRANT = TokenGrant(scopes=SCOPES)
# as many request ids' draws as the signer keeps results; one forgotten is drawn again
MAX_DRAWN_REQUEST_IDS = MAX_CACHED_RESULTS

# the request-state key the MCP mount sets: the bearer token that authorized it
AUTH_TOKEN = "auth_token"  # nosec B105 - a state key, not a credential
# and the (tool, request id) of each call it relieved as a retry: replay only
REPLAYS = "replays"


class GrantRefused(Exception):
    """A token may not do this; `rule` names why."""

    def __init__(self, rule: GrantRule, detail: str, status: int = 403) -> None:
        """Initialize."""
        super().__init__(rule, detail, status)
        self.rule = rule
        self.detail = detail
        self.status = status

    def __str__(self) -> str:
        """Return the refusal a caller reads."""
        return self.detail

    @property
    def message(self) -> str:
        """Return the refusal as every surface words it, its rule first.

        One wording, since the shipped client reads a refusal by that prefix.
        """
        return f"rule '{self.rule}': {self.detail}"


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
    for field in ("max_mech_payment", "max_mech_payment_per_session", "expires_at"):
        limit = getattr(parent, field)
        mine = getattr(child, field)
        if limit is not None and (mine is None or mine > limit):
            return False
    return True


def _expired() -> GrantRefused:
    """Return the refusal of an expired token: a 401, as the README says."""
    return GrantRefused("token-expired", "this token has expired", 401)


def _key(token: str) -> str:
    """Return the key a token is stored under: its SHA-256, one dict lookup away."""
    return hashlib.sha256(token.encode()).hexdigest()


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


def _is_universal_router(spender: str, chain: t.Any) -> bool:
    """Whether `spender` is a Uniswap Universal Router Connect ships on `chain`."""
    info = chain_info(chain) if isinstance(chain, str) else None
    if info is None:
        return False
    known = known_contract(spender, info["chain_id"])
    return known is not None and known.name == UNIVERSAL_ROUTER_NAME


class GrantStore:  # pylint: disable=too-many-instance-attributes
    """The bearer tokens this process honours, and what each may do.

    Every table is keyed by the token's SHA-256 (`_key`), never the token.
    """

    def __init__(
        self, workspace_token: str, *, held: t.Callable[[str, bool], bool]
    ) -> None:
        """Hold the workspace token, the root every other token is minted from.

        `held(request_id, via_safe)` says whether the signer holds that request
        id, completed or still sending (`Signer.holds_request`): a call
        repeating it then sends nothing new.
        """
        self._held = held
        # what each (token, action, request_id) has drawn, so a retry of a
        # request this token already paid for is not drawn again; forgotten
        # past the bound, which only draws again
        self._drawn: OrderedDict[tuple[str, str, str], dict[str, int]] = OrderedDict()
        self._lock = threading.Lock()
        self._grants: dict[str, TokenGrant] = {_key(workspace_token): WORKSPACE_GRANT}
        self._spent: dict[str, dict[str, int]] = {}
        self._mech_spent: dict[str, int] = {}
        # a minted token's parent: a session cap binds every descendant
        self._parents: dict[str, str] = {}

    def lookup(self, header: str | None) -> str | None:
        """Return the presented token if it is one we issued, else None."""
        if not header or not header.startswith("Bearer "):
            return None
        presented = header.removeprefix("Bearer ")
        with self._lock:
            return presented if _key(presented) in self._grants else None

    def grant(self, token: str) -> TokenGrant:
        """Return a copy of a known token's grant.

        :raises GrantRefused: `token-expired`: `lookup` accepted it, but a
            mint has pruned it since, which only an expired token is.
        """
        with self._lock:
            grant = self._grants.get(_key(token))
        if grant is None:
            raise _expired()
        return grant.model_copy(deep=True)

    def mint(self, parent: str, grant: TokenGrant) -> str:
        """Mint a token for `grant`, which must be no wider than `parent`'s.

        :raises GrantRefused: a wider grant (`token-scope`), one with no future
            expiry or a `mech` one with no session cap, or past the limits.
        """
        now = time.time()
        live = self._live(parent)
        if grant.expires_at is None or grant.expires_at <= now:
            raise GrantRefused(
                "token-expiry-required",
                "a minted token needs an expires_at in the future (unix seconds)",
                400,
            )
        if "mech" in grant.scopes and grant.max_mech_payment_per_session is None:
            raise GrantRefused(
                "token-mech-cap-required",
                "a minted token with the 'mech' scope needs a "
                "max_mech_payment_per_session",
                400,
            )
        if not narrower(grant, live):
            raise GrantRefused(
                "token-scope",
                "a token can only mint a narrower one: the requested grant "
                "allows something this token does not",
            )
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(now)
            siblings = sum(1 for p in self._parents.values() if p == _key(parent))
            if (
                siblings >= MAX_CHILDREN_PER_TOKEN
                or len(self._grants) >= MAX_LIVE_TOKENS
            ):
                raise GrantRefused(
                    "token-limit",
                    f"too many live tokens (at most {MAX_CHILDREN_PER_TOKEN} "
                    f"minted by one token, {MAX_LIVE_TOKENS} in all); let some "
                    "expire first",
                )
            self._grants[_key(token)] = grant.model_copy(deep=True)
            self._parents[_key(token)] = _key(parent)
        return token

    def _prune(self, now: float) -> None:
        """Forget every expired token; the caller holds the lock.

        A child never outlives its parent (`narrower`), so no live token
        loses an ancestor here.
        """
        expired = {
            key
            for key, grant in self._grants.items()
            if grant.expires_at is not None and grant.expires_at <= now
        }
        for key in expired:
            del self._grants[key]
            self._parents.pop(key, None)
            self._spent.pop(key, None)
            self._mech_spent.pop(key, None)
        for drawn in [k for k in self._drawn if k[0] in expired]:
            del self._drawn[drawn]

    def _live(self, token: str) -> TokenGrant:
        grant = self.grant(token)
        if grant.expires_at is not None and time.time() >= grant.expires_at:
            raise _expired()
        return grant

    def _lineage(self, key: str) -> list[tuple[str, TokenGrant]]:
        """Return `key` and every ancestor it was minted from, with their grants.

        The caller holds the lock. A token checked live a moment ago may have
        expired and been pruned by a mint since; its call is then refused as
        expired, as it would be had it arrived a moment later.
        """
        chain = [key]
        while chain[-1] in self._parents:
            chain.append(self._parents[chain[-1]])
        lineage = []
        for holder in chain:
            grant = self._grants.get(holder)
            if grant is None:
                raise _expired()
            lineage.append((holder, grant))
        return lineage

    def authorize(
        self,
        token: str,
        action: str,
        arguments: t.Mapping[str, t.Any],
        *,
        draw: bool = True,
    ) -> bool:
        """Refuse what `token` may not do; return whether a retry's draw was spared.

        The rules are the README's ("Scoped tokens"); `draw=False` is a dry run.
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
            self._check_mech_payment(_key(token), grant, arguments, draw=draw)
        if action == "sign_message" and grant.value_capped():
            raise GrantRefused(
                "token-cap-sign",
                "a value-capped token may not sign raw digests: a digest can "
                "authorize a safe transaction that no cap or intent sees",
            )
        if scope == "tx" and action != "sign_message":
            return self._check_value(
                _key(token), grant, action=action, arguments=arguments, draw=draw
            )
        return False

    def intent_for(
        self, token: str | None, intent: dict | None
    ) -> intent_module.AgentIntent:
        """Return the intent the gate holds a call to, for the calling token.

        A value-capped token's intent is `intent.Capped`, so the gate refuses
        any position the call moves out. The one rule for both surfaces, and
        it fails closed: a call with no known token is treated as capped.
        """
        with self._lock:
            grant = self._grants.get(_key(token)) if token else None
        if grant is None or grant.value_capped():
            return intent_module.Capped(intent)
        return intent

    def _check_mech_payment(
        self,
        key: str,
        grant: TokenGrant,
        arguments: t.Mapping[str, t.Any],
        *,
        draw: bool,
    ) -> None:
        """Hold a mech payment to the per-request cap and every session cap."""
        asked = arguments.get("max_payment")
        whole = isinstance(asked, int) and not isinstance(asked, bool) and asked >= 0
        cap = grant.max_mech_payment
        if cap is not None and (not whole or t.cast(int, asked) > cap):
            raise GrantRefused(
                "token-mech-payment-cap",
                f"this token pays a mech at most {cap} base units; pass a "
                f"max_payment no higher than that (got {asked})",
            )
        with self._lock:
            capped = [
                (holder, t.cast(int, held.max_mech_payment_per_session))
                for holder, held in self._lineage(key)
                if held.max_mech_payment_per_session is not None
            ]
            if not capped:
                return
            if not whole:
                raise GrantRefused(
                    "token-mech-session-cap",
                    "this token's mech payments draw on a session budget; pass "
                    f"max_payment as a whole number of base units (got {asked})",
                )
            for holder, per_session in capped:
                spent = self._mech_spent.get(holder, 0)
                if spent + t.cast(int, asked) > per_session:
                    raise GrantRefused(
                        "token-mech-session-cap",
                        f"this token pays mechs at most {per_session} base units "
                        f"in all (with every token minted from it); {spent} is "
                        f"drawn and this asks up to {asked}",
                    )
            if draw:
                for holder, _ in capped:
                    self._mech_spent[holder] = self._mech_spent.get(holder, 0) + t.cast(
                        int, asked
                    )

    def _check_value(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        key: str,
        grant: TokenGrant,
        *,
        action: str,
        arguments: t.Mapping[str, t.Any],
        draw: bool,
    ) -> bool:
        """Hold a send to the caps; return whether a retry's draw was relieved."""
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
        # Permit2 included, since it also honours grants made before this token.
        # Except an approval of a Universal Router: it pulls only from its own
        # caller, so only the safe's own swaps use it, and those draw as spend.
        drawn = dict(declared)
        for approval in approvals:
            if _is_universal_router(approval["spender"], arguments.get("chain")):
                continue
            asset = intent_module.balance_key(approval["token"])
            drawn[asset] = drawn.get(asset, 0) + approval["amount"]
        # a retry of a request id this token drew for, which the signer still
        # holds, sends nothing new: only what it declares past that draw is owed
        request_id = arguments.get("request_id")
        id_key = None
        paid: dict[str, int] = {}
        if isinstance(request_id, str):
            id_key = (key, action, request_id)
            if self._held(request_id, action == "safe_transaction"):
                with self._lock:
                    paid = self._drawn.get(id_key, {})
        owed = {asset: max(0, n - paid.get(asset, 0)) for asset, n in drawn.items()}
        with self._lock:
            # this token and every ancestor it was minted from: minting more
            # children must not multiply a parent's session budget
            capped = [
                (holder, held.max_value_per_session)
                for holder, held in self._lineage(key)
                if held.max_value_per_session is not None
            ]
            for holder, per_session in capped:
                spent = self._spent.get(holder, {})
                for asset, amount in owed.items():
                    cap = t.cast(dict, per_session).get(asset, 0)
                    if spent.get(asset, 0) + amount > cap:
                        raise GrantRefused(
                            "token-cap-per-session",
                            f"this token spends at most {cap} of {asset} in all "
                            f"(with every token minted from it); "
                            f"{spent.get(asset, 0)} is spent and this declares "
                            f"{amount} (spend and approvals)",
                        )
            if not draw:
                return bool(paid)
            for holder, _ in capped:
                spent = self._spent.setdefault(holder, {})
                for asset, amount in owed.items():
                    spent[asset] = spent.get(asset, 0) + amount
            if id_key is not None and capped:
                self._remember(id_key, paid, drawn)
        return bool(paid)

    def _remember(
        self, key: tuple[str, str, str], paid: dict[str, int], drawn: dict[str, int]
    ) -> None:
        """Record what a request id has drawn, keeping the most per asset."""
        merged = {**paid}
        for asset, amount in drawn.items():
            merged[asset] = max(amount, merged.get(asset, 0))
        self._drawn[key] = merged
        self._drawn.move_to_end(key)
        while len(self._drawn) > MAX_DRAWN_REQUEST_IDS:
            self._drawn.popitem(last=False)

    @staticmethod
    def _check_approvals(
        grant: TokenGrant, approvals: list[intent_module.IntentApproval]
    ) -> None:
        """Hold a capped token's declared approvals to its caps.

        An approval lets the spender move up to its amount later, outside any
        transaction this token sends, so it is held to the per-transaction and
        the per-session cap alike; a token with no cap may not be approved.
        """
        bounds: tuple[tuple[GrantRule, dict[str, int] | None], ...] = (
            ("token-cap-per-tx", grant.max_value_per_tx),
            ("token-cap-per-session", grant.max_value_per_session),
        )
        for rule, caps in bounds:
            if caps is None:
                continue
            for approval in approvals:
                token = intent_module.balance_key(approval["token"])
                if approval["amount"] > caps.get(token, 0):
                    raise GrantRefused(
                        rule,
                        f"this token may approve at most {caps.get(token, 0)} of "
                        f"{token} (the intent approves {approval['amount']})",
                    )


def is_replay(request: t.Any, action: str, request_id: str | None) -> bool:
    """Whether the MCP mount relieved this call's draw as a retry of `request_id`."""
    replays = getattr(getattr(request, "state", None), REPLAYS, None) or set()
    return request_id is not None and (action, request_id) in replays


def request_token(request: t.Any) -> str | None:
    """Return the bearer token the auth layer stamped on a request, if any.

    Both surfaces stamp it under AUTH_TOKEN: `RequireAuth` on an HTTP route's
    request, the MCP mount's middleware on the scope the tool's request reads.
    """
    return getattr(getattr(request, "state", None), AUTH_TOKEN, None)


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
        grants: GrantStore,
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
    ) -> None:
        """Initialize."""
        self._grants = grants
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
        grants: GrantStore,
        activity: ActivityLog,
        limiter: AuthFailureLimiter,
    ) -> None:
        """Initialize."""
        self._app = app
        self._grants = grants
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
        """Return a JSON-RPC error for the first tool call this token may not make.

        Each call relieved as a retry is added to `replays` as (tool, request id).
        """
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
            arguments = arguments if isinstance(arguments, dict) else {}
            name = str(params.get("name"))
            try:
                if self._grants.authorize(token, name, arguments):
                    replays.add((name, str(arguments["request_id"])))
            except GrantRefused as e:
                self._activity.record(
                    "refusal", rule=e.rule, tool=params.get("name"), reason=str(e)
                )
                return {
                    "jsonrpc": "2.0",
                    "id": call.get("id"),
                    "error": {"code": -32001, "message": e.message},
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
) -> bool:
    """Authorize an HTTP route's action against the request's token.

    Returns whether it was relieved as a retry (`GrantStore.authorize`).

    :raises HTTPException: 403 (401 for an expired token) naming the rule.
    """
    grants: GrantStore = request.app.state.grants
    try:
        return grants.authorize(getattr(request.state, AUTH_TOKEN), action, arguments)
    except GrantRefused as e:
        raise refused_route(request, activity, e) from e


def refused_route(
    request: Request, activity: ActivityLog, refused: GrantRefused
) -> HTTPException:
    """Audit an HTTP route's grant refusal and return the error that answers it."""
    activity.record(
        "refusal", rule=refused.rule, path=request.url.path, reason=str(refused)
    )
    return HTTPException(status_code=refused.status, detail=refused.message)
