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

"""The single signing choke point.

Every on-chain action of the Claude agent reduces to one EOA transaction that
Signer._send_guarded() checks (guard, then intent gate) and broadcasts — send()
and send_via_safe() are its two callers; off-chain mech requests use
Signer.sign_digest(). The key never leaves this module's LocalAccount.
"""

import hashlib
import logging
import re
import threading
import typing as t
from dataclasses import dataclass
from functools import partial

from aea_ledger_ethereum.rpc_rotation import RotatingHTTPProvider, parse_rpc_urls
from eth_abi.exceptions import EncodingError
from eth_account.signers.local import LocalAccount
from eth_typing import Hash32
from web3 import Web3
from web3.exceptions import ContractLogicError, Web3RPCError
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware
from web3.types import TxParams

from connect import intent as intent_module
from connect import safe as safe_module
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard, GuardError

logger = logging.getLogger("agent")

GAS_ESTIMATE_BUFFER = 1.2


class SignerError(Exception):
    """Signing or broadcast failure."""


class SendUnknown(SignerError):
    """A broadcast the RPC never answered: it may have landed, as `tx_hash`.

    The hash is the signed bytes', known before the broadcast, so the request
    id it was sent under keeps it: a retry replays it rather than signing a
    second transaction at the next nonce.
    """

    def __init__(self, tx_hash: str) -> None:
        """Initialize."""
        super().__init__(SEND_UNKNOWN)
        self.tx_hash = tx_hash


class _ServerBuilt:
    """Marks a transaction the server built itself, which the intent gate skips.

    The mech flow and the agent top-up build their own transactions, already
    bounded by their own caps and, while restricted, by single-use guard
    allowances; no session intent describes them. This is a private object, so
    no request body or tool argument can produce it: every agent surface
    reaches the gate.
    """

    def __repr__(self) -> str:
        """Repr."""
        return "SERVER_BUILT"


SERVER_BUILT = _ServerBuilt()


class _GateRefused(Exception):
    """A call the intent gate refuses before simulating it: `problem` says why."""

    def __init__(self, rule: intent_module.Rule, detail: str) -> None:
        """Initialize."""
        super().__init__(rule, detail)
        self.problem = intent_module.Problem(rule=rule, detail=detail)


GateFactory = t.Callable[[], "_GateCall"]


@dataclass(frozen=True)
class _GateCall:
    """The call the intent gate simulates: what `sender` itself does."""

    sender: str
    to: str
    value: int
    data: str


@dataclass
class _ChainState:
    w3: Web3
    lock: threading.Lock
    chain_id: int
    next_nonce: int | None = None  # local counter; None until first send


class _ChainPool:
    """Lazily-built per-chain Web3 clients with their nonce locks."""

    def __init__(self, config: AppConfig) -> None:
        """Initialize."""
        self._config = config
        self._lock = threading.Lock()
        self._states: dict[str, _ChainState] = {}

    def get(self, chain: str) -> _ChainState:
        """Return (building on first use) the state for a configured chain."""
        chain = chain.lower()
        with self._lock:
            state = self._states.get(chain)
        if state is not None:
            return state
        # build outside the pool lock: the chain_id fetch is a network
        # round-trip and must not stall first use of unrelated chains
        chain_config = self._config.chain(chain)  # raises on unknown chain
        w3 = Web3(
            RotatingHTTPProvider(
                parse_rpc_urls(chain_config.rpc_url),
                request_kwargs={"timeout": 30},
            )
        )
        # PoA chains (Polygon above all) pad extraData past 32 bytes, which
        # web3's default block formatter refuses — making every send there
        # fail at fee estimation. The middleware is a no-op on non-PoA chains.
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        state = _ChainState(w3=w3, lock=threading.Lock(), chain_id=w3.eth.chain_id)
        with self._lock:
            # a racing builder may have won; one state per chain must survive
            # or two nonce counters would fight over the same account
            return self._states.setdefault(chain, state)


MAX_CACHED_RESULTS = 1024


def _same_call(key: str, cached: tuple[str, str], stamp: str) -> str:
    """Return the cached tx hash, or :raises SignerError: on a different call."""
    tx_hash, seen = cached
    if seen != stamp:
        raise SignerError(
            f"request id '{key}' was already used for a different call; "
            "choose a new id rather than replaying this one, which would "
            "report a transaction that was never sent for it"
        )
    return tx_hash


def _call_stamp(chain: str, to: str, value: int, data: str) -> str:
    """Fingerprint the call a request id stands for."""
    raw = "\x1f".join((chain.lower(), to.lower(), str(value), (data or "0x").lower()))
    return hashlib.sha256(raw.encode()).hexdigest()


# What a caller is told of a failure that is not one of Connect's refusals:
# Connect's own words, never the library's, which may name the RPC URL and its
# key (urllib3 writes "with url: /v2/<key>"); the cause goes to the log.
SEND_FAILED = (
    "send failed: the RPC could not take the transaction (the cause is in "
    "Connect's log)"
)
# the broadcast itself failed with no answer from the RPC: it may have landed
SEND_UNKNOWN = (
    "send failed while broadcasting: the transaction may have been sent (the "
    "cause is in Connect's log); a retry with the same request_id answers its "
    "tx_hash without sending again, otherwise check the account's nonce "
    "before sending again"
)
COMPOSE_FAILED = (
    "cannot compose the safe call: the target must be an address, the value a "
    "whole amount and the data hex"
)


def _send_failure(error: Exception, *, broadcasting: bool) -> str:
    """Return what a caller is told of a failed send.

    A revert in gas estimation is the contract's own answer, so its reason
    stays (the shipped client reads it as reverted before signing). A
    broadcast that failed without the RPC's answer (a timeout, a dropped
    connection) is SEND_UNKNOWN; anything else is SEND_FAILED.
    """
    if isinstance(error, ContractLogicError):
        reason = str(error.message or "execution reverted")
        if "execution reverted" not in reason:
            reason = f"execution reverted: {reason}"
        return f"send failed: {reason}"
    if broadcasting and not isinstance(error, (Web3RPCError, ValueError)):
        return SEND_UNKNOWN
    return SEND_FAILED


def _safe_request_key(request_id: str) -> str:
    """Return send_via_safe's idempotency key: its own namespace, apart from send's.

    The same id on the EOA path is a different logical action and must not
    collide with it.
    """
    return f"safe:{request_id}"


# strict: bytes.fromhex would skip whitespace, and the raw string goes on
_HEX_CALLDATA = re.compile(r"(0[xX])?[0-9a-fA-F]*")


def _calldata_problem(data: str) -> intent_module.Problem | None:
    """Return the bad-calldata problem for calldata that is not hex, else None.

    Checked before anything reaches the RPC, so a caller's typo is refused as
    one rather than as the RPC failing to simulate it.
    """
    raw = data or ""
    if _HEX_CALLDATA.fullmatch(raw) and len(safe_module.calldata_hex(raw)) % 2 == 0:
        return None
    return intent_module.Problem(
        rule="bad-calldata",
        detail="cannot decode the calldata: it must be hex of whole bytes, "
        "0x-prefixed or bare, with nothing else in it (no spaces)",
    )


class _IdempotencyCache:
    """At-most-once execution of actions keyed by caller-chosen request ids."""

    def __init__(self, max_results: int = MAX_CACHED_RESULTS) -> None:
        """Initialize."""
        self._lock = threading.Lock()
        self._max_results = max_results
        self._results: dict[str, tuple[str, str]] = {}  # id -> (tx_hash, stamp)
        self._in_flight: set[str] = set()  # request_ids currently executing

    def run(self, key: str, stamp: str, action: t.Callable[[], str]) -> str:
        """Run action at most once per key.

        A completed key returns its cached result; a key whose action is still
        executing raises (the caller retries after the original settles); a
        failed attempt releases the key so a retry can run the action again,
        except a broadcast that may have landed (`SendUnknown`), whose hash is
        kept as the key's result so a retry replays it.

        :raises SignerError: when the key was used for a different call.
        """
        with self._lock:
            cached = self._results.get(key)
            if cached is not None:
                return _same_call(key, cached, stamp)
            if key in self._in_flight:
                raise SignerError(
                    f"request '{key}' is already in flight; retry shortly"
                )
            self._in_flight.add(key)
        return self._execute(key, stamp, action)

    def cached(self, key: str, stamp: str) -> str | None:
        """Return the result of a completed run of this key, if any.

        :raises SignerError: when the key was used for a different call.
        """
        with self._lock:
            cached = self._results.get(key)
        return None if cached is None else _same_call(key, cached, stamp)

    def holds(self, key: str) -> bool:
        """Whether a run of this key completed or is running: a new run sends nothing."""
        with self._lock:
            return key in self._results or key in self._in_flight

    def _execute(self, key: str, stamp: str, action: t.Callable[[], str]) -> str:
        try:
            result = action()
        except SendUnknown as e:
            # it may have landed: re-running would sign a second transaction
            # at the next nonce, so a retry replays this hash instead and the
            # receipt read settles whether it was mined
            self._store(key, stamp, e.tx_hash)
            raise
        except Exception:
            with self._lock:
                self._in_flight.discard(key)
            raise
        self._store(key, stamp, result)
        return result

    def _store(self, key: str, stamp: str, result: str) -> None:
        # cache the result and release the reservation atomically, so no retry
        # can observe "not cached and not in flight" after a success
        with self._lock:
            self._results[key] = (result, stamp)
            self._in_flight.discard(key)
            # bound memory over a long run: a request_id evicted here and
            # retried much later re-broadcasts, which is the right trade at
            # that distance — retries cluster within seconds of the original
            while len(self._results) > self._max_results:
                del self._results[next(iter(self._results))]


class Signer:
    """Signer."""

    def __init__(
        self,
        account: LocalAccount,
        config: AppConfig,
        activity: ActivityLog,
        guard: Guard | None = None,
    ) -> None:
        """Initialize."""
        self._account = account
        self._activity = activity
        self._config = config
        self._chains = _ChainPool(config)
        self._requests = _IdempotencyCache()
        self._guard = guard

    def set_guard(self, guard: Guard) -> None:
        """Attach the guardrail; the boot path passes it to the constructor."""
        self._guard = guard

    @property
    def address(self) -> str:
        """Address."""
        return self._account.address

    def holds_request(self, request_id: str, via_safe: bool) -> bool:
        """Whether a send under this request id completed or is still sending.

        Either way a call repeating it sends nothing new: it replays the hash,
        or is refused as in flight. `via_safe` picks send_via_safe's namespace.
        """
        return self._requests.holds(
            _safe_request_key(request_id) if via_safe else request_id
        )

    def w3(self, chain: str) -> Web3:
        """W3."""
        return self._chains.get(chain).w3

    def send(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        to: str,
        *,
        value: int = 0,
        data: str = "0x",
        request_id: str | None = None,
        gas: int | None = None,
        audit: bool = True,
        intent: t.Any = None,
        replay_only: bool = False,
    ) -> str:
        """Fill, sign and broadcast one EOA transaction; returns the tx hash.

        With a request_id the call is idempotent: repeating a completed send
        returns the original tx hash without rebroadcasting. audit=False is for
        a caller that audits the outcome itself, under its own kind. `intent`
        is what the transaction may do; a value-moving one without it is
        refused (`SERVER_BUILT` is for the server's own transactions).
        `replay_only` answers only from the request id's completed send (see
        `_send_guarded`).
        """
        return self._send_guarded(
            chain,
            to,
            value=value,
            data=data,
            request_id=request_id,
            gas=gas,
            audit=audit,
            gate=lambda: self._eoa_gate(chain, to, value, data),
            intent=intent,
            replay_only=replay_only,
        )

    def _send_guarded(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        chain: str,
        to: str,
        *,
        value: int,
        data: str,
        request_id: str | None,
        gas: int | None,
        audit: bool,
        gate: GateFactory,
        intent: t.Any,
        replay_only: bool = False,
    ) -> str:
        """Replay, guard, intent gate, then broadcast: the one path to signing.

        `gate` builds the call the intent gate simulates, after the guard has
        answered, so a gate refusal and a guard refusal are audited alike.
        Only `SERVER_BUILT`, a private object no request body can produce,
        skips the gate. `replay_only` is a retry whose token draw was spared
        because the id was held: it is answered from the id's completed send
        or refused, never sent fresh, since the hold may have ended since.
        """
        if replay_only and request_id is None:
            raise SignerError("a replay-only send needs the request id it replays")
        stamp = _call_stamp(chain, to, value, data)
        if request_id is not None:
            # a completed send stays answerable even if the guardrail has
            # tightened since — the transaction already happened; nothing
            # new is signed by returning its hash again
            cached = self._requests.cached(request_id, stamp)
            if cached is not None:
                return cached
            if replay_only:
                self._refuse_lost_replay(request_id)
        self._check_transaction(chain=chain, to=to, value=value, data=data, audit=audit)
        if intent is not SERVER_BUILT:
            # after the guard, so the cheap static rules answer first and the
            # simulation only ever runs on a call the guard already permits
            gated_to, gated_value = to, value
            try:
                call = gate()
                gated_to, gated_value = call.to, call.value
                problems = self._gate_problems(chain, call, intent)
            except _GateRefused as e:
                problems = [e.problem]
            if problems:
                self._refuse(chain, gated_to, gated_value, problems, audit=audit)

        def broadcast() -> str:
            return self._send(
                chain=chain,
                to=to,
                value=value,
                data=data,
                gas=gas,
                request_id=request_id,
                audit=audit,
            )

        if request_id is None:
            return broadcast()
        return self._requests.run(request_id, stamp, broadcast)

    def _refuse_lost_replay(self, request_id: str) -> t.NoReturn:
        """Refuse a spared retry that has no completed send to answer from."""
        if self._requests.holds(request_id):
            raise SignerError(
                f"request '{request_id}' is already in flight; retry shortly"
            )
        raise SignerError(
            f"request '{request_id}' was authorized as a retry of a send that has "
            "since failed (or whose result was forgotten); nothing was sent for "
            "this retry. Retry again to send "
            "it, which is charged as a new send"
        )

    def _refuse(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        to: str,
        value: int,
        problems: list[intent_module.Problem],
        *,
        audit: bool,
    ) -> t.NoReturn:
        """Audit a gate refusal (unless the caller audits its own), then raise it."""
        if audit:
            self._activity.record(
                "refusal",
                chain=chain,
                to=to,
                value=str(value),
                rule=problems[0]["rule"],
                rules=[p["rule"] for p in problems],
                reason=intent_module.refusal_message(problems),
            )
        raise SignerError(intent_module.refusal_message(problems))

    def _compose_safe_call(
        self, chain: str, target: str, value: int, data: str
    ) -> tuple[str, str]:
        """Wrap one inner call for the safe; returns (safe address, calldata).

        One home for the composition so the send and the dry run cannot answer
        about different bytes, and one home for the two refusals so their
        wording cannot drift apart.

        :raises SignerError: no safe on this chain, or the call cannot encode.
        """
        safe = self._config.chain(chain).safe_address
        if safe is None:
            raise SignerError(
                f"no service safe is configured for chain '{chain}', so the "
                "agent cannot act there"
            )
        try:
            calldata = safe_module.exec_transaction(
                target=target, value=value, data=data, owner=self.address
            )
        except (EncodingError, ValueError, TypeError, OverflowError) as e:
            # composition fails on the caller's input, not the chain — a 400, the
            # same answer send() gives for a malformed EOA transaction, not a 500
            raise SignerError(COMPOSE_FAILED) from e
        return safe, calldata

    def send_via_safe(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        target: str,
        *,
        value: int = 0,
        data: str = "0x",
        request_id: str | None = None,
        gas: int | None = None,
        audit: bool = True,
        intent: t.Any = None,
        replay_only: bool = False,
    ) -> str:
        """Act as the service safe: wrap one inner call and send it.

        `target`, `value` and `data` are the call the *safe* makes — most carry
        no value at all (an approve, a stake, a claim); any they do carry leaves
        the safe rather than the EOA. The distinct parameter name is deliberate:
        this is not send()'s outer recipient, and the two must not be confused.

        The composed transaction goes through _send_guarded(), the one path
        send() takes too, so it meets the same guard and intent gate as
        anything else — a caller of the gate, not a way around it.
        """
        problem = _calldata_problem(data)
        if problem is not None:  # composing it would fail on the same bytes
            self._refuse(chain, target, value, [problem], audit=audit)
        safe, calldata = self._compose_safe_call(chain, target, value, data)
        return self._send_guarded(
            chain,
            safe,
            value=0,  # the outer transaction carries none; the safe pays
            data=calldata,
            request_id=None if request_id is None else _safe_request_key(request_id),
            gas=gas,
            audit=audit,
            # the gate simulates the call the safe makes, as the safe: that is
            # whose assets move, and what the intent describes
            gate=lambda: _GateCall(sender=safe, to=target, value=value, data=data),
            intent=intent,
            replay_only=replay_only,
        )

    def _eoa_gate(self, chain: str, to: str, value: int, data: str) -> _GateCall:
        """Return the call to gate for an EOA send: the safe's, for its execTransaction.

        An EOA transaction to the configured safe carrying execTransaction
        moves the safe's assets, so the gate simulates the call inside it, as
        the safe; to anything else, the EOA's own call is what runs.

        :raises _GateRefused: what the gate cannot hold to an intent — the
            safe's approveHash (it pre-approves a transaction by hash, which
            anyone may then execute), and an execTransaction that also carries
            EOA value, pays a gas refund or is not a CALL.
        """
        calldata = safe_module.calldata_hex(data)
        if calldata.startswith(safe_module.APPROVE_HASH_SELECTOR):
            raise _GateRefused(
                "approve-hash",
                "approveHash pre-approves a safe transaction by its hash, which "
                "the intent gate cannot see; act as the safe with "
                "safe_transaction instead",
            )
        safe = self._config.chain(chain).safe_address
        own = _GateCall(sender=self.address, to=to, value=value, data=data)
        if (
            safe is None
            or to.lower() != safe.lower()
            or not safe_module.is_exec_transaction(data)
        ):
            return own
        try:
            exec_call = safe_module.SafeExec.decode(data)
        except ValueError as e:
            raise _GateRefused("bad-exec-transaction", str(e)) from e
        if value:
            raise _GateRefused(
                "bad-exec-transaction",
                "an execTransaction to a safe may not also carry value from the "
                "EOA; send the value as part of the safe's own call",
            )
        if exec_call.operation != safe_module.OPERATION_CALL:
            raise _GateRefused(
                "bad-exec-transaction",
                "an execTransaction may only CALL (operation 0), never DELEGATECALL",
            )
        if exec_call.pays_refund:
            raise _GateRefused(
                "bad-exec-transaction",
                "an execTransaction may not pay a gas refund: gasPrice, gasToken "
                "and refundReceiver must be zero (safe_transaction sets them so)",
            )
        return _GateCall(
            sender=safe, to=exec_call.to, value=exec_call.value, data=exec_call.data
        )

    def _simulate(self, chain: str, call: _GateCall) -> intent_module.AssetDiff:
        """Simulate one call at head over the chain's RPC.

        :raises intent_module.SimulationUnavailable: the RPC cannot simulate.
        """
        self._config.chain(chain)  # ValueError: an unknown chain is the caller's
        try:
            w3 = self.w3(chain)
        except Exception as e:  # pylint: disable=broad-exception-caught
            # the client is built on first use, and that needs the RPC too: a
            # garbled eth_chainId answer is a ValueError, and still the RPC's
            raise intent_module.SimulationUnavailable(str(e)) from e

        def rpc(method: str, params: list) -> t.Any:
            try:
                response = w3.provider.make_request(t.cast(t.Any, method), params)
            except Exception as e:  # pylint: disable=broad-exception-caught
                raise intent_module.SimulationUnavailable(str(e)) from e
            if "error" in response or "result" not in response:
                raise intent_module.SimulationUnavailable(
                    str(response.get("error", "no result in the answer"))
                )
            return response["result"]

        def get_code(address: str) -> bytes:
            try:
                return bytes(w3.eth.get_code(Web3.to_checksum_address(address)))
            except Exception as e:  # pylint: disable=broad-exception-caught
                raise intent_module.SimulationUnavailable(str(e)) from e

        return intent_module.simulate(
            rpc,
            sender=call.sender,
            to=call.to,
            value=call.value,
            data=call.data or "0x",
            get_code=get_code,
        )

    def _evaluate(
        self, chain: str, call: _GateCall, raw_intent: t.Any
    ) -> tuple[intent_module.AssetDiff | None, intent_module.Intent | None, list]:
        """Simulate a call and check it: (diff, parsed intent, problems).

        The one path the send-time gate and simulate_transaction share, so the
        two cannot answer differently about the same call.
        """
        problem = _calldata_problem(call.data)
        if problem is not None:
            return None, None, [problem]
        parsed, problems = intent_module.parse_intent(raw_intent)
        if problems:
            return None, None, problems
        try:
            diff = self._simulate(chain, call)
        except intent_module.SimulationUnavailable:
            # every agent send on this chain is refused until it can simulate:
            # log.txt must say why, including when the cause is our own code
            logger.error(
                "intent gate cannot simulate on %s (%s -> %s)",
                chain,
                call.sender,
                call.to,
                exc_info=True,
            )
            return (
                None,
                parsed,
                [
                    intent_module.Problem(
                        rule="simulation-unavailable",
                        detail=f"the RPC for '{chain}' cannot simulate this call, "
                        "so it is not signed unchecked (the cause is in Connect's log)",
                    )
                ],
            )
        return diff, parsed, intent_module.check_intent(diff, parsed)

    def _gate_problems(
        self, chain: str, call: _GateCall, raw_intent: t.Any
    ) -> list[intent_module.Problem]:
        """Every intent-gate rule this call breaks, simulating it at head."""
        return self._evaluate(chain, call, raw_intent)[2]

    def simulate(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        target: str,
        *,
        value: int = 0,
        data: str = "0x",
        via_safe: bool = True,
        intent: t.Any = None,
    ) -> dict:
        """Simulate a call at head and report its asset diff and intent verdict."""
        sender = self._sender(chain, via_safe)  # no safe / unknown chain refused
        if via_safe:
            call = _GateCall(sender=sender, to=target, value=value, data=data)
        else:
            try:
                call = self._eoa_gate(chain, target, value, data)
            except _GateRefused as e:
                return {"fits_intent": False, "problems": [e.problem]}
        diff, parsed, problems = self._evaluate(chain, call, intent)
        if diff is None:
            return {"fits_intent": False, "problems": problems}
        return {
            **diff,
            "fits_intent": None if parsed is None else not problems,
            "problems": problems,
        }

    def _sender(self, chain: str, via_safe: bool) -> str:
        """Whose call it is: the chain's safe, or the agent EOA."""
        if not via_safe:
            self._config.chain(chain)  # raises on an unknown chain
            return self.address
        safe = self._config.chain(chain).safe_address
        if safe is None:
            raise SignerError(
                f"no service safe is configured for chain '{chain}', so the "
                "agent cannot act there"
            )
        return safe

    def refusal_reason(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        target: str,
        *,
        value: int = 0,
        data: str = "0x",
        via_safe: bool = True,
        intent: t.Any = None,
    ) -> str | None:
        """Say why the call would be refused, or None if it passes."""
        reason, _ = self.check(
            chain, target, value=value, data=data, via_safe=via_safe, intent=intent
        )
        return reason

    def check(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        chain: str,
        target: str,
        *,
        value: int = 0,
        data: str = "0x",
        via_safe: bool = True,
        intent: t.Any = None,
    ) -> tuple[str | None, list[intent_module.Problem]]:
        """Ask the guardrail, then the intent gate, consuming and signing nothing.

        Returns the refusal (None if the call passes) and the gate's problems.
        """
        probed_target, probed_value = target, value
        problems: list[intent_module.Problem] = []
        try:
            self._config.chain(chain)
        except ValueError as e:  # an unknown chain
            reason: str | None = str(e)
        else:
            try:
                self._sender(chain, via_safe)  # no safe / unknown chain refused
                safe = t.cast(str, self._config.chain(chain).safe_address)
                # built after the guard has answered, as the send builds it
                gate: GateFactory = (
                    partial(_GateCall, sender=safe, to=target, value=value, data=data)
                    if via_safe
                    else partial(self._eoa_gate, chain, target, value, data)
                )
                problem = _calldata_problem(data)
                if problem is not None:  # as the send refuses it, before the RPC
                    problems = [problem]
                    raise SignerError(intent_module.refusal_message(problems))
                if via_safe:
                    target, data = self._compose_safe_call(chain, target, value, data)
                    value = 0
                elif value < 0:
                    raise SignerError("value must be a non-negative amount in wei")
                reason = self._refused_by_guard(chain, target, value, data)
                if reason is None:
                    try:
                        problems = self._gate_problems(chain, gate(), intent)
                    except _GateRefused as e:
                        problems = [e.problem]
                    if problems:
                        reason = intent_module.refusal_message(problems)
            except SignerError as e:
                reason = str(e)
        self._activity.record(
            "checked",
            chain=chain,
            to=target,
            value=str(value),
            allowed=reason is None,
            reason=reason,
            probed_target=probed_target,
            probed_value=str(probed_value),
            via_safe=via_safe,
        )
        return reason, problems

    def _refused_by_guard(
        self, chain: str, to: str, value: int, data: str
    ) -> str | None:
        """Ask the guardrail about a composed transaction, consuming nothing."""
        if self._guard is None:
            logger.error(
                "the signing choke point has no guardrail attached; every "
                "request would be permitted"
            )
            return None
        try:
            self._guard.check_transaction(chain, to, value, data, consume=False)
        except GuardError as e:
            return str(e)
        return None

    def _send(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        to: str,
        *,
        value: int,
        data: str,
        gas: int | None,
        request_id: str | None,
        audit: bool,
    ) -> str:
        """Fill, sign and broadcast under the chain's nonce lock."""
        state = self._chains.get(chain)
        with state.lock:
            signed = None
            try:
                tx = self._fill_transaction(
                    state, to=to, value=value, data=data, gas=gas
                )
                signed = self._account.sign_transaction(tx)
                tx_hash = state.w3.eth.send_raw_transaction(
                    signed.raw_transaction
                ).to_0x_hex()
            except Exception as e:
                # covers gas-estimation reverts (the common failure), RPC and
                # signing errors — all must surface as a structured SignerError.
                # A failure may also mean the local nonce counter is wrong
                # (e.g. "nonce too low" after a pool drop): forget it so the
                # next send resyncs from the node's pending count.
                state.next_nonce = None
                if audit:
                    self._activity.record(
                        "send_failed",
                        chain=chain,
                        to=to,
                        value=str(value),
                        error=str(e),
                    )
                logger.warning("send on %s to %s failed", chain, to, exc_info=True)
                said = _send_failure(e, broadcasting=signed is not None)
                if signed is not None and said == SEND_UNKNOWN:
                    raise SendUnknown(signed.hash.to_0x_hex()) from e
                raise SignerError(said) from e
            state.next_nonce = tx["nonce"] + 1
        if audit:
            self._activity.record(
                "transaction",
                chain=chain,
                to=to,
                value=str(value),
                data_size=len(safe_module.calldata_hex(data)) // 2,
                tx_hash=tx_hash,
                request_id=request_id,
            )
        return tx_hash

    def _fill_transaction(
        self, state: _ChainState, *, to: str, value: int, data: str, gas: int | None
    ) -> dict:
        w3 = state.w3
        pending = w3.eth.get_transaction_count(self._account.address, "pending")
        nonce = pending if state.next_nonce is None else max(state.next_nonce, pending)
        tx: dict = {
            "chainId": state.chain_id,
            "from": self._account.address,
            "to": Web3.to_checksum_address(to),
            "value": value,
            "data": data or "0x",
            "nonce": nonce,
        }
        if gas is None:
            gas = int(w3.eth.estimate_gas(t.cast(TxParams, tx)) * GAS_ESTIMATE_BUFFER)
        tx["gas"] = gas

        latest = w3.eth.get_block("latest")
        base_fee = latest.get("baseFeePerGas")
        if base_fee is not None:
            try:
                tip = w3.eth.max_priority_fee
            except Exception:  # pylint: disable=broad-exception-caught
                tip = w3.to_wei(1, "gwei")
            tx["maxPriorityFeePerGas"] = tip
            tx["maxFeePerGas"] = base_fee * 2 + tip
        else:
            tx["gasPrice"] = w3.eth.gas_price
        return tx

    def _check_transaction(  # pylint: disable=too-many-arguments
        self, *, chain: str, to: str, value: int, data: str, audit: bool
    ) -> None:
        """Consult the guardrail; a denial is audited and surfaced as SignerError."""
        if self._guard is None:
            return
        try:
            self._guard.check_transaction(chain, to, value, data)
        except GuardError as e:
            if audit:
                self._activity.record(
                    "blocked",
                    action="send",
                    chain=chain,
                    to=to,
                    value=str(value),
                    reason=str(e),
                )
            raise SignerError(str(e)) from e

    def sign_digest(self, digest: bytes) -> str:
        """Sign a raw 32-byte digest (no EIP-191 prefix); returns 0x-hex 65-byte signature.

        The caller passes the exact 32 bytes to be signed and this signs them
        unprefixed. For off-chain mech requests that is the safe's ERC-1271
        SafeMessage hash (agent mode), which the marketplace verifies via
        Safe.isValidSignature — the wrapping is the mech flow's job, not this
        method's; here the digest is opaque and the guard gates it.
        """
        if self._guard is not None:
            try:
                self._guard.check_sign_digest(digest)
            except GuardError as e:
                self._activity.record("blocked", action="sign_digest", reason=str(e))
                raise SignerError(str(e)) from e
        if len(digest) != 32:
            raise SignerError(f"digest must be exactly 32 bytes, got {len(digest)}")
        signature = self._account.unsafe_sign_hash(
            t.cast(Hash32, digest)
        ).signature.to_0x_hex()
        self._activity.record("sign_message", digest="0x" + digest.hex())
        return signature
