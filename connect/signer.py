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

Every on-chain action of the Claude agent reduces to one EOA transaction sent
through Signer.send(); off-chain mech requests use Signer.sign_digest(). The
key never leaves this module's LocalAccount.
"""

import logging
import threading
import typing as t
from dataclasses import dataclass

from aea_ledger_ethereum.rpc_rotation import RotatingHTTPProvider, parse_rpc_urls
from eth_abi.exceptions import EncodingError
from eth_account.signers.local import LocalAccount
from eth_typing import Hash32
from web3 import Web3
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware
from web3.types import TxParams

from connect import safe as safe_module
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard, GuardError

logger = logging.getLogger("agent")

GAS_ESTIMATE_BUFFER = 1.2


class SignerError(Exception):
    """Signing or broadcast failure."""


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


class _IdempotencyCache:
    """At-most-once execution of actions keyed by caller-chosen request ids."""

    def __init__(self, max_results: int = MAX_CACHED_RESULTS) -> None:
        """Initialize."""
        self._lock = threading.Lock()
        self._max_results = max_results
        self._results: dict[str, str] = {}  # request_id -> tx_hash, insertion-ordered
        self._in_flight: set[str] = set()  # request_ids currently executing

    def run(self, key: str, action: t.Callable[[], str]) -> str:
        """Run action at most once per key.

        A completed key returns its cached result; a key whose action is still
        executing raises (the caller retries after the original settles); a
        failed attempt releases the key so a retry can run the action again.
        """
        with self._lock:
            cached = self._results.get(key)
            if cached:
                return cached
            if key in self._in_flight:
                raise SignerError(
                    f"request '{key}' is already in flight; retry shortly"
                )
            self._in_flight.add(key)
        return self._execute(key, action)

    def cached(self, key: str) -> str | None:
        """Return the result of a completed run of this key, if any."""
        with self._lock:
            return self._results.get(key)

    def _execute(self, key: str, action: t.Callable[[], str]) -> str:
        try:
            result = action()
        except Exception:
            with self._lock:
                self._in_flight.discard(key)
            raise
        # cache the result and release the reservation atomically, so no retry
        # can observe "not cached and not in flight" after a success
        with self._lock:
            self._results[key] = result
            self._in_flight.discard(key)
            # bound memory over a long run: a request_id evicted here and
            # retried much later re-broadcasts, which is the right trade at
            # that distance — retries cluster within seconds of the original
            while len(self._results) > self._max_results:
                del self._results[next(iter(self._results))]
        return result


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
    ) -> str:
        """Fill, sign and broadcast one EOA transaction; returns the tx hash.

        With a request_id the call is idempotent: repeating a completed send
        returns the original tx hash without rebroadcasting.
        """
        if request_id is not None:
            # a completed send stays answerable even if the guardrail has
            # tightened since — the transaction already happened; nothing
            # new is signed by returning its hash again
            cached = self._requests.cached(request_id)
            if cached is not None:
                return cached
        self._check_transaction(chain=chain, to=to, value=value, data=data)

        def broadcast() -> str:
            return self._send(
                chain=chain,
                to=to,
                value=value,
                data=data,
                gas=gas,
                request_id=request_id,
            )

        if request_id is None:
            return broadcast()
        return self._requests.run(request_id, broadcast)

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
            raise SignerError(f"cannot compose the safe call: {e}") from e
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
    ) -> str:
        """Act as the service safe: wrap one inner call and send it.

        `target`, `value` and `data` are the call the *safe* makes — most carry
        no value at all (an approve, a stake, a claim); any they do carry leaves
        the safe rather than the EOA. The distinct parameter name is deliberate:
        this is not send()'s outer recipient, and the two must not be confused.

        The composed transaction goes back through send(), so it meets the same
        guard as anything else — a caller of the gate, not a way around it.
        """
        safe, calldata = self._compose_safe_call(chain, target, value, data)
        return self.send(
            chain,
            safe,
            value=0,  # the outer transaction carries none; the safe pays
            data=calldata,
            # the safe path keeps its own idempotency namespace: the same id on
            # the EOA path is a different logical action and must not collide
            request_id=None if request_id is None else f"safe:{request_id}",
            gas=gas,
        )

    def refusal_reason(
        self,
        chain: str,
        target: str,
        *,
        value: int = 0,
        data: str = "0x",
        via_safe: bool = True,
    ) -> str | None:
        """Say why the guardrail would refuse this call, or None if it passes.

        The answer has to be about the bytes the send would really produce, so
        this composes through _compose_safe_call exactly as send_via_safe does
        rather than checking the inner call on its own — the floor rules are
        about the wrapper, and an unwrapped guess would answer a different
        question.

        Nothing is signed or broadcast, and no single-use allowance is consumed:
        asking must never cost anything or change what a later send is allowed
        to do. It is recorded as `checked`, never as `blocked` — a request that
        was actually stopped and a question about one are different events, and
        an operator reconstructing an incident needs to tell them apart.
        """
        try:
            if via_safe:
                target, data = self._compose_safe_call(chain, target, value, data)
                value = 0
            elif value < 0:
                # send() rejects this before the guard ever sees it, and the dry
                # run must not answer "allowed" for a call that cannot be sent
                raise SignerError("value must be a non-negative amount in wei")
            reason = self._refused_by_guard(chain, target, value, data)
        except SignerError as e:
            reason = str(e)
        except ValueError as e:  # an unknown chain, which config.chain() raises on
            reason = str(e)
        self._activity.record(
            "checked",
            chain=chain,
            to=target,
            value=str(value),
            allowed=reason is None,
            reason=reason,
        )
        return reason

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
    ) -> str:
        """Fill, sign and broadcast under the chain's nonce lock."""
        state = self._chains.get(chain)
        with state.lock:
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
                self._activity.record(
                    "send_failed", chain=chain, to=to, value=str(value), error=str(e)
                )
                raise SignerError(f"send failed: {e}") from e
            state.next_nonce = tx["nonce"] + 1
        self._activity.record(
            "transaction",
            chain=chain,
            to=to,
            value=str(value),
            data_size=len((data or "0x").removeprefix("0x")) // 2,
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

    def _check_transaction(self, *, chain: str, to: str, value: int, data: str) -> None:
        """Consult the guardrail; a denial is audited and surfaced as SignerError."""
        if self._guard is None:
            return
        try:
            self._guard.check_transaction(chain, to, value, data)
        except GuardError as e:
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
