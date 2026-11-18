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

"""At-most-once sends keyed by a caller's request id, split out of `signer.py`.

`IdempotencyCache` keeps each request id's hash with a stamp of the call it
stood for, so a retry answers the same hash and a reused id cannot answer a
different call; a broadcast the RPC never answered is kept unconfirmed, so a
retry raises it again rather than signing at the next nonce.
"""

import hashlib
import threading
import typing as t

from connect.signer_errors import SendUnknown, SignerError

MAX_CACHED_RESULTS = 1024


class Sent(t.NamedTuple):
    """What a request id's send left: its hash, and whether the RPC took it."""

    tx_hash: str
    stamp: str
    # False for a broadcast the RPC never answered (SendUnknown)
    confirmed: bool


def _same_call(key: str, cached: Sent, stamp: str) -> str:
    """Return the cached tx hash.

    :raises SignerError: on a different call.
    :raises SendUnknown: again, for a broadcast that may not have landed.
    """
    if cached.stamp != stamp:
        raise SignerError(
            f"request id '{key}' was already used for a different call; "
            "choose a new id rather than replaying this one, which would "
            "report a transaction that was never sent for it"
        )
    if not cached.confirmed:
        raise SendUnknown(cached.tx_hash, held=True)
    return cached.tx_hash


def call_stamp(chain: str, to: str, value: int, data: str) -> str:
    """Fingerprint the call a request id stands for."""
    raw = "\x1f".join((chain.lower(), to.lower(), str(value), (data or "0x").lower()))
    return hashlib.sha256(raw.encode()).hexdigest()


def safe_request_key(request_id: str) -> str:
    """Return send_via_safe's idempotency key: its own namespace, apart from send's.

    The same id on the EOA path is a different logical action and must not
    collide with it.
    """
    return f"safe:{request_id}"


class IdempotencyCache:
    """At-most-once execution of actions keyed by caller-chosen request ids."""

    def __init__(self, max_results: int = MAX_CACHED_RESULTS) -> None:
        """Initialize."""
        self._lock = threading.Lock()
        self._max_results = max_results
        self._results: dict[str, Sent] = {}
        self._in_flight: set[str] = set()  # request_ids currently executing

    def run(self, key: str, stamp: str, action: t.Callable[[], str]) -> str:
        """Run action at most once per key.

        A completed key returns its cached result; a key whose action is still
        executing raises (the caller retries after the original settles); a
        failed attempt releases the key so a retry can run the action again,
        except a broadcast that may have landed (`SendUnknown`), whose hash is
        kept as the key's unconfirmed result so a retry raises it again.

        :raises SignerError: when the key was used for a different call.
        :raises SendUnknown: for a key whose broadcast may not have landed.
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
        :raises SendUnknown: for a key whose broadcast may not have landed.
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
            # at the next nonce, so a retry raises this hash again instead,
            # never as a confirmed send, and its receipt settles whether it
            # was mined
            self._store(key, Sent(e.tx_hash, stamp, confirmed=False))
            raise
        except Exception:
            with self._lock:
                self._in_flight.discard(key)
            raise
        self._store(key, Sent(result, stamp, confirmed=True))
        return result

    def _store(self, key: str, sent: Sent) -> None:
        # cache the result and release the reservation atomically, so no retry
        # can observe "not cached and not in flight" after a success
        with self._lock:
            self._results[key] = sent
            self._in_flight.discard(key)
            # bound memory over a long run: a request_id evicted here and
            # retried much later re-broadcasts, which is the right trade at
            # that distance — retries cluster within seconds of the original
            while len(self._results) > self._max_results:
                del self._results[next(iter(self._results))]
