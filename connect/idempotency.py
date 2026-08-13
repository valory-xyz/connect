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

"""At-most-once execution of paid actions, keyed by caller-chosen request ids.

The signer keeps its own cache mapping an id to a tx hash. An action that is
paid for before it is answered has no single equivalent, so entries here hold
a whole report, plus a stamp of what was asked — without which a reused id
would answer a question its caller never posed.
"""

import threading
import typing as t

MAX_CACHED_REQUESTS = 1024


class InFlightError(Exception):
    """A request id whose first attempt has not settled yet."""


class LedgerEntry(t.NamedTuple):
    """What one settled attempt produced, and a stamp of what it was asked."""

    payload: dict
    stamp: str | None


class RequestLedger:
    """Settled attempts and what each one was asked."""

    def __init__(self, max_results: int = MAX_CACHED_REQUESTS) -> None:
        """Initialize."""
        self._lock = threading.Lock()
        self._max_results = max_results
        self._results: dict[str, LedgerEntry] = {}
        self._in_flight: set[str] = set()

    def reserve(self, key: str) -> LedgerEntry | None:
        """Claim a key, returning the entry a replay should resume, if any.

        The claim is taken whether or not an entry exists. A replay reads the
        stored entry and writes back a merged one, so two concurrent replays
        of one key would otherwise race — and the loser's write can drop a
        delivery the winner had just recorded.

        :raises InFlightError: when another attempt on this key is running.
        """
        with self._lock:
            if key in self._in_flight:
                raise InFlightError(key)
            self._in_flight.add(key)
            return self._results.get(key)

    def complete(self, key: str, payload: dict, stamp: str | None = None) -> None:
        """Store what the key produced and release its claim."""
        with self._lock:
            # re-insert so recency tracks use: eviction costs a second payment
            self._results.pop(key, None)
            self._results[key] = LedgerEntry(payload, stamp)
            self._in_flight.discard(key)
            while len(self._results) > self._max_results:
                del self._results[next(iter(self._results))]

    def release(self, key: str) -> None:
        """Release a claim whose attempt never got far enough to spend."""
        with self._lock:
            self._in_flight.discard(key)
