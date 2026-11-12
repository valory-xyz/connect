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

"""Connect's marketplace nonce allocator: one per safe and chain (OPE-2035 T3).

Two off-chain requests from one safe used to get the same nonce: mech-client
set each to the marketplace's `mapNonces(safe)`, which only moves when a
delivery settles. Connect now owns the allocation and hands mech-client the
nonce to sign (`send_request(nonces=[n])`), on the marketplace as deployed
(D24): the mech admits only `nonce == mapNonces + accepted + settling` (503 on
a gap, 401 on a stale or duplicate nonce), and settlement rebuilds every id
from `mapNonces`, so

- one mech is in flight per safe and chain: a request to another mech waits
  until the first mech's slots settle, and is refused as `mech-in-flight`
  when its wait runs out;
- the lock is held from `reserve` until the mech answers, so POSTs go out in
  nonce order and at most one slot is ever reserved but unanswered;
- a slot is held until `mapNonces > n` (settlement), not until delivery;
- every held slot, its metadata salt and the stalled flag are persisted under
  STORE_PATH, so a restart never reissues a held nonce.
"""

import contextlib
import json
import logging
import threading
import time
import typing as t
from dataclasses import dataclass, field
from pathlib import Path

from mech_client import OffchainRequestRejected

logger = logging.getLogger("agent")

NONCES_FILE = "mech_nonces.json"
# how often a waiting reserve re-reads mapNonces
POLL_SECONDS = 2.0
# an accepted slot whose delivery should have settled by now but has not
DEFAULT_SETTLE_TIMEOUT = 1800.0

# a 503 is a nonce gap behind a slot still settling: resend the same nonce and
# id this many times, this far apart, then refuse as mech-nonce-gap
MAX_GAP_RETRIES = 3
GAP_RETRY_SECONDS = 2.0
# the mech's 401 for a stale or duplicate nonce, verbatim: n is taken
NONCE_TAKEN_REASON = "wire nonce below sender's next expected slot"

Outcome = t.Literal["accepted", "retry", "not_accepted", "taken", "unknown"]
ACCEPTED: Outcome = "accepted"
UNKNOWN: Outcome = "unknown"


class NonceRefused(Exception):
    """The allocator will not hand out a nonce now; `rule` names why."""

    def __init__(self, rule: str, detail: str) -> None:
        """Initialize."""
        super().__init__(rule, detail)
        self.rule = rule
        self.detail = detail

    def __str__(self) -> str:
        """Return the refusal a caller reads."""
        return self.detail


@dataclass
class _Slot:
    """One held nonce: who it was sent to, its salt, and what the mech said."""

    state: Outcome
    mech: str
    salt: str
    at: float


@dataclass
class _Queue:
    """One safe's nonces on one chain."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    slots: dict[int, _Slot] = field(default_factory=dict)
    stalled: bool = False


class Reservation:
    """A nonce reserved under the queue's lock, until the mech answers."""

    def __init__(self, allocator: "NonceAllocator", key: str, nonce: int) -> None:
        """Initialize."""
        self._allocator = allocator
        self._key = key
        self.nonce = nonce
        self.outcome: Outcome | None = None

    def answered(self, outcome: Outcome, *, mech: str, salt: str) -> None:
        """Record the mech's answer to this nonce."""
        self.outcome = outcome
        self._allocator._answered(  # pylint: disable=protected-access
            self._key, self.nonce, outcome, mech=mech, salt=salt
        )


class NonceAllocator:
    """Allocates off-chain marketplace nonces, one queue per (chain, safe)."""

    def __init__(
        self,
        store_path: Path,
        *,
        settle_timeout: float = DEFAULT_SETTLE_TIMEOUT,
        clock: t.Callable[[], float] = time.time,
        sleep: t.Callable[[float], None] = time.sleep,
    ) -> None:
        """Load the persisted queues from STORE_PATH."""
        self._path = store_path / NONCES_FILE
        self._settle_timeout = settle_timeout
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._queues: dict[str, _Queue] = {}
        self._load()

    @staticmethod
    def key(chain: str, safe: str) -> str:
        """Return the queue key for a safe on a chain."""
        return f"{chain.lower()}:{safe.lower()}"

    def _queue(self, key: str) -> _Queue:
        with self._lock:
            return self._queues.setdefault(key, _Queue())

    def stalled(self, chain: str, safe: str) -> bool:
        """Whether the safe's queue on this chain is stalled."""
        return self._queue(self.key(chain, safe)).stalled

    def stall_note(self, chain: str, safe: str) -> str:
        """Return the mech_queue_stalled note for a refusal, or "" if none."""
        if not self.stalled(chain, safe):
            return ""
        return (
            "; mech_queue_stalled: the mech is not settling this safe's "
            "requests in order, so only a request at the settled nonce is sent "
            "until one is accepted again"
        )

    def salt(self, chain: str, safe: str, nonce: int) -> str | None:
        """Return the salt kept with a held slot, so a resend signs the same id."""
        slot = self._queue(self.key(chain, safe)).slots.get(nonce)
        return None if slot is None else slot.salt

    def sync(self, chain: str, safe: str, map_nonces: int) -> None:
        """Free every slot below mapNonces (settled), and stall an overdue queue.

        An accepted slot that mapNonces has not passed within the settle
        timeout means the mech dropped or never settled it: later nonces would
        gap behind it, so the queue stalls until a probe at mapNonces is
        accepted again.
        """
        key = self.key(chain, safe)
        queue = self._queue(key)
        self._sync(key, queue, map_nonces)

    def _sync(self, key: str, queue: _Queue, map_nonces: int) -> None:
        now = self._clock()
        settled = [n for n in queue.slots if n < map_nonces]
        for nonce in settled:
            del queue.slots[nonce]
        overdue = any(
            slot.state == ACCEPTED and now - slot.at > self._settle_timeout
            for slot in queue.slots.values()
        )
        if overdue and not queue.stalled:
            logger.warning("mech nonce queue %s stalled: a slot never settled", key)
            queue.stalled = True
        if settled or overdue:
            self._save()

    @contextlib.contextmanager
    def reserve(
        self,
        chain: str,
        safe: str,
        mech: str,
        read_map_nonces: t.Callable[[], int],
        *,
        timeout: float,
    ) -> t.Iterator[Reservation]:
        """Reserve the next nonce for `mech`, holding the queue until it answers.

        n = mapNonces + the safe's own held slots. While another mech holds
        unsettled slots this waits (re-reading mapNonces), and is refused as
        `mech-in-flight` once `timeout` runs out. While the queue is stalled
        only a probe at n = mapNonces is handed out.
        """
        self._check_readable()
        key = self.key(chain, safe)
        queue = self._queue(key)
        deadline = self._clock() + timeout
        with queue.lock:
            while True:
                map_nonces = read_map_nonces()
                self._sync(key, queue, map_nonces)
                others = {s.mech for s in queue.slots.values()} - {mech.lower()}
                if not others:
                    break
                if self._clock() >= deadline:
                    raise NonceRefused(
                        "mech-in-flight",
                        f"this safe still has requests to {sorted(others)[0]} "
                        "settling on this chain, and a request to another mech "
                        "must wait for them; try again once they settle",
                    )
                self._sleep(POLL_SECONDS)
            if queue.stalled:
                nonce = map_nonces  # the probe that can clear the stall
            else:
                nonce = map_nonces + len(queue.slots)
            reservation = Reservation(self, key, nonce)
            try:
                yield reservation
            finally:
                if reservation.outcome is None:
                    # the caller never heard from the mech (an exception, a
                    # crash mid-send): whether it stored the request is
                    # unknown, so the slot is held, never reused
                    reservation.answered(UNKNOWN, mech=mech, salt="")

    @contextlib.contextmanager
    def exclusive(
        self,
        chain: str,
        safe: str,
        read_map_nonces: t.Callable[[], int],
        *,
        timeout: float,
    ) -> t.Iterator[None]:
        """Hold the queue for an on-chain request, once no slot is held.

        An on-chain marketplace request takes the nonce at mapNonces itself,
        which a held off-chain slot already claims; so it waits for the queue
        to empty, and is refused as `mech-in-flight` past `timeout`.
        """
        self._check_readable()
        key = self.key(chain, safe)
        queue = self._queue(key)
        deadline = self._clock() + timeout
        with queue.lock:
            while True:
                self._sync(key, queue, read_map_nonces())
                if not queue.slots:
                    break
                if self._clock() >= deadline:
                    raise NonceRefused(
                        "mech-in-flight",
                        "this safe still has off-chain requests settling on this "
                        "chain; an on-chain request must wait for them",
                    )
                self._sleep(POLL_SECONDS)
            yield

    def _check_readable(self) -> None:
        if self._broken:
            raise NonceRefused(
                "mech-queue-unreadable",
                f"{self._path.name} could not be read, so held nonces cannot be "
                "told from free ones; no mech request is sent until the operator "
                "restores or removes it",
            )

    def _answered(
        self, key: str, nonce: int, outcome: Outcome, *, mech: str, salt: str
    ) -> None:
        """Apply the mech's answer to a reserved nonce (the queue lock is held)."""
        queue = self._queue(key)
        held = queue.slots.get(nonce)
        if outcome == "accepted":
            queue.slots[nonce] = _Slot(ACCEPTED, mech.lower(), salt, self._clock())
            queue.stalled = False
        elif outcome == "taken":
            if held is not None and held.state == UNKNOWN:
                held.state = ACCEPTED  # our own earlier request holds it
            else:
                # another signer took n, or the mech still settles slots we
                # think free: sending more would only gap behind it
                queue.stalled = True
        elif outcome == UNKNOWN:
            queue.slots[nonce] = _Slot(UNKNOWN, mech.lower(), salt, self._clock())
        # "not_accepted": n is free, reused next; "retry": the caller resends
        self._save()

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            # held slots cannot be told apart from free ones any more, so stop
            # every queue rather than risk reissuing a nonce the mech holds
            logger.error("unreadable %s (%s); mech requests refused", self._path, e)
            self._broken = True
            return
        for key, entry in raw.items():
            self._queues[key] = _Queue(
                slots={
                    int(n): _Slot(s["state"], s["mech"], s["salt"], float(s["at"]))
                    for n, s in entry.get("slots", {}).items()
                },
                stalled=bool(entry.get("stalled")),
            )

    _broken = False

    def _save(self) -> None:
        state = {
            key: {
                "stalled": queue.stalled,
                "slots": {
                    str(n): {
                        "state": s.state,
                        "mech": s.mech,
                        "salt": s.salt,
                        "at": s.at,
                    }
                    for n, s in sorted(queue.slots.items())
                },
            }
            for key, queue in self._queues.items()
        }
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(self._path)


def outcome_of(rejection: OffchainRequestRejected) -> Outcome:
    """Map the mech's HTTP answer to what it means for the nonce (D24)."""
    if rejection.status == 503:
        return "retry"
    if rejection.status == 401 and rejection.reason == NONCE_TAKEN_REASON:
        return "taken"
    if 400 <= rejection.status < 500:
        return "not_accepted"
    return UNKNOWN


REJECTION_RULES = {
    "retry": "mech-nonce-gap",
    "taken": "mech-nonce-taken",
    "not_accepted": "mech-request-rejected",
    "unknown": "mech-answer-unknown",
}


def send_with_nonce(  # pylint: disable=too-many-arguments
    allocator: NonceAllocator,
    *,
    chain: str,
    safe: str,
    mech: str,
    salt: str,
    read_map_nonces: t.Callable[[], int],
    send: t.Callable[[int], dict],
    not_sent: tuple[type[Exception], ...],
    timeout: float,
    sleep: t.Callable[[float], None] = time.sleep,
) -> dict:
    """Reserve a nonce, send with it, and record what the mech answered.

    A 503 resends the same nonce (and, the salt being kept, the same id) up
    to MAX_GAP_RETRIES times. An exception in `not_sent` was raised before
    anything was signed, so the nonce is free again; any other failure (a
    transport error) leaves the slot held, since the mech may have stored it.

    :raises NonceRefused: naming the rule, when the mech did not accept it.
    """
    with allocator.reserve(chain, safe, mech, read_map_nonces, timeout=timeout) as slot:
        for attempt in range(MAX_GAP_RETRIES + 1):
            try:
                result = send(slot.nonce)
            except OffchainRequestRejected as e:
                outcome = outcome_of(e)
                if outcome == "retry" and attempt < MAX_GAP_RETRIES:
                    sleep(GAP_RETRY_SECONDS)
                    continue
                slot.answered(
                    "not_accepted" if outcome == "retry" else outcome,
                    mech=mech,
                    salt=salt,
                )
                raise NonceRefused(
                    REJECTION_RULES[outcome],
                    f"the mech answered HTTP {e.status} ({e.reason}) to nonce "
                    f"{e.nonce}",
                ) from e
            except not_sent:
                slot.answered("not_accepted", mech=mech, salt=salt)
                raise
            slot.answered("accepted", mech=mech, salt=salt)
            return result
    raise AssertionError("unreachable")  # pragma: no cover
