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

"""Connect's marketplace nonce allocator: one per safe and chain.

mech-client's own choice of nonce is the marketplace's `mapNonces(safe)`,
which only moves when a delivery settles, so two off-chain requests from one
safe would share it. Connect owns the allocation instead and hands mech-client
the nonce to sign (`send_request(nonces=[n])`). The mech admits only
`nonce == mapNonces + accepted + settling` (503 on a gap, 401 on a stale or
duplicate nonce), and settlement rebuilds every id from `mapNonces`, so

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

from mech_client import OffchainRequestRejected, OffchainTopUpFailed

from connect.config import DEFAULT_MECH_GAP_RETRIES, DEFAULT_MECH_SETTLE_TIMEOUT
from connect.mech_types import MechError, MechNotSent
from connect.signer import SignerError

logger = logging.getLogger("agent")

NONCES_FILE = "mech_nonces.json"
# how often a waiting reserve re-reads mapNonces
POLL_SECONDS = 2.0
# a held slot whose delivery is done, or timed out, but mapNonces has not
# passed it within this many seconds stalls its queue
DEFAULT_SETTLE_TIMEOUT = float(DEFAULT_MECH_SETTLE_TIMEOUT)
# mech-client writes responseTimeout=300 into every request: past that the
# mech is out of time by the request's own terms, so its delivery timed out
RESPONSE_TIMEOUT_SECONDS = 300.0

# a 503 is a nonce gap behind a slot still settling: resend the same nonce and
# id this many times, this far apart, then refuse as mech-nonce-gap
GAP_RETRY_SECONDS = 2.0
# the mech's 401 for a stale or duplicate nonce, verbatim: n is taken
NONCE_TAKEN_REASON = "wire nonce below sender's next expected slot"

Outcome = t.Literal["accepted", "retry", "not_accepted", "taken", "unknown"]
ACCEPTED: Outcome = "accepted"
UNKNOWN: Outcome = "unknown"


class NonceRefused(Exception):
    """The allocator will not hand out a nonce now; `rule` names why.

    `deposited` is what mech-client's auto top-up paid into the balance
    tracker before the mech refused the request anyway, else 0. `nonce` is
    the one the mech answered for, when a request was sent with one.
    """

    def __init__(
        self, rule: str, detail: str, deposited: int = 0, nonce: int | None = None
    ) -> None:
        """Initialize."""
        super().__init__(rule, detail, deposited, nonce)
        self.rule = rule
        self.detail = detail
        self.deposited = deposited
        self.nonce = nonce

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
    delivered_at: float | None = None

    def settle_from(self) -> float:
        """Return when mapNonces should start to pass this slot.

        That is its delivery, or the end of the mech's response timeout if no
        delivery was seen first.
        """
        if self.delivered_at is not None:
            return self.delivered_at
        return self.at + RESPONSE_TIMEOUT_SECONDS


@dataclass
class _Queue:
    """One safe's nonces on one chain."""

    lock: threading.Lock = field(default_factory=threading.Lock)
    slots: dict[int, _Slot] = field(default_factory=dict)
    stalled: bool = False


class Reservation:
    """A nonce reserved under the queue's lock, until the mech answers."""

    def __init__(
        self,
        allocator: "NonceAllocator",
        key: str,
        nonce: int,
        prior: "_Slot | None",
    ) -> None:
        """Initialize; `prior` is what held this nonce before this reservation."""
        self._allocator = allocator
        self._key = key
        self.nonce = nonce
        self.prior = prior
        self.outcome: Outcome | None = None

    def answered(self, outcome: Outcome, *, mech: str, salt: str) -> None:
        """Record the mech's answer to this nonce."""
        self.outcome = outcome
        self._allocator._answered(  # pylint: disable=protected-access
            self._key, self.nonce, outcome, mech=mech, salt=salt, prior=self.prior
        )


class NonceAllocator:  # pylint: disable=too-many-instance-attributes
    """Allocates off-chain marketplace nonces, one queue per (chain, safe)."""

    def __init__(
        self,
        store_path: Path,
        *,
        settle_timeout: float = DEFAULT_SETTLE_TIMEOUT,
        gap_retries: int = DEFAULT_MECH_GAP_RETRIES,
        clock: t.Callable[[], float] = time.time,
        sleep: t.Callable[[float], None] = time.sleep,
    ) -> None:
        """Load the persisted queues from STORE_PATH."""
        self._path = store_path / NONCES_FILE
        self._settle_timeout = settle_timeout
        self.gap_retries = gap_retries
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._save_lock = threading.Lock()
        self._queues: dict[str, _Queue] = {}
        self._broken = False
        self._unwritable = False
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

    def delivered(self, chain: str, safe: str, nonces: t.Iterable[int]) -> None:
        """Start the settle clock of each held nonce whose delivery arrived.

        mapNonces should pass a delivered request soon after; one it has not
        passed within the settle timeout stalls the queue (see _sync).
        """
        key = self.key(chain, safe)
        queue = self._queue(key)
        now = self._clock()
        marked = False
        with self._lock:
            for nonce in nonces:
                # _sync frees slots under the queue's lock, not this one: a
                # slot settled meanwhile is simply gone, with nothing to mark
                slot = queue.slots.get(nonce)
                if slot is not None and slot.delivered_at is None:
                    slot.delivered_at = now
                    marked = True
        if marked:
            self._save()

    def _sync(self, key: str, queue: _Queue, map_nonces: int) -> None:
        """Free every slot below mapNonces (settled), and stall an overdue queue.

        A held slot whose delivery is done or timed out, and that mapNonces has
        not passed within the settle timeout, means the mech dropped or never
        settled it: later nonces would gap behind it, so the queue stalls until
        a probe at mapNonces is accepted again.
        """
        now = self._clock()
        settled = [n for n in queue.slots if n < map_nonces]
        for nonce in settled:
            del queue.slots[nonce]
        # an accepted slot the mech never settled, or an unknown one (a POST
        # whose answer was lost) nothing resolved: later nonces would gap
        # behind it, so the queue probes at mapNonces until one is accepted
        overdue = any(
            now - slot.settle_from() > self._settle_timeout
            for slot in queue.slots.values()
        )
        if overdue and not queue.stalled:
            logger.warning("mech nonce queue %s stalled: a slot never settled", key)
            queue.stalled = True
        if settled or overdue:
            self._save()

    @contextlib.contextmanager
    def reserve(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        safe: str,
        mech: str,
        read_map_nonces: t.Callable[[], int],
        *,
        timeout: float,
        salt: str = "",
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
        with self._locked(queue, timeout):
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
            # written down before the POST: if the process dies mid-send the
            # mech may hold n, and a restart must not hand it out again
            prior = queue.slots.get(nonce)  # held already only for a probe
            queue.slots[nonce] = _Slot(UNKNOWN, mech.lower(), salt, self._clock())
            self._save()
            if self._unwritable:  # held in memory only: a restart would reissue n
                self._restore(queue, nonce, prior)
                self._check_readable()  # raises mech-queue-unwritable
            reservation = Reservation(self, key, nonce, prior)
            try:
                yield reservation
            finally:
                if reservation.outcome is None:
                    # an exception mid-send: whether the mech stored the
                    # request is unknown, so the slot stays held
                    reservation.answered(UNKNOWN, mech=mech, salt=salt)

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
        with self._locked(queue, timeout):
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

    @staticmethod
    @contextlib.contextmanager
    def _locked(queue: _Queue, timeout: float) -> t.Iterator[None]:
        """Hold a queue's lock, waiting at most `timeout` for it."""
        if not queue.lock.acquire(timeout=max(timeout, 0)):
            raise NonceRefused(
                "mech-in-flight",
                "another request from this safe is still being sent on this "
                "chain; try again shortly",
            )
        try:
            yield
        finally:
            queue.lock.release()

    def _check_readable(self) -> None:
        if self._broken:
            raise NonceRefused(
                "mech-queue-unreadable",
                f"{self._path.name} could not be read, so held nonces cannot be "
                "told from free ones; no mech request is sent until the operator "
                "restores or removes it",
            )
        if self._unwritable:
            raise NonceRefused(
                "mech-queue-unwritable",
                f"{self._path.name} could not be written, so a held nonce would "
                "not survive a restart; no mech request is sent until STORE_PATH "
                "is writable again and Connect restarts",
            )

    def _answered(  # pylint: disable=too-many-arguments
        self,
        key: str,
        nonce: int,
        outcome: Outcome,
        *,
        mech: str,
        salt: str,
        prior: _Slot | None,
    ) -> None:
        """Apply the mech's answer to a reserved nonce (the queue lock is held).

        `prior` is the slot that held n before this reservation's placeholder:
        only a stalled queue's probe can reserve a nonce that is already held.
        """
        queue = self._queue(key)
        now = self._clock()
        if outcome == "accepted":
            queue.slots[nonce] = _Slot(ACCEPTED, mech.lower(), salt, now)
            queue.stalled = False
        elif outcome == "taken":
            if prior is not None and prior.state == UNKNOWN:
                # our own earlier request holds n: it was accepted after all
                queue.slots[nonce] = _Slot(ACCEPTED, prior.mech, prior.salt, now)
            else:
                # another signer took n, or the mech still settles slots we
                # think free: sending more would only gap behind it
                self._restore(queue, nonce, prior)
                queue.stalled = True
        elif outcome == UNKNOWN:
            queue.slots[nonce] = _Slot(UNKNOWN, mech.lower(), salt, now)
        elif outcome == "not_accepted":
            self._restore(queue, nonce, prior)  # n is reused next
        # "retry": the caller resends the same nonce, under the placeholder
        self._save()

    @staticmethod
    def _restore(queue: _Queue, nonce: int, prior: _Slot | None) -> None:
        """Put back what held n before the placeholder, or free n."""
        if prior is None:
            queue.slots.pop(nonce, None)
        else:
            queue.slots[nonce] = prior

    def _load(self) -> None:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            queues = {
                key: _Queue(
                    slots={
                        int(n): _Slot(
                            s["state"],
                            s["mech"],
                            s["salt"],
                            float(s["at"]),
                            _optional_time(s.get("delivered_at")),
                        )
                        for n, s in entry.get("slots", {}).items()
                    },
                    stalled=bool(entry.get("stalled")),
                )
                for key, entry in raw.items()
            }
        except FileNotFoundError:
            return
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            # held slots cannot be told apart from free ones any more, so stop
            # every queue rather than risk reissuing a nonce the mech holds
            logger.error("unreadable %s (%s); mech requests refused", self._path, e)
            self._broken = True
            return
        self._queues.update(queues)

    def _save(self) -> None:
        """Write every queue down; a failure refuses requests, never an answer."""
        with self._save_lock:
            try:
                self._write()
            except OSError as e:
                logger.error(
                    "could not write %s (%s); mech requests refused", self._path, e
                )
                self._unwritable = True

    def _write(self) -> None:
        with self._lock:
            queues = list(self._queues.items())
        state = {
            key: {
                "stalled": queue.stalled,
                "slots": {
                    str(n): {
                        "state": s.state,
                        "mech": s.mech,
                        "salt": s.salt,
                        "at": s.at,
                        "delivered_at": s.delivered_at,
                    }
                    for n, s in sorted(dict(queue.slots).items())
                },
            }
            for key, queue in queues
        }
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
        tmp.replace(self._path)


def _optional_time(raw: t.Any) -> float | None:
    return None if raw is None else float(raw)


# what mech-client raises for one request of an off-chain call: the mech's HTTP
# answer, or an auto top-up that failed on our side before the mech accepted it
OFFCHAIN_FAILURES = (OffchainRequestRejected, OffchainTopUpFailed)


def outcome_of(rejection: OffchainRequestRejected | OffchainTopUpFailed) -> Outcome:
    """Map the mech's HTTP answer, or a failed top-up, to what it means for the nonce."""
    if isinstance(rejection, OffchainTopUpFailed):
        return "not_accepted"
    if rejection.status == 503:
        return "retry"
    if rejection.status == 401 and rejection.reason == NONCE_TAKEN_REASON:
        return "taken"
    if 400 <= rejection.status < 500:
        return "not_accepted"
    return UNKNOWN


ANSWER_UNKNOWN_RULE = "mech-answer-unknown"
REJECTION_RULES = {
    "retry": "mech-nonce-gap",
    "taken": "mech-nonce-taken",
    "not_accepted": "mech-request-rejected",
    "unknown": ANSWER_UNKNOWN_RULE,
}


def _answer(failure: OffchainRequestRejected | OffchainTopUpFailed) -> str:
    """Say what came back for a nonce, for the refusal's detail."""
    if isinstance(failure, OffchainTopUpFailed):
        return f"the auto top-up for nonce {failure.nonce} failed: {failure}"
    return (
        f"the mech answered HTTP {failure.status} ({failure.reason}) to nonce "
        f"{failure.nonce}"
    )


def not_sent_on_error(read: t.Callable[[], int]) -> t.Callable[[], int]:
    """Wrap a mapNonces read: an RPC failure there means nothing was sent."""

    def wrapped() -> int:
        try:
            return read()
        except Exception as e:
            raise MechNotSent(f"could not read the marketplace nonce: {e}") from e

    return wrapped


def offchain_send(
    send: t.Callable[..., dict], on_request_id: t.Callable[..., None]
) -> dict:
    """Send one off-chain request, telling a failure before the POST apart.

    mech-client calls `on_request_id` just before it signs, so whatever fails
    before that call has not reached the mech; Connect's own refusals (the
    hook's id check, the signer) come before the POST too. Those raise
    MechNotSent, and leave the nonce free. Anything else may have reached it.
    """
    hooked: list[bool] = []

    def hook(*args: t.Any) -> None:
        hooked.append(True)
        on_request_id(*args)

    try:
        return send(on_request_id=hook)
    except (MechError, SignerError) as e:
        raise MechNotSent(str(e)) from e
    except OFFCHAIN_FAILURES:
        raise
    except Exception as e:
        if not hooked:
            raise MechNotSent(f"mech request not sent: {e}") from e
        raise


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
    to the allocator's gap_retries times. An exception in `not_sent` was raised before
    anything was signed, so the nonce is free again; any other failure (a
    transport error) leaves the slot held, since the mech may have stored it.

    :raises NonceRefused: naming the rule, when the mech did not accept it.
    """
    with allocator.reserve(
        chain, safe, mech, read_map_nonces, timeout=timeout, salt=salt
    ) as slot:
        for attempt in range(allocator.gap_retries + 1):
            try:
                result = send(slot.nonce)
            except OFFCHAIN_FAILURES as e:
                outcome = outcome_of(e)
                if outcome == "retry" and attempt < allocator.gap_retries:
                    sleep(GAP_RETRY_SECONDS)
                    continue
                slot.answered(
                    "not_accepted" if outcome == "retry" else outcome,
                    mech=mech,
                    salt=salt,
                )
                raise NonceRefused(
                    REJECTION_RULES[outcome],
                    _answer(e),
                    getattr(e, "deposited", 0),
                    slot.nonce,
                ) from e
            except not_sent:
                slot.answered("not_accepted", mech=mech, salt=salt)
                raise
            slot.answered("accepted", mech=mech, salt=salt)
            return result
    raise AssertionError("unreachable")  # pragma: no cover
