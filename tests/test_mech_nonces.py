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

"""Tests for the marketplace nonce allocator."""

import json
import typing as t
from pathlib import Path

import pytest
from mech_client import OffchainRequestRejected, OffchainTopUpFailed

from connect import mech_nonces
from connect.mech_nonces import NonceAllocator, NonceRefused, send_with_nonce
from connect.mech_types import MechError, MechNotSent
from connect.signer import SignerError

SAFE = "0x" + "22" * 20
MECH_A = "0x" + "a1" * 20
MECH_B = "0x" + "b2" * 20


class Clock:
    """A clock that only moves when slept on."""

    def __init__(self) -> None:
        """Start at 1000."""
        self.now = 1000.0
        self.slept: list[float] = []

    def __call__(self) -> float:
        """Return the time."""
        return self.now

    def sleep(self, seconds: float) -> None:
        """Advance the time."""
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    """Return a fake clock."""
    return Clock()


@pytest.fixture
def allocator(tmp_path: Path, clock: Clock) -> NonceAllocator:
    """Return an allocator on the fake clock."""
    return NonceAllocator(tmp_path, settle_timeout=60, clock=clock, sleep=clock.sleep)


def held(allocator: NonceAllocator, nonce: int) -> dict | None:
    """Return the persisted slot for nonce on the test safe, or None."""
    path = allocator._path  # pylint: disable=protected-access
    queues = json.loads(path.read_text()) if path.exists() else {}
    return queues.get(f"gnosis:{SAFE}", {}).get("slots", {}).get(str(nonce))


def salt_of(allocator: NonceAllocator, nonce: int) -> str | None:
    """Return the salt persisted with a held slot, or None if n is free."""
    slot = held(allocator, nonce)
    return None if slot is None else slot["salt"]


def _sync(allocator: NonceAllocator, map_nonces: int) -> None:
    """Re-read mapNonces for the test safe, as every reserve does."""
    key = allocator.key("gnosis", SAFE)
    # pylint: disable-next=protected-access
    allocator._sync(key, allocator._queue(key), map_nonces)


def reject(status: int, reason: str = "no", nonce: int = 0) -> OffchainRequestRejected:
    """Return mech-client's rejection for one HTTP answer."""
    return OffchainRequestRejected(
        f"HTTP {status}",
        request_id="0x01",
        nonce=nonce,
        status=status,
        reason=reason,
        unsent=[],
    )


def take(
    allocator: NonceAllocator, map_nonces: int, mech: str = MECH_A, **kw: t.Any
) -> t.ContextManager[mech_nonces.Reservation]:
    """Return a reserve context on `chain` with a fixed mapNonces."""
    return allocator.reserve(
        "gnosis", SAFE, mech, lambda: map_nonces, timeout=kw.get("timeout", 10)
    )


def _enter(context: t.ContextManager) -> None:
    """Enter and leave a context, doing nothing inside."""
    with context:
        pass


def _crash_inside(context: t.ContextManager) -> None:
    """Raise inside a context, as a send that crashed would."""
    with context:
        raise RuntimeError("boom")


def test_nonces_follow_map_nonces_and_held_slots(allocator: NonceAllocator) -> None:
    """Allocate mapNonces + held slots; hold each until mapNonces passes it."""
    with take(allocator, 5) as slot:
        assert slot.nonce == 5
        slot.answered("accepted", mech=MECH_A, salt="s5")
    with take(allocator, 5) as slot:
        assert slot.nonce == 6  # 5 is held: unsettled, never reissued
        slot.answered("accepted", mech=MECH_A, salt="s6")
    assert salt_of(allocator, 6) == "s6"
    with take(allocator, 6) as slot:
        assert slot.nonce == 7  # 5 settled; 6 still held
        slot.answered("not_accepted", mech=MECH_A, salt="")
    with take(allocator, 6) as slot:
        assert slot.nonce == 7  # not accepted: reused
        slot.answered("accepted", mech=MECH_A, salt="")
    assert salt_of(allocator, 99) is None


def test_one_mech_in_flight_per_safe(allocator: NonceAllocator, clock: Clock) -> None:
    """A second mech waits for the first's slots to settle, then is refused."""
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="")
    with pytest.raises(NonceRefused) as refused:
        _enter(take(allocator, 5, MECH_B, timeout=5))
    assert refused.value.rule == "mech-in-flight"
    assert clock.slept  # it waited, re-reading mapNonces
    with take(allocator, 6, MECH_B) as slot:  # settled now
        assert slot.nonce == 6


def test_an_unanswered_reservation_is_held_as_unknown(
    allocator: NonceAllocator,
) -> None:
    """Leaving without an answer (a crash mid-send) never frees the nonce."""
    with pytest.raises(RuntimeError):
        _crash_inside(take(allocator, 5))
    with take(allocator, 5) as slot:
        assert slot.nonce == 6


def test_a_checksummed_mech_is_the_same_mech(allocator: NonceAllocator) -> None:
    """The mech's address in any case is one mech: its own slot never blocks it."""
    with take(allocator, 5, MECH_A.lower()) as slot:
        slot.answered("accepted", mech=MECH_A.lower(), salt="")
    with take(allocator, 5, MECH_A.upper().replace("0X", "0x"), timeout=0) as slot:
        assert slot.nonce == 6


def test_taken_resolves_our_unknown_or_stalls(allocator: NonceAllocator) -> None:
    """Taken on our own unknown slot means accepted; otherwise the queue stalls."""
    with take(allocator, 5) as slot:
        slot.answered("unknown", mech=MECH_A, salt="")
    with take(allocator, 5) as slot:
        assert slot.nonce == 6
        slot.answered("taken", mech=MECH_A, salt="")  # someone else holds 6
    assert allocator.stalled("gnosis", SAFE)
    with take(allocator, 5) as slot:
        assert slot.nonce == 5  # stalled: only the probe at mapNonces
        slot.answered("taken", mech=MECH_A, salt="")  # our own unknown 5
    assert held(allocator, 5)["state"] == "accepted"  # type: ignore[index]
    with take(allocator, 5) as slot:
        assert slot.nonce == 5
        slot.answered("accepted", mech=MECH_A, salt="")
    assert not allocator.stalled("gnosis", SAFE)


def test_an_overdue_slot_stalls_the_queue(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """Timed out, then not settled within the settle timeout: stop sending.

    The settle clock starts when the request's own response timeout ends, or
    at its delivery if that came first: a mech still working within its time
    stalls nothing.
    """
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="")
    clock.now += mech_nonces.RESPONSE_TIMEOUT_SECONDS
    _sync(allocator, 5)
    assert not allocator.stalled("gnosis", SAFE)  # still within the settle time
    clock.now += 61
    _sync(allocator, 5)
    assert allocator.stalled("gnosis", SAFE)


def test_a_delivery_starts_the_settle_clock(
    tmp_path: Path, allocator: NonceAllocator, clock: Clock
) -> None:
    """Delivered, then not settled within the settle timeout: stop sending."""
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="")
    clock.now += 10
    allocator.delivered("gnosis", SAFE, [5, 9])  # 9 is not held: ignored
    assert held(allocator, 5)["delivered_at"] == clock.now  # type: ignore[index]
    clock.now += 50
    allocator.delivered("gnosis", SAFE, [5])  # a second sighting keeps the first
    clock.now += 11
    _sync(allocator, 5)
    assert allocator.stalled("gnosis", SAFE)
    restarted = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    queue = restarted._queue(  # pylint: disable=protected-access
        restarted.key("gnosis", SAFE)
    )
    assert queue.slots[5].delivered_at == 1010.0


def test_queues_survive_a_restart(tmp_path: Path, clock: Clock) -> None:
    """Held slots, salts and the stall are read back, so nothing is reissued."""
    first = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    with take(first, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="salt")
    second = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    assert salt_of(second, 5) == "salt"
    with take(second, 5) as slot:
        assert slot.nonce == 6


def test_an_unreadable_queue_file_refuses_every_request(
    tmp_path: Path, clock: Clock
) -> None:
    """Held nonces cannot be told from free ones: nothing is sent."""
    (tmp_path / mech_nonces.NONCES_FILE).write_text("{not json")
    allocator = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    for context in (
        take(allocator, 5),
        allocator.exclusive("gnosis", SAFE, lambda: 5, timeout=1),
    ):
        with pytest.raises(NonceRefused) as refused:
            _enter(context)
        assert refused.value.rule == "mech-queue-unreadable"
        assert "could not be read" in str(refused.value)


def test_on_chain_requests_wait_for_an_empty_queue(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """An on-chain request takes mapNonces itself, so no slot may be held."""
    with allocator.exclusive("gnosis", SAFE, lambda: 5, timeout=1):
        pass
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="")
    start = clock.now
    with pytest.raises(NonceRefused, match="on-chain request must wait"):
        _enter(allocator.exclusive("gnosis", SAFE, lambda: 5, timeout=3))
    assert clock.now - start >= 3  # it waited out its timeout first
    map_nonces = iter([5, 5, 6])
    with allocator.exclusive("gnosis", SAFE, lambda: next(map_nonces), timeout=30):
        pass  # the slot settled during the wait
    assert held(allocator, 5) is None


def test_outcomes_follow_the_mechs_answers() -> None:
    """503 retries; the exact stale-nonce 401 is taken; 4xx not accepted; else unknown."""
    assert mech_nonces.outcome_of(reject(503)) == "retry"
    assert (
        mech_nonces.outcome_of(reject(401, mech_nonces.NONCE_TAKEN_REASON)) == "taken"
    )
    assert mech_nonces.outcome_of(reject(401, "bad signature")) == "not_accepted"
    assert mech_nonces.outcome_of(reject(402)) == "not_accepted"
    assert mech_nonces.outcome_of(reject(400)) == "not_accepted"  # the bound
    assert mech_nonces.outcome_of(reject(399)) == "unknown"
    assert mech_nonces.outcome_of(reject(500)) == "unknown"
    top_up = OffchainTopUpFailed("cap", request_id="0x01", nonce=0, unsent=[])
    assert mech_nonces.outcome_of(top_up) == "not_accepted"


def _send(allocator: NonceAllocator, answers: list, clock: Clock) -> tuple[list, t.Any]:
    sent: list[int] = []

    def send(nonce: int) -> dict:
        sent.append(nonce)
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    try:
        result = send_with_nonce(
            allocator,
            chain="gnosis",
            safe=SAFE,
            mech=MECH_A,
            salt="s",
            read_map_nonces=lambda: 5,
            send=send,
            not_sent=(KeyError,),
            timeout=1,
            sleep=clock.sleep,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        return sent, e
    return sent, result


def test_send_with_nonce_retries_a_gap_then_succeeds(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """A 503 resends the same nonce; a later 200 holds it."""
    sent, result = _send(allocator, [reject(503), {"ok": 1}], clock)
    assert sent == [5, 5]
    assert result == {"ok": 1}
    assert salt_of(allocator, 5) == "s"


def test_send_with_nonce_refuses_a_persistent_gap(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """After gap_retries resends the request is refused as mech-nonce-gap; n is free."""
    answers = [reject(503)] * (mech_nonces.DEFAULT_MECH_GAP_RETRIES + 1)
    sent, error = _send(allocator, answers, clock)
    assert len(sent) == mech_nonces.DEFAULT_MECH_GAP_RETRIES + 1
    assert isinstance(error, NonceRefused)
    assert error.rule == "mech-nonce-gap"
    assert salt_of(allocator, 5) is None


@pytest.mark.parametrize(
    ("status", "reason", "rule", "held"),
    [
        (401, mech_nonces.NONCE_TAKEN_REASON, "mech-nonce-taken", False),
        (402, "payment required", "mech-request-rejected", False),
        (500, "boom", "mech-answer-unknown", True),
    ],
)
def test_send_with_nonce_names_each_rejection(  # pylint: disable=too-many-arguments
    allocator: NonceAllocator,
    clock: Clock,
    status: int,
    reason: str,
    rule: str,
    held: bool,
) -> None:
    """Each answer names its rule, and holds the slot only when it may be stored."""
    _, error = _send(allocator, [reject(status, reason)], clock)
    assert isinstance(error, NonceRefused)
    assert error.rule == rule
    assert (salt_of(allocator, 5) is not None) is held


def test_send_with_nonce_frees_a_nonce_never_sent_and_holds_a_lost_one(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """Refused before signing: n is free. A transport error: n is held."""
    sent, error = _send(allocator, [KeyError("refused")], clock)
    assert isinstance(error, KeyError)
    sent, error = _send(allocator, [ConnectionError("lost")], clock)
    assert sent == [5]  # the freed 5 was reused
    assert isinstance(error, ConnectionError)
    with take(allocator, 5) as slot:
        assert slot.nonce == 6


def test_the_slot_is_on_disk_before_the_post(allocator: NonceAllocator) -> None:
    """A crash mid-send leaves n held: it was written down before sending."""
    with take(allocator, 5) as slot:
        assert held(allocator, 5) == {
            **t.cast(dict, held(allocator, 5)),
            "state": "unknown",
        }
        slot.answered("accepted", mech=MECH_A, salt="")
    assert t.cast(dict, held(allocator, 5))["state"] == "accepted"


def test_a_restart_keeps_the_stall(tmp_path: Path, clock: Clock) -> None:
    """A stalled queue is still stalled after a restart, and still probes."""
    first = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    with take(first, 5) as slot:
        slot.answered("taken", mech=MECH_A, salt="")
    second = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    assert second.stalled("gnosis", SAFE)
    with take(second, 5) as slot:
        assert slot.nonce == 5


def test_the_settle_timeout_boundary_and_an_overdue_unknown(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """Exactly at the timeout is not overdue; past it, accepted or unknown stalls."""
    with take(allocator, 5) as slot:
        slot.answered("unknown", mech=MECH_A, salt="")
    clock.now += mech_nonces.RESPONSE_TIMEOUT_SECONDS + 60
    _sync(allocator, 5)
    assert not allocator.stalled("gnosis", SAFE)
    clock.now += 1
    _sync(allocator, 5)
    assert allocator.stalled("gnosis", SAFE)  # a lost POST stalls, not wedges


def test_a_rejected_probe_puts_back_what_it_replaced(allocator: NonceAllocator) -> None:
    """A stalled queue probes at mapNonces over a held slot; a refusal restores it."""
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="kept")
    with take(allocator, 5) as slot:
        assert slot.nonce == 6
        slot.answered("taken", mech=MECH_A, salt="")
    with take(allocator, 5) as slot:
        assert slot.nonce == 5  # the probe, over our accepted 5
        slot.answered("not_accepted", mech=MECH_A, salt="")
    assert t.cast(dict, held(allocator, 5))["salt"] == "kept"


def test_the_lock_wait_is_bounded(allocator: NonceAllocator) -> None:
    """A second request on the same safe waits for the lock, then is refused."""
    import threading  # pylint: disable=import-outside-toplevel

    entered, release = threading.Event(), threading.Event()

    def hold() -> None:
        with take(allocator, 5) as slot:
            entered.set()
            release.wait(5)
            slot.answered("accepted", mech=MECH_A, salt="")

    worker = threading.Thread(target=hold)
    worker.start()
    entered.wait(5)
    with pytest.raises(NonceRefused, match="still being sent"):
        _enter(take(allocator, 5, timeout=0.05))
    release.set()
    worker.join(5)


def test_an_unwritable_store_refuses_requests_not_answers(
    allocator: NonceAllocator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed write never fails an accepted request; it stops the next one."""
    real_write = Path.write_text
    writes: list[int] = []

    def full_after_one(self: Path, *args: t.Any, **kwargs: t.Any) -> int:
        writes.append(1)
        if len(writes) > 1:
            raise OSError(28, "No space left on device")
        return real_write(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", full_after_one)
    with take(allocator, 5) as slot:  # the placeholder is on disk
        slot.answered("accepted", mech=MECH_A, salt="")  # does not raise
    with pytest.raises(NonceRefused) as refused:
        _enter(take(allocator, 6))
    assert refused.value.rule == "mech-queue-unwritable"


def test_a_placeholder_that_cannot_be_saved_is_never_sent(
    allocator: NonceAllocator, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Held only in memory, n would be reissued after a restart: refuse first."""

    def full(*_args: t.Any, **_kwargs: t.Any) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "write_text", full)
    with pytest.raises(NonceRefused) as refused:  # before the body would run
        _enter(take(allocator, 5))
    assert refused.value.rule == "mech-queue-unwritable"
    assert (
        allocator._queue(  # pylint: disable=protected-access
            allocator.key("gnosis", SAFE)
        ).slots
        == {}
    )


@pytest.mark.parametrize(
    "content",
    ["[1, 2]", '{"gnosis:0x": {"slots": {"5": {"state": "accepted"}}}}'],
)
def test_a_wrong_shaped_queue_file_is_unreadable(
    tmp_path: Path, clock: Clock, content: str
) -> None:
    """Valid JSON in the wrong shape is as unreadable as broken JSON."""
    (tmp_path / mech_nonces.NONCES_FILE).write_text(content)
    allocator = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    with pytest.raises(NonceRefused) as refused:
        _enter(take(allocator, 5))
    assert refused.value.rule == "mech-queue-unreadable"


def test_offchain_send_tells_a_failure_before_the_post_apart() -> None:
    """Before mech-client's pre-sign hook nothing was sent; after it, maybe."""
    seen: list[tuple] = []

    def failing(before_hook: bool, error: Exception) -> t.Callable[..., dict]:
        def send(on_request_id: t.Callable[..., None]) -> dict:
            if not before_hook:
                on_request_id(b"id", 5)
            raise error

        return send

    with pytest.raises(MechNotSent, match="not sent: rpc"):
        mech_nonces.offchain_send(failing(True, ConnectionError("rpc")), seen.append)
    with pytest.raises(ConnectionError):  # the POST may have reached the mech
        mech_nonces.offchain_send(
            failing(False, ConnectionError("rpc")), lambda *a: seen.append(a)
        )
    assert seen == [(b"id", 5)]
    for refused in (MechError("id mismatch"), SignerError("guard")):
        with pytest.raises(MechNotSent):  # Connect's own refusals precede the POST
            mech_nonces.offchain_send(failing(False, refused), lambda *a: None)
    with pytest.raises(OffchainRequestRejected):  # the mech's answer: mapped later
        mech_nonces.offchain_send(failing(False, reject(401)), lambda *a: None)
    assert mech_nonces.offchain_send(lambda on_request_id: {"ok": 1}, print) == {
        "ok": 1
    }
