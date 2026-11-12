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

"""Tests for the marketplace nonce allocator (OPE-2035 T3, D24)."""

import typing as t
from pathlib import Path

import pytest
from mech_client import OffchainRequestRejected

from connect import mech_nonces
from connect.mech_nonces import NonceAllocator, NonceRefused, send_with_nonce

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
    assert allocator.salt("gnosis", SAFE, 6) == "s6"
    with take(allocator, 6) as slot:
        assert slot.nonce == 7  # 5 settled; 6 still held
        slot.answered("not_accepted", mech=MECH_A, salt="")
    with take(allocator, 6) as slot:
        assert slot.nonce == 7  # not accepted: reused
        slot.answered("accepted", mech=MECH_A, salt="")
    assert allocator.salt("gnosis", SAFE, 99) is None


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
    with take(allocator, 5) as slot:
        assert slot.nonce == 5
        slot.answered("accepted", mech=MECH_A, salt="")
    assert not allocator.stalled("gnosis", SAFE)


def test_an_overdue_slot_stalls_the_queue(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """Accepted but never settled within the settle timeout: stop sending."""
    with take(allocator, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="")
    clock.now += 61
    allocator.sync("gnosis", SAFE, 5)
    assert allocator.stalled("gnosis", SAFE)


def test_queues_survive_a_restart(tmp_path: Path, clock: Clock) -> None:
    """Held slots, salts and the stall are read back, so nothing is reissued."""
    first = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    with take(first, 5) as slot:
        slot.answered("accepted", mech=MECH_A, salt="salt")
    second = NonceAllocator(tmp_path, clock=clock, sleep=clock.sleep)
    assert second.salt("gnosis", SAFE, 5) == "salt"
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
    with pytest.raises(NonceRefused, match="on-chain request must wait"):
        _enter(allocator.exclusive("gnosis", SAFE, lambda: 5, timeout=3))
    with allocator.exclusive("gnosis", SAFE, lambda: 6, timeout=1):
        pass


def test_outcomes_follow_the_mechs_answers() -> None:
    """503 retries; the exact stale-nonce 401 is taken; 4xx not accepted; else unknown."""
    assert mech_nonces.outcome_of(reject(503)) == "retry"
    assert (
        mech_nonces.outcome_of(reject(401, mech_nonces.NONCE_TAKEN_REASON)) == "taken"
    )
    assert mech_nonces.outcome_of(reject(401, "bad signature")) == "not_accepted"
    assert mech_nonces.outcome_of(reject(402)) == "not_accepted"
    assert mech_nonces.outcome_of(reject(500)) == "unknown"


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
    assert allocator.salt("gnosis", SAFE, 5) == "s"


def test_send_with_nonce_refuses_a_persistent_gap(
    allocator: NonceAllocator, clock: Clock
) -> None:
    """After MAX_GAP_RETRIES the request is refused as mech-nonce-gap; n is free."""
    answers = [reject(503)] * (mech_nonces.MAX_GAP_RETRIES + 1)
    sent, error = _send(allocator, answers, clock)
    assert len(sent) == mech_nonces.MAX_GAP_RETRIES + 1
    assert isinstance(error, NonceRefused)
    assert error.rule == "mech-nonce-gap"
    assert allocator.salt("gnosis", SAFE, 5) is None


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
    assert (allocator.salt("gnosis", SAFE, 5) is not None) is held


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
