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


"""Tests for the run window behind Connect's activity goal."""

from connect.run_goal import RunGoal

START = 1_791_331_200


class FakeClock:
    """A wall clock the test moves by hand."""

    def __init__(self, now: float = START) -> None:
        """Initialize."""
        self.now = now

    def __call__(self) -> float:
        """Return the current time."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the clock forward."""
        self.now += seconds


def test_fresh_window_is_not_met() -> None:
    """A window that just opened has no progress and no completed run."""
    goal = RunGoal(15, clock=FakeClock())
    assert goal.snapshot() == {
        "unit": "minutes",
        "target": 15,
        "progress": 0,
        "is_met": False,
        "period_start": START,
        "last_met_at": None,
        "updated_at": START,
    }


def test_progress_counts_whole_minutes() -> None:
    """Progress is elapsed minutes rounded down."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(59)
    assert goal.snapshot()["progress"] == 0
    clock.advance(1)
    assert goal.snapshot()["progress"] == 1
    clock.advance(14 * 60 - 1)
    block = goal.snapshot()
    assert (block["progress"], block["last_met_at"]) == (14, None)


def test_window_completes_and_reopens_at_target() -> None:
    """At target minutes the run is stamped as met and a new window opens."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(15 * 60)
    block = goal.snapshot()
    assert block["last_met_at"] == START + 15 * 60
    assert block["period_start"] == START + 15 * 60
    assert block["progress"] == 0
    assert block["is_met"] is False


def test_long_gap_yields_one_completion() -> None:
    """A suspend spanning several windows counts once, then a fresh window."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(3 * 15 * 60 + 120)
    block = goal.snapshot()
    resumed = START + 3 * 15 * 60 + 120
    assert (block["last_met_at"], block["period_start"]) == (resumed, resumed)
    clock.advance(60)
    block = goal.snapshot()
    assert block["last_met_at"] == resumed
    assert block["progress"] == 1


def test_raising_target_extends_the_current_window() -> None:
    """A higher target keeps the window's start and its progress."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(10 * 60)
    goal.set_target(30)
    clock.advance(10 * 60)
    block = goal.snapshot()
    assert (block["target"], block["progress"]) == (30, 20)
    assert block["period_start"] == START
    assert block["last_met_at"] is None


def test_lowering_target_to_progress_completes_the_window() -> None:
    """A target at or below the progress made completes the run on the next read."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(5 * 60)
    goal.set_target(5)
    block = goal.snapshot()
    assert block["last_met_at"] == START + 5 * 60
    assert (block["target"], block["progress"]) == (5, 0)


def test_zero_target_is_always_met_and_never_rolls_over() -> None:
    """A 0-minute run is met from the start and stamps last_met_at once."""
    clock = FakeClock()
    goal = RunGoal(0, clock=clock)
    clock.advance(3600)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert (block["last_met_at"], block["period_start"]) == (START, START)


def test_switching_to_zero_stamps_when_it_takes_effect() -> None:
    """Setting 0 mid-window is met at once; setting it again stamps nothing new."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(120)
    goal.set_target(0)
    clock.advance(120)
    goal.set_target(0)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert block["last_met_at"] == START + 120
    assert goal.target == 0
