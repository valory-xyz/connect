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
    """A window that just opened has no progress and is not met."""
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
    clock.advance(13 * 60 + 59)
    block = goal.snapshot()
    assert (block["progress"], block["is_met"], block["last_met_at"]) == (
        14,
        False,
        None,
    )


def test_goal_is_met_at_target_and_stays_met() -> None:
    """At target minutes the goal is met, and later reads keep the same window."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(15 * 60)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert block["last_met_at"] == START + 15 * 60
    clock.advance(3 * 3600)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert (block["period_start"], block["progress"]) == (START, 3 * 60 + 15)
    assert block["last_met_at"] == START + 15 * 60


def test_raising_target_after_met_unmeets_it() -> None:
    """A target above the progress made is not met, against the same window."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(20 * 60)
    assert goal.snapshot()["is_met"] is True
    goal.set_target(30)
    block = goal.snapshot()
    assert (block["target"], block["progress"], block["is_met"]) == (30, 20, False)
    assert block["period_start"] == START


def test_last_met_at_is_stamped_once() -> None:
    """Meeting the goal again after a raise keeps the first stamp."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(15 * 60)
    goal.snapshot()
    goal.set_target(30)
    clock.advance(15 * 60)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert block["last_met_at"] == START + 15 * 60


def test_lowering_target_to_progress_meets_the_goal() -> None:
    """A target at or below the progress made is met on the next read."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(5 * 60)
    goal.set_target(5)
    block = goal.snapshot()
    assert (block["target"], block["progress"], block["is_met"]) == (5, 5, True)
    assert block["last_met_at"] == START + 5 * 60


def test_zero_target_is_met_at_once() -> None:
    """A 0-minute run is met from the first read."""
    goal = RunGoal(0, clock=FakeClock())
    block = goal.snapshot()
    assert (block["is_met"], block["last_met_at"]) == (True, START)


def test_switching_to_zero_meets_the_goal() -> None:
    """Setting 0 mid-window is met on the next read."""
    clock = FakeClock()
    goal = RunGoal(15, clock=clock)
    clock.advance(120)
    goal.set_target(0)
    block = goal.snapshot()
    assert block["is_met"] is True
    assert block["last_met_at"] == START + 120
    assert goal.target == 0
