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

"""Connect's activity goal: one run window per process (README, "Run window")."""

import threading
import time
import typing as t

UNIT = "minutes"


def check_target(target: object) -> int:
    """Return target if it is a whole number of minutes >= 0, else raise ValueError."""
    if isinstance(target, bool) or not isinstance(target, int) or target < 0:
        raise ValueError(f"{target!r} is not a whole number of minutes >= 0")
    return target


class RunGoal:
    """The process's run window and its target, safe to share across threads."""

    def __init__(self, target: int, clock: t.Callable[[], float] = time.time) -> None:
        """Open the window now."""
        self._lock = threading.Lock()
        self._clock = clock
        self._target = check_target(target)
        self._period_start = self._now()
        self._last_met_at: int | None = None

    def _now(self) -> int:
        return int(self._clock())

    @property
    def target(self) -> int:
        """Minutes per run currently in effect."""
        with self._lock:
            return self._target

    def set_target(self, target: int) -> None:
        """Apply a new target to the window; the next snapshot re-checks is_met."""
        check_target(target)
        with self._lock:
            self._target = target

    def snapshot(self) -> dict[str, t.Any]:
        """Return the activity_goal block."""
        with self._lock:
            now = self._now()
            progress = (now - self._period_start) // 60
            is_met = progress >= self._target
            if is_met and self._last_met_at is None:
                self._last_met_at = now
            return {
                "unit": UNIT,
                "target": self._target,
                "progress": progress,
                "is_met": is_met,
                "period_start": self._period_start,
                "last_met_at": self._last_met_at,
                "updated_at": now,
            }
