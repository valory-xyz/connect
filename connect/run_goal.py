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

"""Connect's activity goal: a run window of N minutes.

Connect has no staking epoch, so its period is a run window that opens when
the process starts. When a window's minutes have elapsed, the window is
stamped as met (`last_met_at`) and the next one opens at once: Connect never
stops itself, and Pearl's Auto-run keys its hand-over on `last_met_at`.
A target of 0 is always met and never rolls over.
"""

import threading
import time
import typing as t

UNIT = "minutes"


class RunGoal:
    """The current run window and its target, safe to share across threads."""

    def __init__(
        self, target: int, clock: t.Callable[[], float] = time.time
    ) -> None:
        """Open the first window now."""
        self._lock = threading.Lock()
        self._clock = clock
        self._target = target
        self._period_start = self._now()
        self._last_met_at: int | None = self._period_start if target == 0 else None

    def _now(self) -> int:
        return int(self._clock())

    @property
    def target(self) -> int:
        """Minutes per run currently in effect."""
        with self._lock:
            return self._target

    def set_target(self, target: int) -> None:
        """Apply a new target to the current window.

        The window keeps its start, so raising the target extends it and
        lowering it to at or below the progress made completes it on the
        next snapshot.
        """
        with self._lock:
            if target == self._target:
                return
            self._target = target
            if target == 0:
                self._last_met_at = self._now()

    def snapshot(self) -> dict[str, t.Any]:
        """Return the activity_goal block, rolling the window over first.

        A rollover opens the next window at the current time, not at the
        theoretical boundary: after a suspend, that is one completed run
        rather than a burst of back-to-back ones.
        """
        with self._lock:
            now = self._now()
            if self._target > 0 and now - self._period_start >= self._target * 60:
                self._last_met_at = now
                self._period_start = now
            return {
                "unit": UNIT,
                "target": self._target,
                "progress": (now - self._period_start) // 60,
                "is_met": self._target == 0,
                "period_start": self._period_start,
                "last_met_at": self._last_met_at,
                "updated_at": now,
            }
