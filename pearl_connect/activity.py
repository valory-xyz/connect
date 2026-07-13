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

"""Activity log + agent_performance.json.

The activity log is the audit trail of every signer action (rotating, bounded
on disk). agent_performance.json is the Pearl SDK contract file the desktop
app reads from STORE_PATH.
"""

import json
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger("agent")

ACTIVITY_LOG_FILE = "activity_log.jsonl"
PERFORMANCE_FILE = "agent_performance.json"
MAX_LOG_BYTES = 5 * 1024 * 1024  # rotate to .1 beyond this


class ActivityLog:
    """ActivityLog."""

    def __init__(self, store_path: Path) -> None:
        """Initialize."""
        self._path = store_path / ACTIVITY_LOG_FILE
        self._performance_path = store_path / PERFORMANCE_FILE
        self._lock = threading.Lock()
        self._count = 0
        self._tx_count = 0
        self._last_activity: str | None = None

    def record(self, kind: str, **fields: object) -> None:
        """Record an entry; a failing disk never fails the caller's action.

        Recording happens after the fact (the transaction is broadcast, the
        session is open, the settings are saved). Raising here would report
        those as failures and invite the operator to retry work already done —
        so an unwritable log is loud in log.txt and in memory, but not fatal.
        """
        entry = {"timestamp": int(time.time()), "kind": kind, **fields}
        with self._lock:
            self._count += 1
            if kind == "transaction":
                self._tx_count += 1
            self._last_activity = kind
            try:
                self._append(entry)
                self._write_performance()
            except OSError:
                logger.exception("could not persist activity entry %r", kind)

    @property
    def count(self) -> int:
        """Count."""
        return self._count

    def _append(self, entry: dict) -> None:
        if self._path.exists() and self._path.stat().st_size > MAX_LOG_BYTES:
            self._path.replace(self._path.with_suffix(".jsonl.1"))
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def write_performance(self) -> None:
        """Write the SDK contract file; a failing disk is loud, never fatal.

        Same contract as record(): this class reports what happened, it does
        not decide whether the caller's work stands. A boot that cannot write
        agent_performance.json is degraded, not dead — so callers do not wrap
        this, and there is one error contract to remember rather than two.
        """
        with self._lock:
            try:
                self._write_performance()
            except OSError:
                logger.exception("could not write %s", PERFORMANCE_FILE)

    def _write_performance(self) -> None:
        payload = {
            "timestamp": int(time.time()),
            "metrics": [
                {
                    "name": "transactions",
                    "value": self._tx_count,
                    "is_primary": True,
                    "description": "Transactions broadcast this run",
                }
            ],
            "agent_behavior": None,
            "last_activity": self._last_activity,
            "last_chat_message": None,
        }
        tmp = self._performance_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._performance_path)
