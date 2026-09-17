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

"""State files the skills keep in the workspace."""

import json
import sys
import typing as t
from datetime import datetime, timezone
from pathlib import Path

from evm import SwapError

T = t.TypeVar("T")


def write_json_atomic(path: Path, doc: t.Any, compact: bool = False) -> None:
    """Write JSON through a sibling .tmp file; a half-written file is the corrupt one."""
    if compact:
        text = json.dumps(doc, separators=(",", ":"))
    else:
        text = json.dumps(doc, indent=2)
    scratch = path.with_suffix(".tmp")
    scratch.write_text(text, encoding="utf-8")
    scratch.replace(path)


def read_json(
    path: Path, consequence: str, build: t.Callable[[t.Any], T]
) -> t.Optional[T]:
    """Return ``build`` of a JSON file; None when it is missing, or unreadable after a NOTE."""
    try:
        return build(json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError:
        return None
    except (OSError, TypeError, ValueError, KeyError, AttributeError) as exc:
        print(
            f"NOTE: {path} is unreadable ({type(exc).__name__}: {exc}); {consequence}",
            file=sys.stderr,
        )
        return None


def _answered(doc: t.Any) -> dict[str, t.Any]:
    """Return a recorded answer document.

    Raises:
        ValueError: when it holds no non-empty answer.
    """
    if isinstance(doc, dict) and isinstance(doc.get("answer"), str) and doc["answer"]:
        return doc
    raise ValueError("it holds no non-empty answer")


def read_answer(path: Path, consequence: str) -> t.Optional[dict[str, t.Any]]:
    """Return the operator's recorded answer, or None when absent or unreadable."""
    return read_json(path, consequence, _answered)


def record_answer(path: Path, answer: str, **extra: t.Callable[[], t.Any]) -> None:
    """Record the operator's answer, with each ``extra`` field computed once it is accepted.

    Raises:
        SwapError: when the answer is empty.
    """
    answer = answer.strip()
    if not answer:
        raise SwapError("record the operator's own words; the answer is empty")
    doc = {"answer": answer, "recorded_at": datetime.now(timezone.utc).isoformat()}
    write_json_atomic(path, {**doc, **{k: make() for k, make in extra.items()}})


__all__ = ["read_answer", "read_json", "record_answer", "write_json_atomic"]
