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

"""What the skill commands print, and checks on what they are given."""

import json
import typing as t

from evm import SwapError


def print_json(doc: t.Any) -> None:
    """Emit one JSON document on stdout."""
    print(json.dumps(doc, indent=2, default=str))


def print_plan(plan: t.Mapping[str, t.Any]) -> None:
    """Print a plan without its raw calls."""
    print(json.dumps({k: v for k, v in plan.items() if k != "calls"}, indent=2))


def check_byte_limits(
    fields: t.Mapping[str, str],
    limits: t.Mapping[str, int],
    required: t.Iterable[str],
) -> None:
    """Refuse an empty required field or any field over its UTF-8 byte limit.

    Raises:
        SwapError: on the first field that fails.
    """
    for field in required:
        if not fields[field]:
            raise SwapError(f"{field} must be non-empty")
    for field, limit in limits.items():
        size = len(fields[field].encode("utf-8"))
        if size > limit:
            raise SwapError(f"{field} is {size} bytes; the limit is {limit}")


__all__ = ["check_byte_limits", "print_json", "print_plan"]
