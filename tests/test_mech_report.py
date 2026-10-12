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

"""Tests for the deadline connect puts on mech-client's pre-payment report."""

import threading
import time
import typing as t
from types import SimpleNamespace

import pytest

from connect import mech_report as mech_report_module
from connect import mech_rpc
from connect.mech_report import REPORT_TIMEOUT_NOTE, mech_report

MECH = "0x" + "ab" * 20
DOCUMENT = {"tools": ["prediction-online"]}
TERMS = {"valory_operated": False, "terms_url": "https://op.example/terms"}


def _service(report: t.Callable[[str, t.Any], dict]) -> SimpleNamespace:
    """Build a service whose tool manager answers with ``report``."""
    terms_calls: list[tuple] = []

    def terms_report(mech: str, document: t.Any) -> dict:
        terms_calls.append((mech, document))
        return dict(TERMS)

    return SimpleNamespace(
        tool_manager=SimpleNamespace(
            mech_report_or_terms=report, terms_report=terms_report
        ),
        terms_calls=terms_calls,
    )


def test_a_report_in_time_is_mech_client_s_own() -> None:
    """Within the deadline the report is passed through untouched."""
    calls: list[tuple] = []

    def report(mech: str, document: t.Any) -> dict:
        calls.append((mech, document))
        return {**TERMS, "delivery": {"received_requests": 3}}

    service = _service(report)
    out = mech_report(service, MECH, DOCUMENT)  # type: ignore[arg-type]
    assert out == {**TERMS, "delivery": {"received_requests": 3}}
    assert calls == [(MECH, DOCUMENT)]
    assert not service.terms_calls


def test_the_report_runs_as_a_listing_in_its_own_thread() -> None:
    """The RPC mismatch warning is silenced where the report runs, and only there."""
    seen: dict = {}

    def report(_mech: str, _document: t.Any) -> dict:
        seen["listing"] = getattr(
            mech_rpc._LISTING, "active", False
        )  # pylint: disable=protected-access
        seen["thread"] = threading.current_thread().name
        return dict(TERMS)

    mech_report(_service(report), MECH, DOCUMENT)  # type: ignore[arg-type]
    assert seen["listing"] is True
    assert seen["thread"].startswith("mech-report")
    assert not getattr(
        mech_rpc._LISTING, "active", False
    )  # pylint: disable=protected-access


def test_a_report_that_overruns_falls_back_to_the_terms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Past the deadline the session gets mech-client's terms check and a note."""
    release = threading.Event()

    def stalled(_mech: str, _document: t.Any) -> dict:
        release.wait(10)
        return {**TERMS, "delivery": {}}

    monkeypatch.setattr(mech_report_module, "REPORT_DEADLINE", 0.2)
    service = _service(stalled)
    try:
        start = time.monotonic()
        out = mech_report(service, MECH, DOCUMENT)  # type: ignore[arg-type]
        elapsed = time.monotonic() - start
    finally:
        release.set()
    assert elapsed < 2
    assert out == {**TERMS, "report_note": REPORT_TIMEOUT_NOTE.format(deadline=0.2)}
    assert service.terms_calls == [(MECH, DOCUMENT)]


def test_a_failing_report_is_not_turned_into_a_timeout() -> None:
    """An error inside the report reaches the caller as itself."""

    def broken(_mech: str, _document: t.Any) -> dict:
        raise RuntimeError("executor shut down")

    with pytest.raises(RuntimeError, match="executor shut down"):
        mech_report(_service(broken), MECH, DOCUMENT)  # type: ignore[arg-type]
