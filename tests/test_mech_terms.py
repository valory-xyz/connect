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

"""Tests for whose terms a mech request falls under."""

import typing as t
from unittest.mock import MagicMock, patch

import pytest
import requests

from connect.mech_terms import (
    IDENTIFICATION_TIMEOUT,
    MECH_TERMS_URL,
    identification_url,
    is_valory_operated,
    terms_report,
)

MODULE = "connect.mech_terms"
MECH = "0xC05e7412439bD7e91730a6880E18d5D5873F632C"
NAME = (
    "https://c05e7412439bd7e91730a6880e18d5d5873f632c.100.mech.valory.xyz/healthcheck"
)


def _response(status_code: int) -> MagicMock:
    """Build a response whose ``ok`` follows its status code."""
    response = MagicMock()
    response.ok = 200 <= status_code < 300
    return response


class TestIdentificationUrl:
    """The name is the address without 0x, lowercased, then the chain id."""

    @pytest.mark.parametrize(
        "address",
        [MECH, MECH.lower(), MECH[2:], MECH[2:].upper()],
        ids=["checksummed", "lowercase", "no_prefix", "no_prefix_upper"],
    )
    def test_address_form_does_not_change_the_name(self, address: str) -> None:
        """Every way of writing one address yields one name."""
        assert identification_url(address, 100) == NAME

    def test_chain_id_is_a_label_of_its_own(self) -> None:
        """A mech is identified per chain, so the chain id is part of the name."""
        assert ".137.mech.valory.xyz" in identification_url(MECH, 137)


class TestIsValoryOperated:
    """Only a clear success identifies a mech as Valory operated."""

    def test_a_successful_response_identifies_the_mech(self) -> None:
        """A 200 on the mech's own name is what proves it."""
        with patch(f"{MODULE}.requests.get", return_value=_response(200)) as get:
            assert is_valory_operated(MECH, "gnosis") is True
        get.assert_called_once_with(NAME, timeout=IDENTIFICATION_TIMEOUT)

    @pytest.mark.parametrize("status_code", [301, 400, 403, 404, 500], ids=str)
    def test_a_non_success_status_is_not_identified(self, status_code: int) -> None:
        """The zone is a wildcard, so a name answering 404 is not ours."""
        with patch(f"{MODULE}.requests.get", return_value=_response(status_code)):
            assert is_valory_operated(MECH, "gnosis") is False

    @pytest.mark.parametrize(
        "error",
        [requests.Timeout("slow"), requests.ConnectionError("no route")],
        ids=["timeout", "connection"],
    )
    def test_a_failed_check_is_not_identified(self, error: Exception) -> None:
        """Fails closed: an unreachable check must never claim Valory."""
        with patch(f"{MODULE}.requests.get", side_effect=error):
            assert is_valory_operated(MECH, "gnosis") is False

    def test_an_unknown_chain_is_not_identified(self) -> None:
        """No chain id means no name to ask, so no claim and no request."""
        with patch(f"{MODULE}.requests.get") as get:
            assert is_valory_operated(MECH, "not-a-chain") is False
        get.assert_not_called()


class TestTermsReport:
    """The report states the Valory terms, and passes a published link through."""

    def test_a_valory_mech_states_the_terms(self) -> None:
        """A Valory mech tells the session which terms it is agreeing to."""
        with patch(f"{MODULE}.is_valory_operated", return_value=True):
            report = terms_report(MECH, "gnosis", {})
        assert report["valory_operated"] is True
        assert MECH_TERMS_URL in report["terms"]
        assert "Valory AG's Mech Terms (v1.0)" in report["terms"]

    def test_another_operator_s_mech_gets_no_terms_statement(self) -> None:
        """Another operator's terms are theirs to state, not ours."""
        with patch(f"{MODULE}.is_valory_operated", return_value=False):
            report = terms_report(MECH, "gnosis", {})
        assert report["valory_operated"] is False
        assert "terms" not in report

    @pytest.mark.parametrize(
        ("metadata", "expected"),
        [
            ({"termsUrl": "https://third.party/terms"}, "https://third.party/terms"),
            (
                {"termsUrl": "  https://third.party/terms  "},
                "https://third.party/terms",
            ),
            ({"termsUrl": ""}, None),
            ({"termsUrl": "   "}, None),
            ({"termsUrl": 123}, None),
            ({"termsUrl": ["x"]}, None),
            ({}, None),
            (None, None),
            (["not", "a", "dict"], None),
        ],
        ids=[
            "published",
            "stripped",
            "empty",
            "whitespace",
            "int",
            "list_value",
            "absent",
            "no_document",
            "non_dict_document",
        ],
    )
    def test_published_link_is_passed_through_when_usable(
        self, metadata: t.Any, expected: t.Optional[str]
    ) -> None:
        """The document comes from a third party, so every shape must be safe."""
        with patch(f"{MODULE}.is_valory_operated", return_value=False):
            report = terms_report(MECH, "gnosis", metadata)
        assert report.get("terms_url") == expected
