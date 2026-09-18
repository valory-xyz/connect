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

import re
import socket
import threading
import typing as t
from concurrent.futures import TimeoutError as FuturesTimeoutError
from unittest.mock import patch

import pytest

from connect import mech_terms
from connect.mech_terms import (
    IDENTIFICATION_TIMEOUT,
    MECH_TERMS_URL,
    identification_name,
    is_valory_operated,
    terms_report,
)

MODULE = "connect.mech_terms"
MECH = "0xC05e7412439bD7e91730a6880E18d5D5873F632C"
NAME = "c05e7412439bd7e91730a6880e18d5d5873f632c.100.mech.valory.xyz"


def _dns(resolving: set) -> t.Any:
    """Build a getaddrinfo stand-in that resolves only the given names."""
    looked_up: t.List[str] = []

    def getaddrinfo(name: str, _port: t.Any) -> list:
        looked_up.append(name)
        if name in resolving:
            return [("ok",)]
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    getaddrinfo.looked_up = looked_up  # type: ignore[attr-defined]
    return getaddrinfo


class TestIdentificationName:
    """The name is the address without 0x, lowercased, then the chain id."""

    @pytest.mark.parametrize(
        "address",
        [MECH, MECH.lower(), MECH[2:], MECH[2:].upper()],
        ids=["checksummed", "lowercase", "no_prefix", "no_prefix_upper"],
    )
    def test_address_form_does_not_change_the_name(self, address: str) -> None:
        """Every way of writing one address yields one name."""
        assert identification_name(address, 100) == NAME

    def test_chain_id_is_a_label_of_its_own(self) -> None:
        """A mech is identified per chain, so the chain id is part of the name."""
        assert identification_name(MECH, 137).endswith(".137.mech.valory.xyz")


class TestIsValoryOperated:
    """Valory operated means the mech's name resolves and a random one does not."""

    def test_a_resolving_name_identifies_the_mech(self) -> None:
        """Only Valory can create a record under the zone, so resolving proves it."""
        dns = _dns({NAME})
        with patch(f"{MODULE}.socket.getaddrinfo", side_effect=dns):
            assert is_valory_operated(MECH, "gnosis") is True
        assert dns.looked_up[0] == NAME

    def test_a_name_that_does_not_resolve_is_not_identified(self) -> None:
        """No record means Valory does not operate it; no probe is needed."""
        dns = _dns(set())
        with patch(f"{MODULE}.socket.getaddrinfo", side_effect=dns):
            assert is_valory_operated(MECH, "gnosis") is False
        assert dns.looked_up == [NAME]

    def test_a_wildcard_zone_identifies_nothing(self) -> None:
        """If an arbitrary name resolves too, a positive answer proves nothing."""
        # A wildcard record, or a resolver that answers made-up names, would
        # otherwise make every mech look Valory's.
        with patch(f"{MODULE}.socket.getaddrinfo", return_value=[("ok",)]):
            assert is_valory_operated(MECH, "gnosis") is False

    def test_the_probe_can_never_be_a_mech_and_stays_in_the_same_chain(self) -> None:
        """The probe name is not 40 hex characters and sits beside the real name."""
        dns = _dns({NAME})
        with patch(f"{MODULE}.socket.getaddrinfo", side_effect=dns):
            is_valory_operated(MECH, "gnosis")
        probe = dns.looked_up[1]
        assert re.fullmatch(r"[0-9a-f]{32}", probe.split(".", 1)[0])
        assert probe.endswith(".100.mech.valory.xyz")

    def test_each_check_uses_a_fresh_probe(self) -> None:
        """A fixed probe name could be registered to defeat the wildcard guard."""
        dns = _dns({NAME})
        with patch(f"{MODULE}.socket.getaddrinfo", side_effect=dns):
            is_valory_operated(MECH, "gnosis")
            is_valory_operated(MECH, "gnosis")
        assert dns.looked_up[1] != dns.looked_up[3]

    @pytest.mark.parametrize(
        "error",
        [
            socket.gaierror(socket.EAI_NONAME, "not known"),
            socket.gaierror(socket.EAI_AGAIN, "temporary failure"),
            OSError("network unreachable"),
            UnicodeError("label too long"),
        ],
        ids=["no_such_name", "resolver_unavailable", "no_network", "bad_label"],
    )
    def test_a_failed_lookup_is_not_identified(self, error: Exception) -> None:
        """Fails closed: a lookup that cannot complete must never claim Valory."""
        with patch(f"{MODULE}.socket.getaddrinfo", side_effect=error):
            assert is_valory_operated(MECH, "gnosis") is False

    def test_a_slow_lookup_gives_up_rather_than_holding_the_call(self) -> None:
        """A hung resolver must not stall the discovery call; it times out to a no."""
        with patch(f"{MODULE}.ThreadPoolExecutor.submit") as submit:
            submit.return_value.result.side_effect = FuturesTimeoutError()
            assert is_valory_operated(MECH, "gnosis") is False
        submit.return_value.result.assert_called_once_with(
            timeout=IDENTIFICATION_TIMEOUT
        )

    def test_the_timeout_does_not_wait_for_a_hung_lookup(self) -> None:
        """Giving up must return straight away, not block on the stuck thread."""
        release = threading.Event()

        def hang(_name: str, _port: t.Any) -> list:
            release.wait(5)
            return [("ok",)]

        with (
            patch(f"{MODULE}.IDENTIFICATION_TIMEOUT", 0.05),
            patch(f"{MODULE}.socket.getaddrinfo", side_effect=hang),
        ):
            assert (
                mech_terms._resolves(NAME) is False
            )  # pylint: disable=protected-access
        release.set()

    def test_an_unknown_chain_is_not_identified(self) -> None:
        """No chain id means no name to ask, so no claim and no lookup."""
        with patch(f"{MODULE}.socket.getaddrinfo") as lookup:
            assert is_valory_operated(MECH, "not-a-chain") is False
        lookup.assert_not_called()


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
