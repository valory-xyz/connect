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

"""Whose terms a mech request falls under, and who operates the mech."""

import logging
import secrets
import socket
import typing as t
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from mech_client.utils.constants import CHAIN_NAME_TO_ID

logger = logging.getLogger(__name__)

# Valory creates one DNS record per mech it operates under this zone, and only
# Valory can, so a mech's name resolving is what identifies it. The answer does
# not depend on the mech being up.
IDENTIFICATION_ZONE = "mech.valory.xyz"
# Short: this runs inside a discovery call the session is waiting on.
IDENTIFICATION_TIMEOUT = 3

MECH_TERMS_VERSION = "v1.0"
MECH_TERMS_URL = "https://www.valory.xyz/terms/mechs"
# Legal-approved wording, used verbatim here and in mech-client.
VALORY_TERMS_NOTICE = (
    f"By submitting a request to this Mech, you agree to be bound by "
    f"Valory AG's Mech Terms ({MECH_TERMS_VERSION}), available at {MECH_TERMS_URL}."
)


def identification_name(mech_address: str, chain_id: int) -> str:
    """Build the DNS name that identifies a mech as Valory operated.

    :param mech_address: the mech contract address, with or without `0x`.
    :param chain_id: the chain the mech is deployed on.
    :return: the name the identification check resolves.
    """
    # One label, joined by a hyphen, so a single wildcard certificate on the
    # zone covers every mech on every chain. An address is hex and a chain id
    # is digits, so the hyphen is unambiguous.
    address = mech_address.lower().removeprefix("0x")
    return f"{address}-{chain_id}.{IDENTIFICATION_ZONE}"


def _resolves(name: str) -> bool:
    """Report whether a DNS name resolves, giving up after the timeout.

    The lookup has no timeout of its own, so it runs in a thread the caller
    stops waiting on. The pool is not used as a context manager, which would
    wait for a hung lookup and defeat the timeout.

    :param name: the DNS name to look up.
    :return: True if the name resolved within the timeout.
    """
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        executor.submit(socket.getaddrinfo, name, None).result(
            timeout=IDENTIFICATION_TIMEOUT
        )
    except (OSError, UnicodeError, FuturesTimeoutError) as exc:
        logger.debug("%s did not resolve: %s", name, exc)
        return False
    finally:
        executor.shutdown(wait=False)
    return True


def is_valory_operated(mech_address: str, chain: str) -> bool:
    """Report whether Valory operates a mech.

    Fails closed. A name that does not resolve, a timed-out lookup, no network,
    or an unknown chain all mean "not identified as Valory operated". Telling a
    session a mech is Valory's when it is not would be the harmful direction.

    A positive answer is also checked against a name that cannot belong to any
    mech. If that resolves too, the zone answers every name, as a wildcard
    record or a resolver that answers made-up names would, and the positive
    answer proves nothing, so the check says no.

    :param mech_address: the mech contract address.
    :param chain: the chain name the mech is deployed on.
    :return: True only if the mech's own name resolves and an arbitrary one does not.
    """
    chain_id = CHAIN_NAME_TO_ID.get(chain)
    if chain_id is None:
        return False
    if not _resolves(identification_name(mech_address, chain_id)):
        return False
    # 32 hex characters, so it can never be a 40-character mech address.
    probe = f"{secrets.token_hex(16)}-{chain_id}.{IDENTIFICATION_ZONE}"
    return not _resolves(probe)


def terms_report(mech_address: str, chain: str, metadata: t.Any) -> dict:
    """Describe whose terms a request to this mech falls under.

    ``terms_url`` is whatever the operator published, reported as found rather
    than endorsed. ``valory_operated`` is the only claim this server makes
    about who runs a mech, and it says who the session is contracting with.

    :param mech_address: the mech contract address.
    :param chain: the chain name the mech is deployed on.
    :param metadata: the mech's service metadata document, or None.
    :return: the terms fields to merge into a single-mech report.
    """
    report: dict = {"valory_operated": is_valory_operated(mech_address, chain)}
    if report["valory_operated"]:
        report["terms"] = VALORY_TERMS_NOTICE
    terms_url = None
    if isinstance(metadata, dict):
        published = metadata.get("termsUrl")
        if isinstance(published, str) and published.strip():
            terms_url = published.strip()
    if terms_url:
        report["terms_url"] = terms_url
    return report
