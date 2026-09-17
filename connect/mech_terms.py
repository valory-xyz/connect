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
import typing as t

import requests
from mech_client.utils.constants import CHAIN_NAME_TO_ID

logger = logging.getLogger(__name__)

# A Valory operated mech answers on a name under this zone. The zone is a
# wildcard record, so a name resolving proves nothing: only a route existing,
# and therefore a successful response, does.
IDENTIFICATION_ZONE = "mech.valory.xyz"
# The mech root answers 400, so ask for the endpoint that answers 200.
IDENTIFICATION_PATH = "/healthcheck"
# Short: this runs inside a discovery call the session is waiting on.
IDENTIFICATION_TIMEOUT = 3

MECH_TERMS_VERSION = "v1.0"
MECH_TERMS_URL = "https://www.valory.xyz/terms/mechs"


def identification_url(mech_address: str, chain_id: int) -> str:
    """Build the name that identifies a mech as Valory operated.

    :param mech_address: the mech contract address, with or without `0x`.
    :param chain_id: the chain the mech is deployed on.
    :return: the URL the identification check requests.
    """
    address = mech_address.lower().removeprefix("0x")
    return f"https://{address}.{chain_id}.{IDENTIFICATION_ZONE}{IDENTIFICATION_PATH}"


def is_valory_operated(mech_address: str, chain: str) -> bool:
    """Report whether Valory operates a mech.

    Fails closed. A timeout, a connection error, a 404, an unknown chain: all
    mean "not identified as Valory operated". Telling a session a mech is
    Valory's when it is not would be the harmful direction, so anything short
    of a clear success is a no.

    :param mech_address: the mech contract address.
    :param chain: the chain name the mech is deployed on.
    :return: True only on a successful response from the identification URL.
    """
    chain_id = CHAIN_NAME_TO_ID.get(chain)
    if chain_id is None:
        return False
    url = identification_url(mech_address, chain_id)
    try:
        response = requests.get(url, timeout=IDENTIFICATION_TIMEOUT)
    except requests.RequestException as exc:
        logger.debug("identification check failed for %s: %s", url, exc)
        return False
    return bool(response.ok)


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
        report["terms"] = (
            f"Submitting a request to this mech means agreeing to Valory AG's "
            f"Mech Terms ({MECH_TERMS_VERSION}): {MECH_TERMS_URL}"
        )
    terms_url = None
    if isinstance(metadata, dict):
        published = metadata.get("termsUrl")
        if isinstance(published, str) and published.strip():
            terms_url = published.strip()
    if terms_url:
        report["terms_url"] = terms_url
    return report
