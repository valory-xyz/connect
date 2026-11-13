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

"""A mech's published service metadata: read once, and what it rules out.

The tool list and the off-chain endpoint both come from this one document,
which only `connect/mech.py` reads; split out of it for pylint's line limit.
"""

import logging
import typing as t

from mech_client.services.marketplace_service import MarketplaceService

logger = logging.getLogger("agent")


class MetadataRead(t.NamedTuple):
    """A service-metadata read: the document, or why it could not be read.

    The reason travels with the result because the two failure modes it
    separates need opposite responses — a gateway that timed out may well
    answer on the next call, while a mech that never published metadata never
    will — and nothing downstream can tell them apart from a bare ``None``.
    """

    document: dict | None
    error: str | None


def offchain_blocker(read: MetadataRead) -> str | None:
    """Why this mech cannot serve an off-chain request, or None if it can.

    The off-chain flow resolves the mech's endpoint from the ``url`` field of
    the service metadata, so a document we cannot read and a document without
    a ``url`` both rule the flow out entirely — but they earn different advice,
    which is why each reason carries its own. A mech that published no ``url``
    never will serve off-chain; a fetch that failed may simply succeed next
    time, and sending that one on-chain spends gas to avoid a retry.
    """
    if read.document is None:
        cause = read.error or "no cause reported"
        # "may be" is load-bearing: nothing here distinguishes a mech that
        # never published from a gateway that was briefly slow.
        return (
            f"metadata unreadable ({cause}); may be transient or never "
            "published — retry before paying to send this on-chain"
        )
    url = read.document.get("url")
    if not isinstance(url, str) or not url.strip():
        return "no 'url' in metadata; this mech serves on-chain requests only"
    return None


def read_service_metadata(service: MarketplaceService, service_id: int) -> MetadataRead:
    """Read the mech's published service metadata, keeping any failure cause.

    One fetch answers both questions a report asks of that document — the
    tool names and the off-chain URL — where mech-client refetches it per
    question, and every miss costs a full gateway timeout. The request
    path still pays twice: the pre-flight reads it here, then
    ``send_request`` resolves the URL from it again inside mech-client.

    mech-client swallows the common transport failures itself and hands
    back a bare ``None``, so a miss here usually arrives with no cause at
    all. Log every miss rather than only the ones that reach the `except`,
    otherwise the frequent case leaves no trace in this service's log.
    """
    try:
        metadata = service.tool_manager.fetch_tools_metadata(service_id)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("metadata fetch failed for service %s: %s", service_id, e)
        return MetadataRead(None, f"{type(e).__name__}: {e}")
    if isinstance(metadata, dict):
        return MetadataRead(metadata, None)
    logger.warning(
        "metadata for service %s is unusable: expected a document, got %s",
        service_id,
        type(metadata).__name__,
    )
    return MetadataRead(None, None)
