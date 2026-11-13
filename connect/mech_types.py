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

"""Errors and shapes shared by connect/mech.py, mech_allowances.py and mech_nonces.py."""

import logging
import typing as t

from mech_client.services.marketplace_service import MarketplaceService

logger = logging.getLogger("agent")


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


class MechNotSent(MechError):
    """A request refused or failed before anything reached the mech.

    Nothing was paid for, so a caller's request_id is free to use again.
    """


class MechAnswerUnknown(MechError):
    """The mech's answer to a signed request was lost: it may be paid for.

    `pending_request_ids` are registered for mech_result to collect, since
    the mech may still store and deliver the request; `deposited` is what an
    auto top-up paid into the balance tracker on the way, else 0.
    """

    def __init__(
        self, message: str, pending_request_ids: list[str], deposited: int = 0
    ) -> None:
        """Initialize."""
        super().__init__(message, pending_request_ids, deposited)
        self.message = message
        self.pending_request_ids = pending_request_ids
        self.deposited = deposited

    def __str__(self) -> str:
        """Return the error a caller reads."""
        return self.message


class MechUnknownRequest(MechError):
    """No delivery is being awaited for this request id.

    Distinct from a failed read: this id will never become pending again,
    where a failed read says nothing about whether the mech answered.
    """


# Marks a stored report whose request reached the paying call and then failed,
# so the outcome — and the spend — is genuinely unknown to this server.
SPEND_UNCERTAIN = "uncertain"


class PricedMech(t.NamedTuple):
    """The mech a request will pay, with the price the cap must bind."""

    mech: str
    service_id: int
    # per-request price in the mech's payment asset base units (wei for
    # native mechs, token base units for OLAS/USDC ones)
    rate: int
    payment_type: str


class PendingDelivery(t.NamedTuple):
    """Where to resume looking for a request whose delivery had not arrived.

    `from_block` is the request's own transaction block: the on-chain watcher
    otherwise scans from the head minus a hundred blocks, which finds nothing
    for a request that has been waiting a while — exactly the case this exists
    to serve.
    """

    chain: str
    mech: str
    service_id: int
    offchain: bool
    from_block: int | None


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
