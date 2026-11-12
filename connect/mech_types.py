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

import typing as t


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


class MechNotSent(MechError):
    """A request refused or failed before anything reached the mech.

    Nothing was paid for, so a caller's request_id is free to use again.
    """


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
