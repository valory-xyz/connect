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

"""Errors and shapes shared by connect/mech.py and mech_allowances.py."""

import logging
import typing as t

from mech_client import NonceRefused, RequestIdMismatch, RequestIdRpcError

from connect.signer import SignerError

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


def published_tools(document: t.Any) -> list[str]:
    """Return the tool names a mech's metadata document publishes.

    The document is published by the mech operator, so neither its shape nor
    its contents are ours to assume. A `tools` that is not a list must not be
    iterated (a bare string yields one "tool" per character), and an entry that
    is not a name must not be stringified into one: both invent
    plausible-looking tools that no mech serves.
    """
    raw = (document if isinstance(document, dict) else {}).get("tools")
    if not isinstance(raw, list):
        return []
    return [name for name in raw if isinstance(name, str) and name.strip()]


def request_key(request_id: object) -> str:
    """Normalize a caller's request id: mech-client's are bare lowercase hex."""
    return str(request_id).lower().removeprefix("0x")


# what a caller is told of a failure whose words are a library's, which may
# name an RPC URL and its key; the cause goes to the log
UNSAID = "mech-client failed (the cause is in Connect's log)"


def request_label(chain: str, mech: str, tool: str, request_id: str | None) -> str:
    """Name a mech request in the log: its chain, mech, tool and id."""
    return f"mech request to {mech} on {chain} (tool {tool}, id {request_id})"


def said(error: Exception, context: str) -> str:
    """Return what a caller is told of a failure on the mech path.

    Connect's own errors and refusals (MechError and the signer's, rule-named),
    mech-client's NonceRefused, its id check and its unreachable-RPC id
    derivation (which names only the error class) keep their words; anything
    else is a library's, so it is UNSAID and logged under `context` (what
    failed, on which chain and mech), which tells concurrent failures apart.
    """
    if isinstance(
        error,
        (MechError, SignerError, NonceRefused, RequestIdMismatch, RequestIdRpcError),
    ):
        return str(error)
    logger.warning("%s", context, exc_info=error)
    return UNSAID
