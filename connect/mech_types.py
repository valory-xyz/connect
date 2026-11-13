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
