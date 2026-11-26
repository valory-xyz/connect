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

import dataclasses
import logging
import typing as t

from mech_client import (
    DeliveryResult,
    NonceRefused,
    OffchainRequestRejected,
    OffchainTopUpFailed,
    PreSignHook,
    RULE_ANSWER_UNKNOWN,
    RULE_NONCE_TAKEN,
    RULE_REQUEST_REJECTED,
    RequestIdMismatch,
    RequestIdRpcError,
    outcome_of,
)
from mech_client.domain.delivery import (
    OffchainDeliveryWatcher,
    OnchainDeliveryWatcher,
)
from mech_client.nonces import REJECTION_RULES
from mech_client.services.marketplace_service import (
    MarketplaceService,
    NONCE_MODE_EXPLICIT,
)

from connect.signer_errors import SendUnknown, SignerError, logged_cause

logger = logging.getLogger("agent")


# what one request armed, each entry withdrawing one grant (MechAllowances.revoke)
Armed = list[t.Callable[[], None]]
# draws a top-up's amount on the calling token's mech session budget: the
# refusal, naming its rule, or None once drawn
TopUpBudget = t.Callable[[int], str | None]
# counts the safe's requests in flight, which the prepaid balance still owes
# (MechQueue.in_flight); read only when a prepaid deposit is being decided
InFlight = t.Callable[[], int]


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


class MechNotSent(MechError):
    """A request whose nonce is free: it never reached the mech.

    Or the mech answered it only with a 503 that stood through every resend
    (`mech-nonce-gap`), admitting nothing. Nothing was paid for, so a
    caller's request_id is free to use again.
    """


class MechRefused(MechError):
    """The mech refused a request that was posted to it.

    A 4xx answer, or a 402 whose top-up failed before any deposit was sent.
    Nothing was paid for, so a caller's request_id is free to use again; the
    signed request left Connect, so mech-client holds its nonce until it
    settles.
    """


class MechDepositUnknown(MechError):
    """The 402 top-up's deposit was broadcast and never answered: it may have landed.

    The mech answered the posted request 402, so mech-client holds its nonce
    until it settles; the spend is not settled, so `request()` keeps a
    caller's request_id as spend-uncertain rather than freeing it.
    """

    def __init__(self, tx_hash: str) -> None:
        """Initialize."""
        super().__init__(
            "the mech asked for a top-up (HTTP 402), and the safe's deposit "
            f"{tx_hash} was broadcast without an answer from the RPC, so it may "
            "have landed (the cause is in Connect's log). The mech refused the "
            "request itself, and its nonce stays held until it settles. Read "
            "the deposit's receipt (transaction_status) before sending again: "
            "a resend may top up again."
        )
        self.tx_hash = tx_hash


def top_up_failure(error: Exception) -> Exception:
    """Return the signer's failure under `error`, else `error` itself.

    mech-client's agent-mode executor wraps every Safe send failure, the 402
    top-up's included, in a bare Exception, which no `not_sent` can name: a
    deposit the RPC never answered becomes MechDepositUnknown.
    """
    cause: BaseException | None = error
    while cause is not None:
        if isinstance(cause, SendUnknown):
            return MechDepositUnknown(cause.tx_hash)
        if isinstance(cause, SignerError):
            return cause
        cause = cause.__cause__
    return error


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
    """The mech a request will pay, with the per-request rate its bounds bind."""

    mech: str
    service_id: int
    # per request, in the mech's payment asset base units (wei for native
    # mechs, token base units for OLAS/USDC ones): the mech's on-chain price,
    # or off-chain the cap the request signs (`mech_budget.offchain_priced`)
    rate: int
    payment_type: str


@dataclasses.dataclass
class Prefunded:
    """What one request prepaid into the mech balance, counted against its cap.

    Per request, not per chain: two requests on one chain prepay and send
    from different threads, and each must spend only its own `max_payment`.
    """

    amount: int = 0
    _on_hook: bool = False
    # whether its chain still counts this request as one the allocator has
    # not been given a slot for yet (`MechAllowances._hold_slot`)
    counted: bool = False

    def on_hook(self, hook: t.Any) -> None:
        """Hand the prepaid amount to the send's hook, once.

        mech-client's hook carries what a request has deposited across its
        503 resends and bounds them by `max_price`, so the prepaid deposit
        belongs on it too: both bounds then count the same spend.
        """
        if self.amount and not self._on_hook:
            hook.record_deposit(self.amount)
            self._on_hook = True


class RequestPlan(t.NamedTuple):
    """Everything a request needs, settled before any payment can happen.

    Its existence is the payment boundary: a failure with no plan spent
    nothing, a failure with one may have spent funds.
    """

    chain: str
    service: MarketplaceService
    priced: PricedMech
    extra_attributes: dict | None
    offchain: bool  # the flow; False is the on-chain one
    auto_deposit: bool
    tool: str
    max_payment: int
    terms: dict  # mech-client's mech report, merged into the request's report
    armed: Armed  # the guard grants this request armed, revoked if nothing is sent
    top_up_budget: TopUpBudget | None  # the session budget a top-up draws on
    prefunded: Prefunded  # what its prepaid deposit put in, off its cap

    @property
    def legacy_on_chain(self) -> bool:
        """Whether the request goes on-chain: read off `offchain`, never apart."""
        return not self.offchain


def over_max_payment(
    mech: str, price: int, max_payment: int, signed_cap: bool = False
) -> str:
    """Word the refusal of a mech whose price is above the request's budget.

    Off-chain the figure is the cap the request would sign (`signed_cap`),
    not a charge.
    """
    what = "would be signed a cap of" if signed_cap else "charges"
    return (
        f"mech {mech} {what} {price} per request (in its payment asset base "
        f"units), which exceeds max_payment={max_payment}; pass a higher max_payment "
        "to accept that"
    )


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
    nonce: int | None
    salt: str | None


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


def delivery_outcomes(deliveries: t.Mapping[str, DeliveryResult]) -> dict:
    """Return the `failed_runs` and `reported_charges` maps, each only when non-empty."""
    failed = {
        key: {"error": d.failure.error, "fault": d.failure.fault}
        for key, d in deliveries.items()
        if d.failure is not None
    }
    charges = {
        key: str(d.actual_delivery_rate)
        for key, d in deliveries.items()
        if d.actual_delivery_rate is not None
    }
    return {
        **({"failed_runs": failed} if failed else {}),
        **({"reported_charges": charges} if charges else {}),
    }


def merge_outcomes(payload: dict, report: t.Mapping) -> None:
    """Add a `result()` report's `failed_runs` and `reported_charges` to `payload`."""
    for field in ("failed_runs", "reported_charges"):
        if report.get(field):
            payload[field] = {**(payload.get(field) or {}), **report[field]}


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
    failed, on which chain and mech), which tells concurrent failures apart,
    redacted as `cause_of` redacts it, with where it was raised (`logged_cause`).
    """
    if isinstance(
        error,
        (MechError, SignerError, NonceRefused, RequestIdMismatch, RequestIdRpcError),
    ):
        return str(error)
    logger.warning("%s: %s", context, logged_cause(error))
    return UNSAID


def refusal(error: NonceRefused, note: str) -> MechError:
    """Return mech-client's refusal as the caller's error, naming its rule.

    `mech-request-rejected` and `mech-nonce-taken` answer a request that was
    posted, so they are MechRefused, its nonce held; every other rule left
    the nonce free (MechNotSent). `note` is the queue's stall note.
    """
    posted = error.rule in (RULE_REQUEST_REJECTED, RULE_NONCE_TAKEN)
    return (MechRefused if posted else MechNotSent)(
        f"rule '{error.rule}': {error}{note}"
    )


def not_bought(error: Exception, what: str, *, posted: bool, note: str) -> MechError:
    """Return a send failure that bought nothing as the caller's error.

    Before the POST nothing left Connect (MechNotSent). After it, the failure
    is the 402 top-up's, refused before any deposit was sent: the mech
    refused the request, and its nonce stays held (MechRefused).
    """
    if not posted:
        return MechNotSent(f"mech request not sent: {said(error, what)}")
    return MechRefused(
        "the mech asked for a top-up (HTTP 402), which failed: "
        f"{said(error, what)}; the nonce stays held until it settles{note}"
    )


def lost_answer(  # pylint: disable=too-many-arguments
    plan: "RequestPlan",
    sent: list[tuple[int, PreSignHook]],
    armed: dict[int, bytes],
    error: Exception,
    note: str,
) -> MechAnswerUnknown:
    """Describe a signed request whose answer was lost, its armed id pending."""
    held = armed[sent[-1][0]].hex()
    what = request_label(plan.chain, plan.priced.mech, plan.tool, held)
    return answer_lost(error, held, what, note)


def explicit_hook(
    arm: t.Callable[[bytes, int], None], sent: list[tuple[int, PreSignHook]]
) -> PreSignHook:
    """Return the pre-sign hook of an explicit send: arm the id, record the send."""

    def on_request_id(request_id: bytes, nonce: int) -> None:
        arm(request_id, nonce)
        sent.append((nonce, hook))

    hook = PreSignHook(on_request_id)
    return hook


def explicit_send(send: t.Callable[..., dict], hook: PreSignHook) -> dict:
    """Send with an explicit nonce, the mech's HTTP answer as the allocator's rule."""
    try:
        return send(nonce_mode=NONCE_MODE_EXPLICIT, on_request_id=hook)
    except (OffchainRequestRejected, OffchainTopUpFailed) as e:
        raise NonceRefused(REJECTION_RULES[outcome_of(e)], str(e)) from e


def answer_lost(error: Exception, held: str, what: str, note: str) -> MechAnswerUnknown:
    """Describe a signed request whose answer was lost, its id `held` pending."""
    return MechAnswerUnknown(
        f"rule '{RULE_ANSWER_UNKNOWN}': {said(error, what)}{note}; "
        f"pending_request_ids: {[held]} (mech_result collects it if the mech "
        "delivers it)",
        [held],
        getattr(error.__cause__, "deposited", 0),
    )


async def watch_delivery(
    service: MarketplaceService, pending: PendingDelivery, key: str, timeout: float
) -> dict:
    """Run the watcher for the flow this request was sent through."""
    if pending.offchain:
        url = service.tool_manager.get_offchain_url(pending.service_id)
        return await OffchainDeliveryWatcher(url, timeout).watch([key])
    contract = service.marketplace_contract()
    watcher = OnchainDeliveryWatcher(contract, service.ledger_api, timeout)
    return await watcher.watch([key], from_block=pending.from_block)
