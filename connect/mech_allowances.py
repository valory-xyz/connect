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

"""The single-use grants the mech flow registers with the guard."""

import contextlib
import functools
import logging
import threading
import typing as t

from mech_client import balance_tracker, payment_token
from mech_client.infrastructure.config import PaymentType
from mech_client.services.deposit_service import DepositService
from mech_client.services.marketplace_service import (
    MarketplaceService,
    PreSignHook,
    _MAX_AUTO_DEPOSIT_RATIO,
)
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig, NATIVE_ASSET
from connect.guard import Guard
from connect.mech_types import (
    Armed,
    InFlight,
    MechDepositUnknown,
    PricedMech,
    RequestPlan,
    TopUpBudget,
    top_up_failure,
)
from connect.safe import (
    SafeExec,
    decode_deposit,
    is_exec_transaction,
    safe_message_hash,
)
from connect.settings import MODE_RESTRICTED
from connect.signer_errors import SignerError, cause_of
from connect.wallet import asset_balance

logger = logging.getLogger("agent")

# What `DepositService` is asked for each token payment type it deposits; a
# native one takes no asset. A payment type in neither (an NVM subscription,
# or one a pin bump adds upstream) has no prepaid deposit here, and its
# shortfall is left to the mech to name.
DEPOSIT_TOKEN_ASSETS = {
    PaymentType.OLAS_TOKEN: "olas",
    PaymentType.USDC_TOKEN: "usdc",
}


class _Sends:
    """mech-client's signer, keeping the hash of each transaction it sends.

    What reached the chain is what tells a prepaid deposit that never
    happened from one that may have landed, and no error mech-client's
    deposit path raises carries it.
    """

    def __init__(self, signer: t.Any) -> None:
        """Wrap `signer`, forwarding everything but the send."""
        self._signer = signer
        self.hashes: list[str] = []
        self.address = signer.address
        self.sign_message = signer.sign_message
        self.sign_safe_message = signer.sign_safe_message

    def send_transaction(self, unsigned_tx: dict) -> str:
        """Send through the wrapped signer, keeping the hash it answered."""
        tx_hash = self._signer.send_transaction(unsigned_tx)
        self.hashes.append(tx_hash)
        return tx_hash


def deposit_cap(priced: PricedMech, max_payment: int) -> int:
    """Return the most one request may deposit, prepaid and on a 402 together.

    The request's `max_payment`, within the ratio of the mech's per-request
    rate mech-client itself enforces on a shortfall.
    """
    return min(_MAX_AUTO_DEPOSIT_RATIO * priced.rate, max_payment)


class _Short(t.NamedTuple):
    """What a prepaid deposit will be: the path, the balance read and the amount."""

    deposits: DepositService
    sends: _Sends
    balance: int
    amount: int


class _TopUp(t.NamedTuple):
    """The deposits a send may make: its tracker, bound, budget and spend."""

    tracker: str
    cap: int  # max_payment, within mech-client's ratio of the mech's rate
    budget: TopUpBudget | None  # None: a caller with no token, nothing to draw on
    deposited: int = 0  # what this send has put in already, prepaid or on a 402
    drawn: int = 0  # what its deposits have drawn on the session budget


def deposit_tracker(chain: str, payment_type: str) -> tuple[str | None, bool]:
    """Resolve (tracker, is_token) for a payment type; (None, False) otherwise.

    The tracker is mech-client's `balance_tracker`, the contract its deposit
    path pays, so the allowance armed from this answer names the contract
    mech-client will actually pay. None where it names none (NVM
    subscriptions) or raises (no deployment, a chain it does not know):
    auto-deposit is then disarmed rather than a request dying mid-flow.
    """
    kind = PaymentType(payment_type)
    try:
        tracker = balance_tracker(chain, kind)
    except ValueError as e:
        logger.warning("could not resolve the mech balance tracker: %s", e)
        return None, False
    if tracker is None:
        return None, False
    return tracker.lower(), kind.is_token()


def read_map_nonces(contract: t.Any, safe: str) -> int:
    """Read the marketplace's settled nonce for `safe` (an RPC read).

    mech-client's allocator takes this reader from its caller.
    """
    return int(contract.functions.mapNonces(Web3.to_checksum_address(safe)).call())


class MechAllowances:
    """Registers the single-use grants an off-chain mech request needs."""

    def __init__(self, config: AppConfig, guard: Guard, activity: ActivityLog) -> None:
        """Initialize."""
        self._config = config
        self._guard = guard
        self._activity = activity
        # chain -> the deposits the send under its queue's lock may make
        self._top_ups: dict[str, _TopUp] = {}
        self._lock = threading.Lock()  # guards the two tables below
        self._locks: dict[str, threading.Lock] = {}
        # chain -> requests about to be sent that have no allocator slot yet
        self._unreserved: dict[str, int] = {}

    def arm(  # pylint: disable=too-many-arguments
        self,
        *,
        chain: str,
        safe: str,
        chain_id: int,
        mech: str,
        request_id: bytes,
        nonce: int,
        armed: Armed,
    ) -> None:
        """Pre-authorize, once, the safe's signature on a request id.

        mech-client's pre-sign hook: it hands over the id it is about to sign,
        derived locally and checked against the contract's getRequestId
        before the hook runs (a mismatch is RequestIdMismatch, and nothing is
        signed), so a lying RPC cannot make the safe sign any other digest.

        Audited in every mode; the allowance is armed only while restricted.
        """
        digest = safe_message_hash(safe, chain_id, bytes(request_id))
        if self._guard.mode() == MODE_RESTRICTED:
            self._guard.allow_digest_once(digest)
            armed.append(functools.partial(self._guard.revoke_digest, digest))
        self._activity.record(
            "mech_offchain_digest",
            chain=chain,
            mech=mech,
            request_id="0x" + bytes(request_id).hex(),
            digest="0x" + digest.hex(),
            nonce=nonce,
        )

    def keeps_auto_deposit(self, chain: str, priced: PricedMech) -> bool:
        """Say whether auto_deposit should stay on for this request.

        Restricted mode lets the 402 top-up through only on a grant naming its
        tracker, so where no tracker resolves for the payment type it disarms
        instead of letting the flow die mid-request on a guard denial;
        unrestricted stays armed.
        """
        if self._guard.mode() != MODE_RESTRICTED:
            return True
        if deposit_tracker(chain, priced.payment_type)[0] is not None:
            return True
        logger.info(
            "no balance tracker for payment type %s on %s; auto_deposit "
            "disarmed in restricted mode",
            priced.payment_type,
            chain,
        )
        return False

    @contextlib.contextmanager
    def auto_deposit_armed(
        self, plan: RequestPlan, hook: PreSignHook
    ) -> t.Iterator[None]:
        """Pre-authorize the deposits of the send this wraps, then withdraw them.

        A deposit pays the balance tracker from the safe, whether this flow
        prepaid it (`prefund`) or the mech asks for a shortfall over HTTP
        402. Together they are bounded by the same cap mech-client itself
        enforces on the shortfall: the request's `max_payment`, within ratio
        x the mech's per-request rate. What the request has deposited already
        comes from the send's own hook, which carries it across mech-client's
        503 resends, so the bound counts the prepaid deposit and every resend
        of the request alike, as mech-client's `max_price` does; the prepaid
        amount is handed to the first hook for both to count.
        `check_top_up` holds the send's deposits to what is left of that cap
        and draws each on the request's budget before it is signed, in every
        mode, and restricted mode allows them only through a one-shot
        allowance of that remainder.

        The guard consumes a grant by its shape, not by who armed it, and the
        bound itself is per chain, so both are taken under that chain's
        deposit lock — the one `prefund` takes — and withdrawn before it is
        released: one request at a time holds them, and neither a top-up nor
        another request's prepaid deposit can spend or lower them.

        The audit record is written in every mode; the allowance is armed
        only while restricted — unrestricted needs none, and one armed there
        would outlive a switch back to restricted for its TTL. A top-up's
        signer failure is raised unwrapped (`top_up_failure`), and a deposit
        that may have landed is audited as `mech_deposit_unconfirmed`.
        """
        armed: Armed = []
        with self._deposit_lock(plan.chain):
            try:
                if plan.auto_deposit:
                    self._took_slot(plan)  # the allocator shows its slot now
                    plan.prefunded.on_hook(hook)
                    self._arm_deposit(plan, armed, hook.deposited)
                yield
            except Exception as e:
                failure = top_up_failure(e)
                if isinstance(failure, MechDepositUnknown):
                    self._activity.record(
                        "mech_deposit_unconfirmed",
                        chain=plan.chain,
                        mech=plan.priced.mech,
                        tx_hash=failure.tx_hash,
                    )
                    raise failure from e
                if failure is e:
                    raise
                # the signer's error already below e keeps its own cause:
                # `from e` would make the chain a loop
                raise failure from failure.__cause__
            finally:
                self.revoke(armed)

    def _hold_slot(self, plan: RequestPlan) -> None:
        """Count this request until the allocator shows the slot it will take.

        A request is in flight from the moment it is going to be sent, but
        the allocator shows it only once `reserve` has written its slot, and
        the deposit lock is released before that. Until then it is counted
        here, so the next request to prepay does not read a bar one call too
        low and leave a delivery unpaid.
        """
        if plan.prefunded.counted:
            return
        plan.prefunded.counted = True
        with self._lock:
            self._unreserved[plan.chain] = self._unreserved.get(plan.chain, 0) + 1
        # whatever becomes of the request, it stops being counted with it
        plan.armed.append(functools.partial(self._took_slot, plan))

    def _took_slot(self, plan: RequestPlan) -> None:
        """Stop counting this request: it holds a slot now, or it gave up."""
        if not plan.prefunded.counted:
            return
        plan.prefunded.counted = False
        with self._lock:
            left = self._unreserved.get(plan.chain, 0) - 1
            if left > 0:
                self._unreserved[plan.chain] = left
            else:
                self._unreserved.pop(plan.chain, None)

    def _unreserved_count(self, chain: str) -> int:
        """Return how many of this chain's requests have no slot of record yet."""
        with self._lock:
            return self._unreserved.get(chain, 0)

    def _deposit_lock(self, chain: str) -> threading.Lock:
        """Return the lock one chain's deposits are armed, made and withdrawn under.

        The bound and the guard's grant are per chain, and two requests on
        one chain reach them from different threads: the one prepaying
        before it takes a nonce, and the one sending under the safe's queue
        lock. Without this they would overwrite and withdraw each other's,
        leaving a top-up to be signed against no bound at all.
        """
        with self._lock:
            return self._locks.setdefault(chain, threading.Lock())

    def _arm_deposit(self, plan: RequestPlan, armed: Armed, deposited: int) -> None:
        """Arm the deposits' bound (every mode) and grant (restricted only), audited."""
        chain, priced = plan.chain, plan.priced
        tracker, is_token = deposit_tracker(chain, priced.payment_type)
        if tracker is None:  # restricted already disarmed it; unrestricted needs none
            return
        amount_cap = deposit_cap(priced, plan.max_payment)
        self._top_ups[chain] = _TopUp(
            tracker, amount_cap, plan.top_up_budget, deposited
        )
        armed.append(functools.partial(self._disarm_top_up, chain))
        remaining = max(amount_cap - deposited, 0)
        if self._guard.mode() == MODE_RESTRICTED:
            grant = self._guard.allow_safe_deposit_once(
                chain=chain, tracker=tracker, amount_cap=remaining, is_token=is_token
            )
            armed.append(functools.partial(self._guard.revoke_safe_deposit, grant))
        self._activity.record(
            "mech_deposit_allowance",
            chain=chain,
            tracker=tracker,
            amount_cap=str(remaining),
            is_token=is_token,
        )

    def prefund(self, plan: RequestPlan, safe: str, in_flight: InFlight) -> None:
        """Prepay the mech balance for `plan`, before any nonce is reserved.

        A mech admits an off-chain request while the safe's prepaid balance
        covers it, and settles what it has delivered afterwards, so a balance
        that covers one call is already owed to the requests in flight: the
        bar is `(in_flight + 1)` calls, not one. Depositing the whole capped
        amount here, rather than waiting for the mech to name a one-call
        shortfall over HTTP 402, keeps the balance ahead of them: one deposit
        carries several calls, and a call the balance already covers costs no
        transaction at all.

        It runs before the request takes a marketplace nonce, so a deposit
        whose outcome is unknown strands no slot and holds no queue. What it
        deposits is remembered on the plan, and the send's own cap is that
        much smaller (`_arm_deposit`), so one request's deposits together
        stay within its max_payment; and it is armed, bounded and audited
        while it is made exactly as the 402 top-up is, so nothing is armed at
        all for a request that turns out to need no deposit.

        The chain's deposit lock covers the whole of it, reads included: the
        balance it decides on is spent by the deposit it makes, and the bound
        and the grant it arms are the chain's, which the send takes the same
        lock for.

        :raises MechDepositUnknown: a deposit that may have landed; audited.
        """
        if not plan.auto_deposit or not plan.offchain:
            return
        armed: Armed = []
        with self._deposit_lock(plan.chain):
            # the read is inside the lock too: two requests that both read
            # before either deposit is mined would both deposit the cap
            short = self._shortfall(plan, safe, in_flight)
            self._hold_slot(plan)
            if short is None:
                return
            try:
                self._arm_deposit(plan, armed, plan.prefunded.amount)
                plan.prefunded.amount += self._deposit_shortfall(plan, safe, short)
            finally:
                self.revoke(armed)

    def _shortfall(
        self, plan: RequestPlan, safe: str, in_flight: InFlight
    ) -> "_Short | None":
        """Decide what to prepay, from chain reads alone; None to prepay nothing.

        None where there is nothing to do, or nothing that can be done: no
        tracker for the payment type, a payment type with no deposit of its
        own, a prepaid balance that already covers this call and every request
        in flight or cannot be read, and a safe that cannot cover what this
        call is short of the mech's own bar.
        """
        chain, priced, kind = (
            plan.chain,
            plan.priced,
            PaymentType(plan.priced.payment_type),
        )
        if not self._prepays(plan):
            return None
        try:
            deposits, sends = self._deposit_path(plan.service)
            balance = int(deposits.check_balance(safe, kind))
            # what the balance owes: every request in flight, and this one
            needed = (in_flight() + self._unreserved_count(chain) + 1) * priced.rate
            if balance >= needed:
                return None
            spendable = self._spendable(deposits, chain, kind, safe)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(
                "could not read what the safe can prepay on %s: %s", chain, cause_of(e)
            )
            return None
        amount = min(deposit_cap(priced, plan.max_payment), spendable)
        # worth its gas: one call's price, or the whole shortfall if that is
        # less — a deposit the mech's own bar still refuses buys nothing
        least = min(priced.rate, needed - balance)
        if amount < least:
            logger.info(
                "not prepaying the mech balance on %s: the safe can spend %s of "
                "the %s it would take",
                chain,
                spendable,
                least,
            )
            return None
        return _Short(deposits, sends, balance, amount)

    @staticmethod
    def _prepays(plan: RequestPlan) -> bool:
        """Say whether a prepaid deposit is possible for this request at all.

        It is not where no tracker resolves for the payment type, where the
        payment type has no deposit of its own, and where the cap cannot pay
        the mech even once — which `_prepare` refuses the request for, so no
        caller wastes a deposit on a mech it could never pay.
        """
        priced = plan.priced
        if deposit_tracker(plan.chain, priced.payment_type)[0] is None:
            return False
        kind = PaymentType(priced.payment_type)
        if kind is not PaymentType.NATIVE and kind not in DEPOSIT_TOKEN_ASSETS:
            logger.info(
                "payment type %s has no prepaid deposit; leaving its shortfall "
                "to the mech",
                kind.name,
            )
            return False
        return deposit_cap(priced, plan.max_payment) >= priced.rate

    def _deposit_shortfall(self, plan: RequestPlan, safe: str, short: "_Short") -> int:
        """Send the deposit `_shortfall` decided on; return what it put in.

        0 when the deposit was refused before it reached the chain (by the
        guard, by the session budget, or by mech-client's own balance check),
        and when its receipt left the prepaid balance where it was, since
        mech-client answers a hash without reading that receipt's status. The
        mech's shortfall is then left to the 402 path, as it was before.

        :raises MechDepositUnknown: the deposit reached the chain and what
            became of it is unknown; audited as `mech_deposit_unconfirmed`.
        """
        chain, priced = plan.chain, plan.priced
        kind = PaymentType(priced.payment_type)
        drawn = self._top_ups[chain].drawn
        try:
            self._deposit(short.deposits, kind, short.amount)
            rose = int(short.deposits.check_balance(safe, kind)) > short.balance
        except Exception as e:  # pylint: disable=broad-exception-caught
            # only the safe's payment to the tracker can leave a deposit
            # uncertain, and `check_top_up` draws for that call alone:
            # mech-client's approve ahead of a token deposit moves nothing
            paid = self._top_ups[chain].drawn > drawn
            self._unconfirmed(
                chain,
                priced,
                short.sends.hashes if paid else [],
                error=e,
                amount=short.amount,
            )
            self._return_drawn(chain, drawn)
            return 0
        if not rose:
            logger.warning(
                "the safe's prepaid mech balance on %s did not rise on a deposit "
                "of %s; leaving the shortfall to the mech",
                chain,
                short.amount,
            )
            self._return_drawn(chain, drawn)
            return 0
        self._activity.record(
            "mech_prefund",
            chain=chain,
            tracker=self._top_ups[chain].tracker,
            amount=str(short.amount),
            balance=str(short.balance),
            rate=str(priced.rate),
        )
        return short.amount

    def _return_drawn(self, chain: str, drawn: int) -> None:
        """Give back what a deposit drew on the session budget: it moved nothing.

        `check_top_up` draws a deposit on the budget before it is signed,
        which is what bounds it, and only what it drew is given back — a
        deposit it refused drew nothing. A deposit that may have landed keeps
        its draw: this runs only where nothing was spent.
        """
        top_up = self._top_ups[chain]
        returned = top_up.drawn - drawn
        if returned and top_up.budget is not None:
            top_up.budget(-returned)
        self._top_ups[chain] = top_up._replace(drawn=drawn)

    def _unconfirmed(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        priced: PricedMech,
        paid: list[str],
        *,
        error: Exception,
        amount: int,
    ) -> None:
        """Say what a failed prepaid deposit was; raise if it may have landed.

        `paid` is the hashes of this deposit's payments to the tracker, in
        order. A failure with none of them is simply no deposit, whatever
        else was sent: mech-client approves the tracker before it pays it,
        and an approval whose receipt is lost moved nothing. A failure once a
        payment has left is spend-uncertain, whatever failed next, so it is
        audited and raised, and the caller keeps its request id rather than
        being told to send again.

        :raises MechDepositUnknown: the deposit may have landed.
        """
        failure = top_up_failure(error)
        tx_hash = failure.tx_hash if isinstance(failure, MechDepositUnknown) else None
        # a refused payment moved nothing either, whatever went before it
        refused = tx_hash is None and isinstance(failure, SignerError)
        if tx_hash is None and paid and not refused:
            tx_hash = paid[-1]
        if tx_hash is None:
            logger.info(
                "did not prepay %s into the mech balance: %s", amount, cause_of(error)
            )
            return
        self._activity.record(
            "mech_deposit_unconfirmed", chain=chain, mech=priced.mech, tx_hash=tx_hash
        )
        raise MechDepositUnknown(tx_hash) from error

    def _spendable(
        self, deposits: DepositService, chain: str, kind: PaymentType, safe: str
    ) -> int:
        """Return what the safe may put into the prepaid balance right now.

        mech-client refuses a deposit above the safe's own balance of the
        payment asset, before anything is signed, so the prepaid deposit is
        clamped to it rather than asking for the whole cap and failing. It
        also leaves the floor the operator configured for the safe in that
        asset (the funds-manager `safe` requirement, per asset as that table
        is), so prepaying mech calls cannot drain what every other action
        spends.
        """
        token = payment_token(kind, chain) if kind.is_token() else None
        asset = NATIVE_ASSET if token is None else token
        balance, _ = asset_balance(deposits.ledger_api.api, asset, safe, chain)
        rules = self._config.fund_requirements.get(chain, {}).get("safe", {})
        rule = next((r for a, r in rules.items() if a.lower() == asset.lower()), None)
        floor = 0 if rule is None else rule["threshold"]
        return max(balance - floor, 0)

    @staticmethod
    def _deposit_path(service: MarketplaceService) -> tuple[DepositService, _Sends]:
        """Build the deposit path mech-client's own top-up takes, for one deposit.

        Built per deposit, not per chain: the hashes its signer records are
        what tells that deposit's failure from another request's, and a
        shared recorder would answer for whichever request wrote last.
        """
        sends = _Sends(service.signer)
        return (
            DepositService(
                chain_config=service.chain_config,
                agent_mode=service.agent_mode,
                safe_address=service.safe_address,
                ethereum_client=service.ethereum_client,
                signer=sends,
                rpc_url=service.rpc_url,
            ),
            sends,
        )

    @staticmethod
    def _deposit(deposits: DepositService, kind: PaymentType, amount: int) -> None:
        """Send the deposit mech-client's own 402 top-up would send."""
        asset = DEPOSIT_TOKEN_ASSETS.get(kind)
        if asset is None:
            deposits.deposit_native(amount)
        else:
            deposits.deposit_token(amount, asset)

    def _disarm_top_up(self, chain: str) -> None:
        """Forget the top-up armed on `chain`: its send has ended."""
        self._top_ups.pop(chain, None)

    def check_top_up(self, chain: str, to: str, data: str) -> None:
        """Hold a top-up to its cap and draw it on its budget, before it is signed.

        `MechSigner` calls this on every transaction the mech flow sends; one
        is a top-up when a top-up is armed on `chain` and it is the safe's call
        to that tracker, which moves its value plus any `deposit(uint256)`.

        The cap bounds the send's deposits together, not each one: what the
        prepaid deposit already put in is counted, so a 402 top-up after it
        may deposit only the rest.

        :raises SignerError: past the cap or the budget, naming which.
        """
        top_up = self._top_ups.get(chain)
        safe = str(self._config.chain(chain).safe_address).lower()
        if top_up is None or to.lower() != safe or not is_exec_transaction(data):
            return
        try:
            call = SafeExec.decode(data)
        except ValueError:  # the guard refuses what it cannot decode
            return
        if call.to.lower() != top_up.tracker:
            return
        amount = call.value + (decode_deposit(call.data) or 0)
        remaining = top_up.cap - top_up.deposited
        refusal = None
        if amount > remaining:
            refusal = (
                f"the top-up of {amount} is above the {remaining} this request "
                "may still deposit (its max_payment, and at most "
                f"{_MAX_AUTO_DEPOSIT_RATIO}x the mech's price); deposit it "
                "yourself or raise max_payment"
            )
        elif top_up.budget is not None:
            refusal = top_up.budget(amount)
        if refusal is not None:
            self._activity.record(
                "mech_deposit_refused",
                chain=chain,
                tracker=top_up.tracker,
                amount=str(amount),
                reason=refusal,
            )
            raise SignerError(refusal)
        # what the budget is down by, so a deposit that moves nothing can
        # give it back (`_return_drawn`)
        self._top_ups[chain] = top_up._replace(drawn=top_up.drawn + amount)

    def record_deposit(self, chain: str, request_id: str | None, amount: int) -> None:
        """Audit what a top-up deposited before the mech refused or lost it."""
        if amount:
            self._activity.record(
                "mech_deposit", chain=chain, request_id=request_id, amount=str(amount)
            )

    @staticmethod
    def revoke(armed: Armed) -> None:
        """Withdraw every grant a request armed; it signs nothing more.

        Called on every exit of the send, so no grant outlives its request:
        a refusal before the POST spends nothing, and a grant unused by a sent
        request is not left for another caller to consume.
        """
        while armed:
            armed.pop()()
