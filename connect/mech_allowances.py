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
import typing as t

from mech_client import balance_tracker, payment_token
from mech_client.infrastructure.config import PaymentType
from mech_client.services.deposit_service import DepositService
from mech_client.services.marketplace_service import (
    MarketplaceService,
    _MAX_AUTO_DEPOSIT_RATIO,
)
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig, NATIVE_ASSET
from connect.guard import Guard
from connect.mech_types import (
    Armed,
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
        # chain -> mech-client's deposit path and what it has sent
        self._deposits: dict[str, tuple[DepositService, _Sends]] = {}
        # chain -> what the request in flight prepaid, off its cap
        self._prefunded: dict[str, int] = {}

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
    def auto_deposit_armed(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        priced: PricedMech,
        *,
        auto_deposit: bool,
        max_payment: int,
        budget: TopUpBudget | None,
    ) -> t.Iterator[None]:
        """Pre-authorize the deposits of the send this wraps, then withdraw them.

        A deposit pays the balance tracker from the safe, whether this flow
        prepays it (`_prefund`) or the mech asks for a shortfall over HTTP
        402. Together they are bounded by the same cap mech-client itself
        enforces on the shortfall: the request's `max_payment`, within ratio
        x the mech's per-request rate; `check_top_up` holds the send's
        deposits to that cap and draws each on `budget` before it is signed,
        in every mode, and restricted mode allows them only through a
        one-shot allowance of that cap. The guard consumes a grant
        by its shape, not by who
        armed it, so it is armed only inside the send, under the queue's
        lock, and withdrawn before that lock is released: one request at a
        time holds one, and a top-up cannot spend another request's grant.
        The audit record is written in every mode; the allowance is armed
        only while restricted — unrestricted needs none, and one armed there
        would outlive a switch back to restricted for its TTL. A top-up's
        signer failure is raised unwrapped (`top_up_failure`), and a deposit
        that may have landed is audited as `mech_deposit_unconfirmed`.
        """
        armed: Armed = []
        try:
            if auto_deposit:
                self._arm_deposit(
                    chain, priced, armed, max_payment=max_payment, budget=budget
                )
            yield
        except Exception as e:
            failure = top_up_failure(e)
            if isinstance(failure, MechDepositUnknown):
                self._activity.record(
                    "mech_deposit_unconfirmed",
                    chain=chain,
                    mech=priced.mech,
                    tx_hash=failure.tx_hash,
                )
                raise failure from e
            if failure is e:
                raise
            # the signer's error already below e keeps its own cause: `from e`
            # would make the chain a loop
            raise failure from failure.__cause__
        finally:
            self.revoke(armed)

    def _arm_deposit(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        priced: PricedMech,
        armed: Armed,
        *,
        max_payment: int,
        budget: TopUpBudget | None,
    ) -> None:
        """Arm the top-up's bound (every mode) and grant (restricted only), audited."""
        tracker, is_token = deposit_tracker(chain, priced.payment_type)
        if tracker is None:  # restricted already disarmed it; unrestricted needs none
            return
        amount_cap = deposit_cap(priced, max_payment)
        deposited = self._prefunded.get(chain, 0)
        self._top_ups[chain] = _TopUp(tracker, amount_cap, budget, deposited)
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

    def prefund(self, plan: RequestPlan, safe: str) -> None:
        """Prepay the mech balance for `plan`, before any nonce is reserved.

        A mech admits an off-chain request only while the safe's prepaid
        balance covers it, and a balance holding exactly one call is spent by
        the first of the calls behind it. Depositing the whole capped amount
        here, rather than waiting for the mech to name a one-call shortfall
        over HTTP 402, keeps the balance ahead of the requests in flight: one
        deposit carries several calls, and a call whose balance is already
        there costs no transaction at all.

        It runs before the request takes a marketplace nonce, so a deposit
        whose outcome is unknown strands no slot and holds no queue. What it
        deposits is remembered for the send, whose own cap is that much
        smaller (`_arm_deposit`), so one request's deposits together stay
        within its max_payment; and it is armed, bounded and audited while it
        is made exactly as the 402 top-up is, so nothing is armed at all for
        a request that turns out to need no deposit.

        :raises MechDepositUnknown: a deposit that may have landed; audited.
        """
        if not plan.auto_deposit or not plan.offchain:
            return
        short = self._shortfall(plan, safe)
        if short is None:
            return
        armed: Armed = []
        try:
            self._arm_deposit(
                plan.chain,
                plan.priced,
                armed,
                max_payment=plan.max_payment,
                budget=plan.top_up_budget,
            )
            deposited = self._deposit_shortfall(plan, safe, short)
        finally:
            self.revoke(armed)
        if deposited:
            self._prefunded[plan.chain] = deposited
            plan.armed.append(functools.partial(self._forget_prefunded, plan.chain))

    def _shortfall(self, plan: RequestPlan, safe: str) -> "_Short | None":
        """Decide what to prepay, from chain reads alone; None to prepay nothing.

        None where there is nothing to do, or nothing that can be done: no
        tracker for the payment type, a payment type with no deposit of its
        own, a prepaid balance that already covers the call or cannot be
        read, and a safe that cannot cover what the call is short.
        """
        chain, priced = plan.chain, plan.priced
        if deposit_tracker(chain, priced.payment_type)[0] is None:
            return None
        kind = PaymentType(priced.payment_type)
        if kind is not PaymentType.NATIVE and kind not in DEPOSIT_TOKEN_ASSETS:
            logger.info(
                "payment type %s has no prepaid deposit; leaving its shortfall "
                "to the mech",
                kind.name,
            )
            return None
        try:
            deposits, sends = self._deposit_service(chain, plan.service)
            balance = int(deposits.check_balance(safe, kind))
            if balance >= priced.rate:
                return None
            spendable = self._spendable(deposits, chain, kind, safe)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(
                "could not read what the safe can prepay on %s: %s", chain, cause_of(e)
            )
            return None
        amount = min(deposit_cap(priced, plan.max_payment), spendable)
        missing = priced.rate - balance  # the least that lets this call through
        if amount < missing:
            logger.info(
                "not prepaying the mech balance on %s: the safe can spend %s of "
                "the %s one call is short",
                chain,
                spendable,
                missing,
            )
            return None
        return _Short(deposits, sends, balance, amount)

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
        short.sends.hashes.clear()
        try:
            self._deposit(short.deposits, kind, short.amount)
            rose = int(short.deposits.check_balance(safe, kind)) > short.balance
        except Exception as e:  # pylint: disable=broad-exception-caught
            self._unconfirmed(chain, priced, short.sends, error=e, amount=short.amount)
            return 0
        if not rose:
            logger.warning(
                "the safe's prepaid mech balance on %s did not rise on a deposit "
                "of %s; leaving the shortfall to the mech",
                chain,
                short.amount,
            )
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

    def _unconfirmed(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        priced: PricedMech,
        sends: _Sends,
        *,
        error: Exception,
        amount: int,
    ) -> None:
        """Say what a failed prepaid deposit was; raise if it may have landed.

        A failure that reached no chain is simply no deposit. One after the
        transaction left is spend-uncertain, whatever failed — the receipt
        wait, a balance read, the token path's deposit after its approve
        landed — so it is audited and raised, and the caller keeps its
        request id rather than being told to send again.

        :raises MechDepositUnknown: the deposit may have landed.
        """
        failure = top_up_failure(error)
        tx_hash = failure.tx_hash if isinstance(failure, MechDepositUnknown) else None
        if tx_hash is None and sends.hashes:
            tx_hash = sends.hashes[-1]
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
        clamped to it rather than asking for the whole cap and failing. A
        native deposit also leaves the floor the operator configured for the
        safe (the funds-manager `safe` requirement), so prepaying mech calls
        cannot drain what every other action spends.
        """
        token = payment_token(kind, chain) if kind.is_token() else None
        asset = NATIVE_ASSET if token is None else token
        balance, _ = asset_balance(deposits.ledger_api.api, asset, safe, chain)
        if token is not None:
            return balance
        rules = self._config.fund_requirements.get(chain, {}).get("safe", {})
        rule = rules.get(NATIVE_ASSET)
        floor = 0 if rule is None else rule["threshold"]
        return max(balance - floor, 0)

    def _deposit_service(
        self, chain: str, service: MarketplaceService
    ) -> tuple[DepositService, _Sends]:
        """Build, once per chain, the deposit path mech-client's own top-up takes."""
        built = self._deposits.get(chain)
        if built is None:
            sends = _Sends(service.signer)
            built = (
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
            self._deposits[chain] = built
        return built

    @staticmethod
    def _deposit(deposits: DepositService, kind: PaymentType, amount: int) -> None:
        """Send the deposit mech-client's own 402 top-up would send."""
        asset = DEPOSIT_TOKEN_ASSETS.get(kind)
        if asset is None:
            deposits.deposit_native(amount)
        else:
            deposits.deposit_token(amount, asset)

    def _forget_prefunded(self, chain: str) -> None:
        """Forget what the request prepaid on `chain`: the request has ended."""
        self._prefunded.pop(chain, None)

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
