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
from connect.mech_types import MechDepositUnknown, PricedMech, top_up_failure
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

# what one request armed, each entry withdrawing one grant (MechAllowances.revoke)
Armed = list[t.Callable[[], None]]
# draws a top-up's amount on the calling token's mech session budget: the
# refusal, naming its rule, or None once drawn
TopUpBudget = t.Callable[[int], str | None]


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
        # chain -> the top-up the send under its queue's lock may make
        self._top_ups: dict[str, _TopUp] = {}
        # chain -> mech-client's deposit path, built once per chain
        self._deposits: dict[str, DepositService] = {}

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
        service: MarketplaceService,
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
                self._prefund(chain, priced, service, armed)
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
        amount_cap = min(_MAX_AUTO_DEPOSIT_RATIO * priced.rate, max_payment)
        self._top_ups[chain] = _TopUp(tracker, amount_cap, budget)
        armed.append(functools.partial(self._disarm_top_up, chain))
        if self._guard.mode() == MODE_RESTRICTED:
            grant = self._guard.allow_safe_deposit_once(
                chain=chain, tracker=tracker, amount_cap=amount_cap, is_token=is_token
            )
            armed.append(functools.partial(self._guard.revoke_safe_deposit, grant))
        self._activity.record(
            "mech_deposit_allowance",
            chain=chain,
            tracker=tracker,
            amount_cap=str(amount_cap),
            is_token=is_token,
        )

    def _prefund(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        priced: PricedMech,
        service: MarketplaceService,
        armed: Armed,
    ) -> None:
        """Deposit the armed cap when the safe cannot prepay one more request.

        A mech admits an off-chain request only while the safe's prepaid
        balance covers it, and a balance holding exactly one call is spent by
        the first of the calls behind it. Depositing the whole armed cap,
        rather than waiting for the mech to name a one-call shortfall over
        HTTP 402, keeps the balance ahead of the requests in flight: one
        deposit carries several calls, and a call whose balance is already
        there costs no transaction at all.

        Everything that bounds a 402 top-up bounds this: the tracker and cap
        the allowance was just armed for, `check_top_up`'s draw on the
        session budget, the guard's shape check, and mech-client's own
        deposit path.

        What it deposits is counted on the send, so this deposit and any 402
        top-up after it stay within the one cap together.

        Every way it cannot happen leaves the 402 path to deposit the
        shortfall as before: a balance that cannot be read, a safe that
        cannot pay even what one call is short, and a deposit refused before
        anything is signed — by the guard, by the budget, or by mech-client
        itself. Only a deposit that may have landed stops the request, named.
        """
        top_up = self._top_ups.get(chain)
        if top_up is None:  # no tracker for this payment type: nothing to prepay
            return
        kind = PaymentType(priced.payment_type)
        safe = str(self._config.chain(chain).safe_address)
        try:
            deposits = self._deposit_service(chain, service)
            balance = int(deposits.check_balance(safe, kind))
            if balance >= priced.rate:
                return
            spendable = self._spendable(deposits, chain, kind, safe)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning(
                "could not read what the safe can prepay on %s: %s", chain, cause_of(e)
            )
            return
        amount = min(top_up.cap, spendable)
        short = priced.rate - balance  # the least that lets this call through
        if amount < short:
            logger.info(
                "not prepaying the mech balance on %s: the safe can spend %s of "
                "the %s one call is short",
                chain,
                spendable,
                short,
            )
            return
        try:
            if kind.is_token():
                deposits.deposit_token(amount, "usdc" if kind.is_usdc() else "olas")
            else:
                deposits.deposit_native(amount)
        except Exception as e:  # pylint: disable=broad-exception-caught
            refused = top_up_failure(e)
            if not isinstance(refused, (SignerError, ValueError)):
                raise  # it may have landed: auto_deposit_armed audits that
            logger.info(
                "did not prepay %s into the mech balance: %s",
                amount,
                cause_of(refused),
            )
            return
        self._top_ups[chain] = top_up._replace(deposited=top_up.deposited + amount)
        self._rearm(chain, kind, armed)
        self._activity.record(
            "mech_prefund",
            chain=chain,
            tracker=top_up.tracker,
            amount=str(amount),
            balance=str(balance),
            rate=str(priced.rate),
        )

    def _rearm(self, chain: str, kind: PaymentType, armed: Armed) -> None:
        """Re-arm the deposit grant a prepaid deposit consumed, for the rest of the cap.

        The guard spends a deposit allowance whole, so after a prepaid
        deposit restricted mode would refuse the mech's 402 shortfall and
        lose the request. What is left of the cap is armed again, and only
        that: the two deposits of a send stay within its one cap.
        """
        top_up = self._top_ups[chain]
        remaining = top_up.cap - top_up.deposited
        if self._guard.mode() != MODE_RESTRICTED or remaining <= 0:
            return
        is_token = kind.is_token()
        grant = self._guard.allow_safe_deposit_once(
            chain=chain,
            tracker=top_up.tracker,
            amount_cap=remaining,
            is_token=is_token,
        )
        armed.append(functools.partial(self._guard.revoke_safe_deposit, grant))
        self._activity.record(
            "mech_deposit_allowance",
            chain=chain,
            tracker=top_up.tracker,
            amount_cap=str(remaining),
            is_token=is_token,
        )

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
        floor = (
            self._config.fund_requirements.get(chain, {})
            .get("safe", {})
            .get(NATIVE_ASSET, {})
            .get("threshold", 0)
        )
        return max(balance - floor, 0)

    def _deposit_service(
        self, chain: str, service: MarketplaceService
    ) -> DepositService:
        """Build, once per chain, the deposit path mech-client's own top-up takes."""
        deposits = self._deposits.get(chain)
        if deposits is None:
            deposits = DepositService(
                chain_config=service.chain_config,
                agent_mode=service.agent_mode,
                safe_address=service.safe_address,
                ethereum_client=service.ethereum_client,
                signer=service.signer,
                rpc_url=service.rpc_url,
            )
            self._deposits[chain] = deposits
        return deposits

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
