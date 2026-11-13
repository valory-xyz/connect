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

import functools
import logging
import typing as t

from mech_client import balance_tracker
from mech_client.infrastructure.config import PaymentType
from mech_client.services.marketplace_service import _MAX_AUTO_DEPOSIT_RATIO
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech_types import PricedMech
from connect.safe import safe_message_hash
from connect.settings import MODE_RESTRICTED

logger = logging.getLogger("agent")

# what one request armed, each entry withdrawing one grant (MechAllowances.revoke)
Armed = list[t.Callable[[], None]]


def deposit_tracker(chain: str, payment_type: str) -> tuple[str | None, bool]:
    """Resolve (tracker, is_token) for a payment type; (None, False) otherwise.

    The tracker is mech-client's `balance_tracker`, the contract its deposit
    path pays, so the allowance armed from this answer names the contract
    mech-client will actually pay. None where it names none (NVM
    subscriptions, no deployment, a chain it does not know): auto-deposit is
    then disarmed rather than a request dying mid-flow.
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

    def arm_auto_deposit(self, chain: str, priced: PricedMech, armed: Armed) -> bool:
        """Pre-authorize the one 402 top-up this request may send, and say so.

        Returns whether auto_deposit should stay on. The deposit pays the
        balance tracker from the safe, which restricted mode only allows
        through a one-shot allowance bounded by the same cap mech-client
        itself enforces on the shortfall (ratio x the mech's per-request
        rate). The audit record is written in every mode; the allowance is
        armed only while restricted — unrestricted needs none, and one armed
        there would outlive a switch back to restricted for its TTL.
        When no tracker resolves for the payment type, restricted mode
        disarms instead of letting the flow die mid-request on a guard
        denial; unrestricted stays armed.
        """
        restricted = self._guard.mode() == MODE_RESTRICTED
        tracker, is_token = deposit_tracker(chain, priced.payment_type)
        if tracker is None:
            if restricted:
                logger.info(
                    "no balance tracker for payment type %s on %s; auto_deposit "
                    "disarmed in restricted mode",
                    priced.payment_type,
                    chain,
                )
                return False
            return True
        amount_cap = _MAX_AUTO_DEPOSIT_RATIO * priced.rate
        if restricted:
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
        return True

    @staticmethod
    def revoke(armed: Armed) -> None:
        """Withdraw every grant a request armed: it ended with nothing sent.

        A refusal before the POST (mech-client's price cap or id check, the
        signer, the queue) must spend nothing, so no grant outlives it.
        """
        while armed:
            armed.pop()()
