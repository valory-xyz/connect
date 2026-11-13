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

"""The safe's off-chain marketplace queue on each chain, as Connect reports it.

The queue itself is mech-client's NonceAllocator, persisted in
STORE_PATH/mech_nonces.json; this holds it, says when a safe's queue on a
chain is stalled, and runs the operator's hard cancel (D27): one on-chain
marketplace request from the safe that consumes the stuck mapNonces.
"""

import asyncio
import time
import typing as t

from mech_client import NonceAllocator
from mech_client.services.marketplace_service import MarketplaceService
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.mech_allowances import read_map_nonces
from connect.mech_budget import DEFAULT_MAX_PAYMENT
from connect.mech_types import MechError

STALL_NOTE = (
    "; mech_queue_stalled: the mech is not settling this safe's requests in "
    "order, so only a request at the settled nonce is sent until one is "
    "accepted again"
)
HARD_CANCEL_AVAILABLE = (
    "available: the operator can confirm one on-chain request in Connect's UI"
)
# what the hard cancel's on-chain request asks; it exists to consume a nonce
HARD_CANCEL_PROMPT = "Connect hard cancel: consumes this safe's stuck marketplace nonce"
# the hard cancel only needs its transaction mined, not the mech's answer
HARD_CANCEL_WAIT_SECONDS = 1.0


class MechQueue:
    """mech-client's allocator for the safes, what a stall reports, its cancel."""

    def __init__(
        self,
        config: AppConfig,
        activity: ActivityLog,
        clock: t.Callable[[], float] = time.time,
    ) -> None:
        """Load the allocator's persisted queues from STORE_PATH."""
        self._config = config
        self._activity = activity
        self._clock = clock
        self.allocator = NonceAllocator(
            config.store_path,
            settle_timeout=config.mech_settle_timeout,
            gap_retries=config.mech_gap_retries,
            clock=clock,
        )

    def report(self, chain: str) -> dict:
        """Report whether the safe's queue on `chain` is stalled, and since when.

        Once it has been stalled for MECH_HARD_CANCEL_AFTER, the report says
        the operator's hard cancel is available; the session cannot run it.
        """
        safe = self._config.chain(chain).safe_address
        since = None if safe is None else self.allocator.stalled_since(chain, safe)
        if since is None:
            return {}
        report: dict = {"mech_queue_stalled": True}
        if self._clock() - since >= self._config.mech_hard_cancel_after:
            report["hard_cancel"] = HARD_CANCEL_AVAILABLE
        return report

    def note(self, chain: str) -> str:
        """Say, in a refusal, that the safe's queue on `chain` is stalled."""
        report = self.report(chain)
        if not report:
            return ""
        cancel = report.get("hard_cancel")
        return STALL_NOTE + (f"; hard_cancel: {cancel}" if cancel else "")

    def status(self) -> dict:
        """Report every safe's queue, per chain, for the operator's UI."""
        status = {}
        for chain in sorted(self._config.chains):
            safe = self._config.chains[chain].safe_address
            if safe is None:
                continue
            since = self.allocator.stalled_since(chain, safe)
            status[chain] = {
                "stalled": since is not None,
                "stalled_since": since,
                "hard_cancel_available": bool(self.report(chain).get("hard_cancel")),
            }
        return status

    def hard_cancel(self, service: MarketplaceService, chain: str) -> dict:
        """Consume the stuck mapNonces with one on-chain request, and audit it.

        mech-client's `allocator.hard_cancel` refuses (`mech-queue-not-stalled`)
        unless the queue has been stalled for MECH_HARD_CANCEL_AFTER, and holds
        the queue meanwhile. The request goes to the mech of the stuck slot,
        capped by that mech's default max_payment, and is signed like any
        on-chain mech request: through the guard, server-built.

        :raises NonceRefused: the allocator's refusal, naming its rule.
        :raises MechError: no stuck mech, or nothing to send it with.
        """
        # the service was built for this chain, so it has a safe
        safe = t.cast(str, self._config.chain(chain).safe_address)
        contract = service.marketplace_contract()
        with self.allocator.hard_cancel(
            chain,
            safe,
            lambda: read_map_nonces(contract, safe),
            stalled_for=self._config.mech_hard_cancel_after,
        ) as nonce:
            mech = self._stuck_mech(chain, safe, nonce)
            info = service.mech_info(mech)
            cap = DEFAULT_MAX_PAYMENT.get(info.payment_type)
            tools = (
                service.tool_manager.read_tools_metadata(info.service_id).document or {}
            ).get("tools")
            if cap is None or not isinstance(tools, list) or not tools:
                raise MechError(
                    f"cannot hard cancel through mech {mech}: it has no default "
                    "budget or publishes no tool to send"
                )
            result = asyncio.run(
                service.send_request(
                    prompts=(HARD_CANCEL_PROMPT,),
                    tools=(str(tools[0]),),
                    priority_mech=mech,
                    use_offchain=False,
                    max_price=cap,
                    timeout=HARD_CANCEL_WAIT_SECONDS,
                )
            )
        report = {
            "tx_hash": str(result.get("tx_hash")),
            "nonce": nonce,
            "mech": mech,
            "paid": str(info.max_delivery_rate),
        }
        self._activity.record("mech_hard_cancel", chain=chain, **report)
        return report

    def _stuck_mech(self, chain: str, safe: str, nonce: int) -> str:
        """Return the mech of the safe's slot at `nonce`, else its lowest held one.

        mech-client exposes no reader of a held slot, so this reads the
        allocator's queue directly (a private, so it is the one place that does).
        """
        queue = self.allocator._queue(  # pylint: disable=protected-access
            self.allocator.key(chain, safe)
        )
        slots = dict(queue.slots)
        slot = slots.get(nonce) or (slots[min(slots)] if slots else None)
        if slot is None:
            raise MechError(
                f"this safe holds no off-chain slot on {chain}, so there is no "
                "stuck request's mech to send the hard cancel to"
            )
        return Web3.to_checksum_address(slot.mech)
