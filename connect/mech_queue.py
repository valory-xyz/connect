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
STORE_PATH/mech_nonces.json; this holds it, and says when a safe's queue on a
chain is stalled.
"""

from mech_client import NonceAllocator

from connect.config import AppConfig

STALL_NOTE = (
    "; mech_queue_stalled: the mech is not settling this safe's requests in "
    "order, so only a request at the settled nonce is sent until one is "
    "accepted again"
)


class MechQueue:
    """mech-client's allocator for the safes, and what a stall reports."""

    def __init__(self, config: AppConfig) -> None:
        """Load the allocator's persisted queues from STORE_PATH."""
        self._config = config
        self.allocator = NonceAllocator(
            config.store_path,
            settle_timeout=config.mech_settle_timeout,
            gap_retries=config.mech_gap_retries,
        )

    def report(self, chain: str) -> dict:
        """Report whether the safe's queue on `chain` is stalled."""
        safe = self._config.chain(chain).safe_address
        if safe is None or not self.allocator.stalled(chain, safe):
            return {}
        return {"mech_queue_stalled": True}

    def note(self, chain: str) -> str:
        """Say, in a refusal, that the safe's queue on `chain` is stalled."""
        return STALL_NOTE if self.report(chain) else ""
