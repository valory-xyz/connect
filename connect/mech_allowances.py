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

"""What the mech flow pre-authorizes with the guard before it signs or spends.

Restricted mode allows neither raw digest signing nor a safe call to an
address outside the whitelist, and an off-chain mech request needs both: the
safe's ERC-1271 wrap of a request id, and possibly one deposit to a balance
tracker. Rather than widen the mode, the flow registers exactly the digest and
exactly the payment it is about to make, single-use, moments before making it.

That makes this the module where the guardrail's carve-outs are earned, which
is why it is its own file: the reasoning is dense, it is the part a reviewer
must read most carefully, and none of it belongs to driving a request. The
derivations here trust no RPC for anything that gets signed — see
`request_digest`.
"""

import logging

from eth_abi import encode as abi_encode
from mech_client.infrastructure.config import (
    CHAIN_TO_NATIVE_BALANCE_TRACKER,
    CHAIN_TO_TOKEN_BALANCE_TRACKER_OLAS,
    CHAIN_TO_TOKEN_BALANCE_TRACKER_USDC,
    PaymentType,
)
from mech_client.infrastructure.ipfs.metadata import fetch_ipfs_hash
from mech_client.services.marketplace_service import (
    MarketplaceService,
    _MAX_AUTO_DEPOSIT_RATIO,
)
from mech_client.utils.constants import CHAIN_NAME_TO_ID
from web3 import Web3

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.mech_types import MechError, PricedMech
from connect.safe import ZERO_ADDRESS, safe_message_hash
from connect.settings import MODE_RESTRICTED

logger = logging.getLogger("agent")


def request_digest(  # pylint: disable=too-many-arguments
    *,
    domain_separator: bytes,
    marketplace: str,
    mech: str,
    requester: str,
    data_hash: bytes,
    delivery_rate: int,
    payment_type: bytes,
    nonce: int,
) -> bytes:
    r"""Recompute MechMarketplace.getRequestId locally — trusting no RPC for it.

    The id an off-chain request signs is EIP-712-shaped::

        keccak256("\x19\x01" ‖ domainSeparator ‖ keccak256(abi.encode(
            marketplace, mech, requester, keccak256(data),
            deliveryRate, paymentType, nonce)))

    (pinned byte-for-byte against the deployed gnosis marketplace by a
    golden-vector test). Deriving it here is what keeps the RPC out of the
    signing trust base: mech-client asks the *contract* for the id over
    eth_call, and were that answer signed on faith, a lying RPC could hand
    back any 32 bytes — a safe transaction hash included — and collect a
    signature on it. Locally derived, the digest is always our own keccak
    over a preimage we assembled, so a lying RPC (domain separator and nonce
    are still reads) can only produce a mismatch, which is refused.
    """
    struct_hash = Web3.keccak(
        abi_encode(
            [
                "address",
                "address",
                "address",
                "bytes32",
                "uint256",
                "bytes32",
                "uint256",
            ],
            [
                marketplace,
                mech,
                requester,
                Web3.keccak(data_hash),
                delivery_rate,
                payment_type,
                nonce,
            ],
        )
    )
    return bytes(Web3.keccak(b"\x19\x01" + domain_separator + struct_hash))


def deposit_tracker(chain: str, payment_type: str) -> tuple[str | None, bool]:
    """Resolve (tracker, is_token) for a payment type; (None, False) otherwise.

    The addresses come from the pinned mech-client's own constants — the same
    source its deposit path reads — so the allowance armed from this answer
    names the contract mech-client will actually pay. NVM subscription types
    resolve to nothing on purpose: mech-client's auto-deposit refuses them
    too. Malformed constants fail closed to (None, False) — auto-deposit is
    disarmed rather than a request dying mid-flow. (Unlike the settings-side
    readers of these tables, a wholly broken mech-client is not survivable
    here: this module hard-imports it at the top either way.)
    """
    try:
        chain_id = CHAIN_NAME_TO_ID.get(chain.lower())
        if chain_id is None:
            return None, False
        trackers_by_type: dict[str, tuple[dict, bool]] = {
            PaymentType.NATIVE.value: (CHAIN_TO_NATIVE_BALANCE_TRACKER, False),
            PaymentType.OLAS_TOKEN.value: (CHAIN_TO_TOKEN_BALANCE_TRACKER_OLAS, True),
            PaymentType.USDC_TOKEN.value: (CHAIN_TO_TOKEN_BALANCE_TRACKER_USDC, True),
        }
        entry = trackers_by_type.get(payment_type)
        if entry is None:
            return None, False
        tracker = str(entry[0].get(chain_id) or "").lower()
        if not tracker or tracker == ZERO_ADDRESS:
            return None, False
        return tracker, entry[1]
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("could not resolve the mech balance tracker: %s", e)
        return None, False


class MechAllowances:
    """Registers the single-use grants an off-chain mech request needs."""

    def __init__(self, config: AppConfig, guard: Guard, activity: ActivityLog) -> None:
        """Initialize."""
        self._config = config
        self._guard = guard
        self._activity = activity

    def register_offchain_digest(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        service: MarketplaceService,
        *,
        chain: str,
        priced: PricedMech,
        prompt: str,
        tool: str,
        salt: str,
    ) -> None:
        """Derive the digest mech-client will sign, and pre-authorize it once.

        The requester of record is the service safe (mech-client ≥0.21.3
        binds agent-mode off-chain requests to the safe on every surface),
        so the request id commits to the safe, the marketplace nonce is the
        safe's, and what actually gets signed is the ERC-1271 SafeMessage
        wrap of the request id — the allowance registers that wrapped hash,
        the same bytes MechSigner.sign_safe_message will produce.

        The request id commits to the metadata CID, which is deterministic
        here because the salt is pinned: fetch_ipfs_hash generates a random
        nonce but merges ``extra_attributes`` over it, so this method and
        mech-client (handed the same ``{"nonce": salt}`` moments later) run
        the same pure function on the same inputs and get the same CID. The
        domain separator and the marketplace nonce are RPC reads; a wrong
        answer makes the derived digest mismatch the one mech-client asks
        to sign, so the failure mode is a refusal, never a wrong signature.

        Audited: the allowance is what lets funds-adjacent signing happen in
        restricted mode, so the trail must show each one that was granted,
        not only the signatures that followed.
        """
        safe = self._config.chain(chain).safe_address
        if safe is None:
            # unreachable through request(): _service already refused the
            # chain — kept as a real error so the invariant is not silent
            raise MechError(
                f"no service safe is configured for chain '{chain}'; the "
                "off-chain requester of record is the safe"
            )
        try:
            # same private-but-pinned helper _watch already leans on
            # pylint: disable-next=protected-access
            contract = service._get_marketplace_contract()
            domain_separator = bytes(contract.functions.domainSeparator().call())
            nonce = int(
                contract.functions.mapNonces(Web3.to_checksum_address(safe)).call()
            )
            marketplace = str(contract.address)
        except Exception as e:
            raise MechError(
                f"could not derive the off-chain request digest: {e}"
            ) from e
        data_hash, _, _ = fetch_ipfs_hash(prompt, tool, {"nonce": salt})
        request_id = request_digest(
            domain_separator=domain_separator,
            marketplace=marketplace,
            mech=priced.mech,
            requester=safe,
            data_hash=bytes.fromhex(data_hash.removeprefix("0x")),
            delivery_rate=priced.rate,
            payment_type=bytes.fromhex(priced.payment_type),
            nonce=nonce,
        )
        # the chain id mech-client passes to sign_safe_message for this chain
        chain_id = int(service.mech_config.ledger_config.chain_id)
        digest = safe_message_hash(safe, chain_id, request_id)
        if self._guard.mode() == MODE_RESTRICTED:
            self._guard.allow_digest_once(digest)
        self._activity.record(
            "mech_offchain_digest",
            chain=chain,
            mech=priced.mech,
            request_id="0x" + request_id.hex(),
            digest="0x" + digest.hex(),
            nonce=nonce,
        )

    def arm_auto_deposit(self, chain: str, priced: PricedMech) -> bool:
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
            self._guard.allow_safe_deposit_once(
                chain=chain, tracker=tracker, amount_cap=amount_cap, is_token=is_token
            )
        self._activity.record(
            "mech_deposit_allowance",
            chain=chain,
            tracker=tracker,
            amount_cap=str(amount_cap),
            is_token=is_token,
        )
        return True
