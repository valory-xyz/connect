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

import logging
import typing as t

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


def marketplace_contract(service: t.Any) -> t.Any:
    """Return a mech-client service's marketplace contract.

    mech-client exposes it only through a private helper; every use in Connect
    goes through here, so a rename upstream breaks one place, not three.
    """
    return service._get_marketplace_contract()  # pylint: disable=protected-access


def read_map_nonces(contract: t.Any, safe: str) -> int:
    """Read the marketplace's settled nonce for `safe` (an RPC read)."""
    return int(contract.functions.mapNonces(Web3.to_checksum_address(safe)).call())


class OffchainDigests:  # pylint: disable=too-many-instance-attributes
    """Everything an off-chain request id commits to, except its nonce."""

    def __init__(  # pylint: disable=too-many-arguments
        self,
        *,
        allowances: "MechAllowances",
        contract: t.Any,
        chain: str,
        safe: str,
        chain_id: int,
        domain_separator: bytes,
        marketplace: str,
        mech: str,
        data_hash: bytes,
        delivery_rate: int,
        payment_type: bytes,
    ) -> None:
        """Initialize."""
        self._allowances = allowances
        self._contract = contract
        self.chain = chain
        self.safe = safe
        self.chain_id = chain_id
        self.domain_separator = domain_separator
        self.marketplace = marketplace
        self.mech = mech
        self.data_hash = data_hash
        self.delivery_rate = delivery_rate
        self.payment_type = payment_type

    def map_nonces(self) -> int:
        """Read the marketplace's settled nonce for the safe."""
        return read_map_nonces(self._contract, self.safe)

    def request_id(self, nonce: int) -> bytes:
        """Recompute the request id for `nonce`, trusting no RPC for it."""
        return request_digest(
            domain_separator=self.domain_separator,
            marketplace=self.marketplace,
            mech=self.mech,
            requester=self.safe,
            data_hash=self.data_hash,
            delivery_rate=self.delivery_rate,
            payment_type=self.payment_type,
            nonce=nonce,
        )

    def on_request_id(self, request_id: bytes, nonce: int) -> None:
        """mech-client's pre-sign hook: verify the id, then arm its signature."""
        self._allowances.arm(self, request_id, nonce)


class MechAllowances:
    """Registers the single-use grants an off-chain mech request needs."""

    def __init__(self, config: AppConfig, guard: Guard, activity: ActivityLog) -> None:
        """Initialize."""
        self._config = config
        self._guard = guard
        self._activity = activity

    def offchain_digests(  # pylint: disable=too-many-arguments
        self,
        service: MarketplaceService,
        *,
        chain: str,
        priced: PricedMech,
        prompt: str,
        tool: str,
        extra_attributes: dict,
    ) -> "OffchainDigests":
        """Read what the request id depends on, before anything is armed.

        The requester of record is the service safe (mech-client >=0.21.3
        binds agent-mode off-chain requests to the safe on every surface), so
        the request id commits to the safe and the marketplace nonce is the
        safe's. The id also commits to the metadata CID, which is
        deterministic here because the salt is pinned: fetch_ipfs_hash merges
        ``extra_attributes`` over its random nonce, so this and mech-client
        run the same pure function on the same inputs.
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
            contract = marketplace_contract(service)
            domain_separator = bytes(contract.functions.domainSeparator().call())
            marketplace = str(contract.address)
        except Exception as e:
            raise MechError(
                f"could not derive the off-chain request digest: {e}"
            ) from e
        data_hash, _, _ = fetch_ipfs_hash(prompt, tool, extra_attributes)
        return OffchainDigests(
            allowances=self,
            contract=contract,
            chain=chain,
            safe=safe,
            # the chain id mech-client passes to sign_safe_message here
            chain_id=int(service.mech_config.ledger_config.chain_id),
            domain_separator=domain_separator,
            marketplace=marketplace,
            mech=priced.mech,
            data_hash=bytes.fromhex(data_hash.removeprefix("0x")),
            delivery_rate=priced.rate,
            payment_type=bytes.fromhex(priced.payment_type),
        )

    def arm(self, digests: "OffchainDigests", request_id: bytes, nonce: int) -> None:
        """Pre-authorize, once, the signature on a request id mech-client reports.

        mech-client hands the id over just before signing (``on_request_id``),
        but it asked the *contract* for that id over eth_call: signed on
        faith, a lying RPC could return any 32 bytes, a Permit2 digest
        included, and collect the safe's ERC-1271 signature on it. So the id
        is recomputed here from what Connect assembled and the nonce Connect
        allocated, and a mismatch is refused before anything is signed.

        Audited in every mode; the allowance is armed only while restricted.
        """
        expected = digests.request_id(nonce)
        if bytes(request_id) != expected:
            self._activity.record(
                "mech_offchain_digest_mismatch",
                chain=digests.chain,
                mech=digests.mech,
                reported="0x" + bytes(request_id).hex(),
                expected="0x" + expected.hex(),
                nonce=nonce,
            )
            raise MechError(
                "the request id mech-client is about to sign is not the one "
                "this server derives for it; nothing was signed"
            )
        digest = safe_message_hash(digests.safe, digests.chain_id, expected)
        if self._guard.mode() == MODE_RESTRICTED:
            self._guard.allow_digest_once(digest)
        self._activity.record(
            "mech_offchain_digest",
            chain=digests.chain,
            mech=digests.mech,
            request_id="0x" + expected.hex(),
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
