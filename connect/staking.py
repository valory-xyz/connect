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

"""Connect's own staking: the epoch's Marketplace request, and the checkpoint.

The rules are the README's ("Staking").
"""

import logging
import typing as t
from concurrent.futures import ThreadPoolExecutor

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from hexbytes import HexBytes
from web3 import Web3
from web3.types import BlockIdentifier

from connect.activity import (
    ActivityLog,
    STAKING_CHECKPOINT_FAILED_KIND,
    STAKING_CHECKPOINT_KIND,
)
from connect.chain_read import selector_of
from connect.config import AppConfig, StakingConfig
from connect.guard import Guard
from connect.safe import CHECKPOINT_SELECTOR
from connect.server.receipts import wait_mined
from connect.settings import MODE_RESTRICTED
from connect.signer import SERVER_BUILT, Signer
from connect.signer_errors import cause_of, logged_cause

logger = logging.getLogger("agent")

STAKING_REMINDER = (
    "This agent is staked. Make one Marketplace request today to become eligible "
    "for OLAS activity rewards."
)

# livenessRatio is requests per second, scaled by 1e18
LIVENESS_RATIO_SCALE = 10**18
# the index of the Marketplace request count in the nonces both contracts keep
REQUEST_COUNT_INDEX = 1
CHECKPOINT_DATA = "0x" + CHECKPOINT_SELECTOR


def _selector(signature: str) -> bytes:
    """Return a function's 4-byte selector, as bytes."""
    return bytes.fromhex(selector_of(signature)[2:])


def _read_block(w3: Web3) -> BlockIdentifier:
    """Return the block every read of one decision is taken at (README, "Staking")."""
    return max(w3.eth.block_number - 1, 0)


def _call(
    w3: Web3, to: str, data: bytes, types: list[str], block: BlockIdentifier
) -> tuple:
    """Run one eth_call and decode what it returns."""
    raw = w3.eth.call({"to": to, "data": HexBytes(data)}, block)
    return abi_decode(types, bytes(raw))


def _uint(w3: Web3, to: str, signature: str, block: BlockIdentifier) -> int:
    """Read a no-argument uint256 view."""
    (value,) = _call(w3, to, _selector(signature), ["uint256"], block)
    return value


def _concurrently(*reads: t.Callable[[], t.Any]) -> list[t.Any]:
    """Run independent reads at once: one round trip's latency, not one per read."""
    with ThreadPoolExecutor(
        max_workers=len(reads), thread_name_prefix="staking-read"
    ) as pool:
        futures = [pool.submit(read) for read in reads]
        return [future.result() for future in futures]


def request_made_this_epoch(  # pylint: disable=too-many-locals
    w3: Web3, staking: StakingConfig
) -> bool:
    """Whether the program's safe made the epoch's Marketplace requests (README, "Staking").

    :raises ValueError: when the contract holds no record of this service and
        safe, or the checker answers in a shape it does not score.
    """
    block = _read_block(w3)
    checker, contract = staking.activity_checker, staking.staking_contract
    (
        (nonces,),
        ((multisig, _, staked_nonces, ts_start, _, _),),
        liveness_period,
        ts_checkpoint,
        ratio,
        chain_block,
    ) = _concurrently(
        lambda: _call(
            w3,
            checker,
            _selector("getMultisigNonces(address)")
            + abi_encode(["address"], [Web3.to_checksum_address(staking.safe)]),
            ["uint256[]"],
            block,
        ),
        lambda: _call(
            w3,
            contract,
            _selector("getServiceInfo(uint256)")
            + abi_encode(["uint256"], [staking.service_id]),
            ["(address,address,uint256[],uint256,uint256,uint256)"],
            block,
        ),
        lambda: _uint(w3, contract, "livenessPeriod()", block),
        lambda: _uint(w3, contract, "tsCheckpoint()", block),
        lambda: _uint(w3, checker, "livenessRatio()", block),
        lambda: w3.eth.get_block(block),
    )
    if len(staked_nonces) <= REQUEST_COUNT_INDEX:
        raise ValueError(
            f"service {staking.service_id} has no staking record on "
            f"{staking.staking_contract}"
        )
    if Web3.to_checksum_address(multisig) != Web3.to_checksum_address(staking.safe):
        raise ValueError(
            f"service {staking.service_id} is staked with multisig {multisig}, "
            f"not the configured safe {staking.safe}"
        )
    if len(nonces) <= REQUEST_COUNT_INDEX:
        raise ValueError(
            f"activity checker {staking.activity_checker} returns no Marketplace "
            "request count"
        )
    eligible = nonces[REQUEST_COUNT_INDEX] - staked_nonces[REQUEST_COUNT_INDEX]
    # the chain's time, not this host's, as the checkpoint gate reads it
    now = chain_block["timestamp"]
    window = max(now, ts_checkpoint + liveness_period) - max(ts_checkpoint, ts_start)
    # ceil, in integers; the checker passes no epoch without a new request
    required = max(-(-window * ratio // LIVENESS_RATIO_SCALE), 1)
    return eligible >= required


def read_staking_reminder(config: AppConfig, signer: Signer) -> str | None:
    """Return the reminder while the epoch's request is not made, else None.

    :raises Exception: whatever the read raised, so a caller can tell "nothing
        to say" from "could not tell".
    """
    staking = config.staking
    if staking is None:
        return None
    made = request_made_this_epoch(signer.w3(staking.chain), staking)
    return None if made else STAKING_REMINDER


def staking_reminder(config: AppConfig, signer: Signer) -> str | None:
    """Like read_staking_reminder, but a failed read is logged and reminds nothing."""
    try:
        return read_staking_reminder(config, signer)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning(
            "staking reminder skipped: could not read the staking state on %s: %s",
            config.staking.chain if config.staking else None,
            logged_cause(e),
        )
        return None


def _checkpoint_worth_sending(w3: Web3, contract: str) -> bool:
    """Whether checkpoint() is due and worth sending (README, "Staking")."""
    block = _read_block(w3)
    next_at = _uint(w3, contract, "getNextRewardCheckpointTimestamp()", block)
    ts_checkpoint = _uint(w3, contract, "tsCheckpoint()", block)
    liveness_period = _uint(w3, contract, "livenessPeriod()", block)
    if next_at != ts_checkpoint + liveness_period:
        return True
    # the chain's time, not this host's: a clock ahead would pay for no-op sends
    if w3.eth.get_block(block)["timestamp"] < next_at:
        return False
    return _uint(w3, contract, "availableRewards()", block) > 0


def checkpoint_if_due(
    config: AppConfig,
    signer: Signer,
    guard: Guard,
    activity: ActivityLog,
) -> str | None:
    """Send checkpoint() from the agent EOA once worth sending; return its tx hash, or None."""
    staking = config.staking
    if staking is None:
        return None
    chain = staking.chain
    tx_hash: str | None = None
    try:
        w3 = signer.w3(chain)
        if not _checkpoint_worth_sending(w3, staking.staking_contract):
            return None
        if guard.mode() == MODE_RESTRICTED:
            guard.allow_checkpoint_once(
                chain=chain, staking_contract=staking.staking_contract
            )
        tx_hash = signer.send(
            chain,
            staking.staking_contract,
            data=CHECKPOINT_DATA,
            audit=False,
            intent=SERVER_BUILT,
        )
        wait_mined(w3, tx_hash)
    except Exception as e:  # pylint: disable=broad-exception-caught
        guard.revoke_checkpoint(chain=chain, staking_contract=staking.staking_contract)
        logger.warning(
            "staking checkpoint on %s failed (tx %s): %s",
            chain,
            tx_hash,
            logged_cause(e),
        )
        activity.record(
            STAKING_CHECKPOINT_FAILED_KIND,
            chain=chain,
            staking_contract=staking.staking_contract,
            tx_hash=tx_hash,
            error=cause_of(e),
        )
        return None
    activity.record(
        STAKING_CHECKPOINT_KIND,
        chain=chain,
        staking_contract=staking.staking_contract,
        tx_hash=tx_hash,
    )
    return tx_hash
