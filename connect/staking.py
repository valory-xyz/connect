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
import time
import typing as t

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

# the reminder the session gives while the epoch's request is not made
STAKING_REMINDER = (
    "This agent is staked. Make one Marketplace request today to become eligible "
    "for OLAS activity rewards."
)

# livenessRatio is requests per second, scaled by 1e18
LIVENESS_RATIO_SCALE = 10**18
# the index of the Marketplace request count in the nonces both contracts keep
REQUEST_COUNT_INDEX = 1
# the server's one staking call: checkpoint(), no arguments
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
    raw = w3.eth.call(
        {"to": Web3.to_checksum_address(to), "data": HexBytes(data)}, block
    )
    return abi_decode(types, bytes(raw))


def _uint(w3: Web3, to: str, signature: str, block: BlockIdentifier) -> int:
    """Read a no-argument uint256 view."""
    (value,) = _call(w3, to, _selector(signature), ["uint256"], block)
    return int(value)


def request_made_this_epoch(w3: Web3, staking: StakingConfig, now: int) -> bool:
    """Whether the program's safe made the epoch's Marketplace requests, as of `now`.

    Scores the count as RequesterActivityCheckerV2 does (every Connect program's
    checker; README, "Staking"), over the window the contract will measure.

    :raises ValueError: when the contract holds no record of this service and
        safe, or the checker answers in a shape it does not score.
    """
    block = _read_block(w3)
    (nonces,) = _call(
        w3,
        staking.activity_checker,
        _selector("getMultisigNonces(address)")
        + abi_encode(["address"], [Web3.to_checksum_address(staking.safe)]),
        ["uint256[]"],
        block,
    )
    ((multisig, _, staked_nonces, ts_start, _, _),) = _call(
        w3,
        staking.staking_contract,
        _selector("getServiceInfo(uint256)")
        + abi_encode(["uint256"], [staking.service_id]),
        ["(address,address,uint256[],uint256,uint256,uint256)"],
        block,
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
    liveness_period = _uint(w3, staking.staking_contract, "livenessPeriod()", block)
    ts_checkpoint = _uint(w3, staking.staking_contract, "tsCheckpoint()", block)
    ratio = _uint(w3, staking.activity_checker, "livenessRatio()", block)
    # the contract measures from max(tsCheckpoint, tsStart) to the checkpoint,
    # which lands no earlier than tsCheckpoint + livenessPeriod
    window = max(now, ts_checkpoint + liveness_period) - max(ts_checkpoint, ts_start)
    required = -(-window * ratio // LIVENESS_RATIO_SCALE)  # ceil, in integers
    return eligible >= required


def staking_reminder(
    config: AppConfig, signer: Signer, now: t.Callable[[], float] = time.time
) -> str | None:
    """Return the reminder for a session opening now, or None.

    None while unstaked, once the request is made, and whenever the staking
    state cannot be read: a failed read is logged and never reminds.
    """
    staking = config.staking
    if staking is None:
        return None
    chain = staking.chain
    try:
        made = request_made_this_epoch(signer.w3(chain), staking, int(now()))
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning(
            "staking reminder skipped: could not read the staking state on %s: %s",
            chain,
            logged_cause(e),
        )
        return None
    return None if made else STAKING_REMINDER


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
    """Call checkpoint() from the agent EOA once it is due; return the tx hash.

    None while unstaked, while it is not worth sending, and on a failure, which
    is logged and audited; the caller's next tick retries it.
    """
    staking = config.staking
    if staking is None:
        return None
    chain = staking.chain
    tx_hash: str | None = None
    try:
        w3 = signer.w3(chain)
        if not _checkpoint_worth_sending(w3, staking.staking_contract):
            return None
        # armed only while restricted, as for the agent top-up: one armed in
        # unrestricted mode would outlive a switch back for its TTL
        if guard.mode() == MODE_RESTRICTED:
            guard.allow_checkpoint_once(
                chain=chain, staking_contract=staking.staking_contract
            )
        tx_hash = signer.send(
            chain,
            staking.staking_contract,
            data=CHECKPOINT_DATA,
            # audited below under its own kind, outside the agent's activity
            audit=False,
            # the server's own call, fixed to checkpoint() on the configured
            # contract with no value: no session intent applies
            intent=SERVER_BUILT,
        )
        wait_mined(w3, tx_hash)
    except Exception as e:  # pylint: disable=broad-exception-caught
        # cause_of, not the text: an RPC library's words may carry the RPC key
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
