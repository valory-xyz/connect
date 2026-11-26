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
    STAKING_CHECKPOINT_FAILED_KIND,
    STAKING_CHECKPOINT_KIND,
    ActivityLog,
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
    "This agent is staked. Make one Marketplace request today to earn your OLAS "
    "staking rewards."
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


def _call(
    w3: Web3, to: str, data: bytes, types: list[str], block: BlockIdentifier = "latest"
) -> tuple:
    """Run one eth_call and decode what it returns."""
    raw = w3.eth.call(
        {"to": Web3.to_checksum_address(to), "data": HexBytes(data)}, block
    )
    return abi_decode(types, bytes(raw))


def _uint(
    w3: Web3, to: str, signature: str, block: BlockIdentifier = "latest"
) -> int:
    """Read a no-argument uint256 view."""
    (value,) = _call(w3, to, _selector(signature), ["uint256"], block)
    return int(value)


def is_staked(config: AppConfig) -> bool:
    """Whether Pearl staked this instance with a program Connect can use."""
    return config.staking is not None


def request_made_this_epoch(w3: Web3, staking: StakingConfig, now: int) -> bool:
    """Whether the program's safe made the epoch's Marketplace requests, as of `now`.

    :raises ValueError: when the contract holds no record of the service.
    """
    (nonces,) = _call(
        w3,
        staking.activity_checker,
        _selector("getMultisigNonces(address)")
        + abi_encode(["address"], [Web3.to_checksum_address(staking.safe)]),
        ["uint256[]"],
    )
    ((_, _, staked_nonces, _, _, _),) = _call(
        w3,
        staking.staking_contract,
        _selector("getServiceInfo(uint256)")
        + abi_encode(["uint256"], [staking.service_id]),
        ["(address,address,uint256[],uint256,uint256,uint256)"],
    )
    if len(staked_nonces) <= REQUEST_COUNT_INDEX:
        raise ValueError(
            f"service {staking.service_id} has no staking record on "
            f"{staking.staking_contract}"
        )
    eligible = nonces[REQUEST_COUNT_INDEX] - staked_nonces[REQUEST_COUNT_INDEX]
    liveness_period = _uint(w3, staking.staking_contract, "livenessPeriod()")
    since_checkpoint = now - _uint(w3, staking.staking_contract, "tsCheckpoint()")
    ratio = _uint(w3, staking.activity_checker, "livenessRatio()")
    # ceil(max(livenessPeriod, since_checkpoint) * ratio / 1e18), in integers
    required = -(
        -max(liveness_period, since_checkpoint) * ratio // LIVENESS_RATIO_SCALE
    )
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


def _checkpoint_worth_sending(w3: Web3, contract: str, now: int) -> bool:
    """Whether checkpoint() is due and worth sending (README, "Staking")."""
    # one block for every read: another service's checkpoint landing between
    # them would read as a pending rebaseline
    block = w3.eth.block_number
    next_at = _uint(w3, contract, "getNextRewardCheckpointTimestamp()", block)
    ts_checkpoint = _uint(w3, contract, "tsCheckpoint()", block)
    liveness_period = _uint(w3, contract, "livenessPeriod()", block)
    if next_at != ts_checkpoint + liveness_period:
        return True
    if now < next_at:
        return False
    return _uint(w3, contract, "availableRewards()", block) > 0


def checkpoint_if_due(
    config: AppConfig,
    signer: Signer,
    guard: Guard,
    activity: ActivityLog,
    now: t.Callable[[], float] = time.time,
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
        if not _checkpoint_worth_sending(w3, staking.staking_contract, int(now())):
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
