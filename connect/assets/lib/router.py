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

"""The calls a safe makes to swap through the Universal Router, verified."""

import time
import typing as t

import evm
import permit
import uniswap
from web3 import Web3

DEADLINE_S = 600
PERMIT_SIGNED = "signed into the swap"
PERMIT_AT_SEND = "signed into the swap at send time (placeholder in this dry run)"
PERMIT_SEPARATE = "separate transaction"
PERMIT_NONE = "not needed for the native coin"


class RouterSwap(t.NamedTuple):
    """The calls that execute one swap, their deadline and how it was permitted."""

    calls: list[evm.Call]
    deadline: int
    permit: str


def approval_calls(
    chain_id: int, token_in: str, amount: int, expiry: int
) -> list[evm.Call]:
    """Exact-amount approvals: ERC-20 to Permit2, then Permit2 to the router."""
    where = uniswap.deployment(chain_id)
    return [
        evm.erc20_approval_call(token_in, where["permit2"], amount, "approve Permit2"),
        permit.approval_call(
            where["permit2"], token_in, where["universal_router"], amount, expiry
        ),
    ]


def router_swap(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    w3: Web3,
    signer: t.Any,
    account: str,
    chain_id: int,
    pool: uniswap.Pool,
    token_in: str,
    token_out: str,
    amount: int,
    minimum: int,
    separate_approvals: bool,
    calls_ahead: int = 0,
    dry_run: bool = False,
) -> RouterSwap:
    """Build, decode and check the approvals and swap that trade ``amount``.

    Raises:
        SwapError: for a refused signature or calldata that does not say what
            was planned.
    """
    where = uniswap.deployment(chain_id)
    spender = where["universal_router"]
    native = evm.is_native(token_in)
    fold = signer is not None and not separate_approvals and not native
    approvals = 0 if native else 1 if fold else 2
    deadline = (
        int(time.time())
        + DEADLINE_S
        + evm.RECEIPT_TIMEOUT_S * (approvals + calls_ahead)
    )
    action = (
        permit.signed_action(
            w3,
            signer,
            account,
            token_in,
            amount,
            where["permit2"],
            spender,
            deadline,
            placeholder=dry_run,
        )
        if fold
        else None
    )
    calldata = uniswap.build_execute(
        pool, token_in, token_out, amount, minimum, account, deadline, action
    )
    uniswap.verify_execute(
        calldata, pool, token_in, token_out, amount, minimum, account, deadline
    )
    signed = uniswap.permit_action_in(calldata)
    if fold != (signed is not None):
        raise evm.SwapError(
            "a permit was signed but is not in the calldata we would send"
            if fold
            else "the calldata carries a permit nobody asked for"
        )
    if signed is not None:
        permit.verify_action(signed, token_in, spender, amount, deadline)
    if native:
        calls: list[evm.Call] = []
        label = PERMIT_NONE
    elif fold:
        calls = [
            evm.erc20_approval_call(
                token_in, where["permit2"], amount, "approve Permit2"
            )
        ]
        label = PERMIT_AT_SEND if dry_run else PERMIT_SIGNED
    else:
        calls = approval_calls(chain_id, token_in, amount, deadline)
        label = PERMIT_SEPARATE
    swap: evm.Call = {"to": spender, "data": calldata, "what": "swap"}
    if native:
        swap["value"] = amount
    calls.append(swap)
    return RouterSwap(calls, deadline, label)
