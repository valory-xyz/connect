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

"""Unit tests for the connect-stocktokens skill's calldata encoding.

The golden fixtures are real Universal Router calldata that Uniswap's own
Trading API produced for chain 4663, captured once. Our encoder has to
reproduce them byte for byte: a v4 single-hop swap and a v3 single-hop leg.
That is what "parity" means here - not that the bytes look plausible, but
that the router receives exactly what Uniswap's own router encoder sends.

Both swap inputs carry an undocumented ``uint256[] minHopPriceX36`` that is
easy to miss; leaving it out made the router revert with SliceOutOfBounds().

Uniswap appends a 22-byte attribution tag (it contains the ASCII "unix") after
the ABI-encoded arguments. The router ignores trailing calldata, and tagging
our swaps as theirs would be a lie, so parity is asserted up to that suffix.
"""

import argparse
import json
import os
import runpy
import shutil
import subprocess  # nosec B404 - runs our own bootstrap under test
import sys
import time
import typing as t
from decimal import Decimal
from pathlib import Path

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

ASSETS = Path(__file__).resolve().parent.parent / "connect" / "assets"
SKILL = ASSETS / "skills" / "connect-stocktokens" / "scripts"
sys.path.insert(0, str(ASSETS / "lib"))
sys.path.insert(0, str(SKILL))

import evm  # noqa: E402  pylint: disable=wrong-import-position
import permit  # noqa: E402  pylint: disable=wrong-import-position
import pools  # noqa: E402  pylint: disable=wrong-import-position
import router  # noqa: E402  pylint: disable=wrong-import-position
import stocktokens  # noqa: E402  pylint: disable=wrong-import-position
import swap  # noqa: E402  pylint: disable=wrong-import-position
import uniswap  # noqa: E402  pylint: disable=wrong-import-position

V4_CALLDATA = "0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006aa92d1f00000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003070b0e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000200000000000000000000000005fc5360d0400a0fd4f2af552add042d716f1d16800000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000003b9aca000000000000000000000000000000000000000000000000003dfbc473d1438df600000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000d0601ce157db5bdc3162bbac2a2c8af5320d9eec00000000000000000000000000000000000000000000000000000000000000640000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000c847858d25ba9af7d74b59c71d8b21d400000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000005fc5360d0400a0fd4f2af552add042d716f1d168000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000d0601ce157db5bdc3162bbac2a2c8af5320d9eec000000000000000000000000c9bebba9f481b12ce6f3ea54c4b182c9636ec4210000000000000000000000000000000000000000000000000000000000000000756e6978000001a0a4bc1e778000b899fd00baea0100"
V4_DEADLINE = 1789472031
V4_AMOUNT = 1000000000
V4_MIN = 4466379457179127286
V4_MINHOP = 4466379457179127286100000000000000000000000000
V4_RECIPIENT = "0xc9bebba9f481b12ce6f3ea54c4b182c9636ec421"
V4_POOL: uniswap.PoolV4 = {
    "version": "v4",
    "fee": 100,
    "tick_spacing": 1,
    "hooks": uniswap.NO_HOOKS,
    "pool_id": "0x" + "00" * 32,
    "liquidity": 1,
    "quote": "USDG",
    "quote_address": stocktokens.USDG,
}

V3_INPUT = "000000000000000000000000c9bebba9f481b12ce6f3ea54c4b182c9636ec4210000000000000000000000000000000000000000000000000000000017d7840000000000000000000000000000000000000000000000000018cb72ef498f12e400000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000002b5fc5360d0400a0fd4f2af552add042d716f1d1680001f4d0601ce157db5bdc3162bbac2a2c8af5320d9eec000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000c84a48ce0fcc82885fb6da4cd548e5fd000000"
V3_AMOUNT = 400000000
V3_MIN = 1786648049239397092
V3_MINHOP = 4466620123098492732125000000000000000000000000
V3_RECIPIENT = "0xc9bebba9f481b12ce6f3ea54c4b182c9636ec421"
ATTRIBUTION_TAG = b"unix"
USDG = stocktokens.USDG
NVDA = "0xd0601ce157db5bdc3162bbac2a2c8af5320d9eec"
LIVE_NVDA_USDG_V3_500 = "0xd4EB21209C4D6093f80B5b84f5C45cc093EA14a3"
LIVE_NVDA_USDG_V2 = "0xeE6F200063a53Fe9450578d99c0F8eAD4952c97a"
V3_POOL: uniswap.PoolV3 = {
    "version": "v3",
    "fee": 500,
    "address": LIVE_NVDA_USDG_V3_500,
    "quote": "USDG",
    "quote_address": stocktokens.USDG,
}


@pytest.fixture(name="their_minhop")
def _their_minhop(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the API's per-hop price bound so bytes can be compared directly."""
    monkeypatch.setattr(uniswap, "NO_HOP_PRICE_LIMIT", [V4_MINHOP])


def test_v4_execute_is_byte_identical_to_uniswaps(their_minhop: None) -> None:
    """Our whole execute() call matches the Trading API's, byte for byte."""
    del their_minhop
    ours = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    tag = V4_CALLDATA[len(ours) :]
    assert ours == V4_CALLDATA[: len(ours)]
    assert bytes.fromhex(tag).startswith(ATTRIBUTION_TAG)


def test_we_do_not_wear_uniswaps_attribution_tag() -> None:
    """Their calldata is tagged as theirs; ours carries no tag at all."""
    ours = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    assert ATTRIBUTION_TAG in bytes.fromhex(V4_CALLDATA[2:])
    assert ATTRIBUTION_TAG not in bytes.fromhex(ours[2:])


def test_v3_input_is_byte_identical_to_uniswaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Our v3 router input matches the one Uniswap's API produced."""
    monkeypatch.setattr(uniswap, "NO_HOP_PRICE_LIMIT", [V3_MINHOP])
    ours = uniswap._v3_swap_input(  # pylint: disable=protected-access
        V3_POOL, USDG, NVDA, V3_AMOUNT, V3_MIN, V3_RECIPIENT
    )
    assert ours.hex() == V3_INPUT


def test_router_inputs_carry_the_per_hop_price_array() -> None:
    """The trailing uint256[] is present; without it the router reverts."""
    blob = uniswap._v3_swap_input(  # pylint: disable=protected-access
        V3_POOL, USDG, NVDA, V3_AMOUNT, V3_MIN, V3_RECIPIENT
    )
    fields = abi_decode(
        ["address", "uint256", "uint256", "bytes", "bool", "uint256[]"], blob
    )
    assert fields[5] == (0,)


def test_approvals_are_for_the_exact_amount() -> None:
    """Never an unlimited Permit2 allowance, whatever the API's own permit does."""
    amount = 1_234_567
    erc20, permit2 = router.approval_calls(CHAIN_ID, USDG, amount, 1789473030)
    spender, approved = abi_decode(
        ["address", "uint256"], bytes.fromhex(erc20["data"][10:])
    )
    assert spender.lower() == uniswap.DEPLOYMENTS[4663]["permit2"].lower()
    assert approved == amount
    decoded = abi_decode(
        ["address", "address", "uint160", "uint48"], bytes.fromhex(permit2["data"][10:])
    )
    assert decoded[2] == amount
    assert decoded[2] != 2**160 - 1


def test_verify_execute_rejects_a_swapped_recipient() -> None:
    """A recipient that is not the one we planned must never reach the signer."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    with pytest.raises(evm.SwapError, match="recipient"):
        uniswap.verify_execute(
            calldata,
            V4_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            uniswap.DEPLOYMENTS[4663]["permit2"],
            V4_DEADLINE,
        )


def test_verify_execute_rejects_a_lowered_floor() -> None:
    """The floor in the bytes must be the floor the caller was shown."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    with pytest.raises(evm.SwapError, match="minimum_out"):
        uniswap.verify_execute(
            calldata,
            V4_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN - 1,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


def test_verify_execute_accepts_every_version() -> None:
    """v2, v3 and v4 calldata all decode back to what was planned."""
    v2_pool: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": NVDA}
    for pool in (V4_POOL, V3_POOL, v2_pool):
        calldata = uniswap.build_execute(
            pool, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )
        uniswap.verify_execute(
            calldata, pool, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )


def test_v2_quote_uses_the_constant_product_with_fee() -> None:
    """The local v2 maths matches the pair's own 0.3% constant product."""

    class _Eth:
        """Minimal eth stub returning reserves then token0."""

        def __init__(self) -> None:
            self.calls = 0

        def call(self, _tx: dict) -> bytes:
            """Reserves on the first call, token0 on the second."""
            self.calls += 1
            if self.calls == 1:
                return (1_000_000 * 10**6).to_bytes(32, "big") + (
                    5_000 * 10**18
                ).to_bytes(32, "big")
            return bytes(12) + bytes.fromhex(USDG[2:])

    class _W3:
        """Web3 stub exposing only .eth."""

        eth = _Eth()

    amount = 1_000 * 10**6
    pair: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": USDG}
    got = uniswap._quote_v2(  # pylint: disable=protected-access
        _W3(), pair, USDG, NVDA, amount
    )
    fee_adjusted = amount * 997
    expected = (fee_adjusted * 5_000 * 10**18) // (
        1_000_000 * 10**6 * 1000 + fee_adjusted
    )
    assert got == expected


def test_price_gap_refuses_when_there_is_no_reference() -> None:
    """A missing reference must not read as "priced exactly right"."""
    with pytest.raises(evm.SwapError, match="no usable Robinhood reference"):
        stocktokens.price_gap_bps(1_000, 0)


def test_price_gap_is_negative_when_the_pool_beats_robinhood() -> None:
    """Pools often price better than the desk; that is not a problem."""
    assert stocktokens.price_gap_bps(1_010, 1_000) == pytest.approx(-100.0)


def test_check_price_gap_allows_an_ordinary_spread() -> None:
    """The median liquid ticker sits ~23 bps off; that must still trade."""
    assert stocktokens.check_price_gap(9_977, 10_000) == pytest.approx(23.0)


def test_check_price_gap_refuses_a_dislocated_pool() -> None:
    """The RDDT case: a pool a percent-plus off the underlying is refused."""
    with pytest.raises(evm.SwapError, match="bps worse than Robinhood"):
        stocktokens.check_price_gap(9_800, 10_000)


def test_check_price_gap_limit_is_configurable() -> None:
    """An operator can tighten the limit below the shipped default."""
    with pytest.raises(evm.SwapError, match="limit 10"):
        stocktokens.check_price_gap(9_977, 10_000, max_gap_bps=10.0)


PERMIT2 = uniswap.DEPLOYMENTS[4663]["permit2"]
CHAIN_ID = 4663
ONCHAIN_PERMIT2_DOMAIN = bytes.fromhex(
    "448684463b1f7965c1ec7c249cee11520df24c07242efc2b20f6e54c85614fad"
)
LIVE_SAFE_DOMAIN = bytes.fromhex(
    "777a51697a2f391b432e1f5e8608640f92bf22b0e37656329813b638d25107ad"
)
LIVE_SAFE_MESSAGE_HASH = bytes.fromhex(
    "e5d94a37d6bf17c614a7aedbbe2914e36b47d0e56f37ee03b45d681a00c3b094"
)


def test_permit2_domain_matches_the_deployed_contract() -> None:
    """Pinned against Permit2's own DOMAIN_SEPARATOR() on chain 4663."""
    assert permit.permit2_domain_separator(CHAIN_ID, PERMIT2) == ONCHAIN_PERMIT2_DOMAIN


def test_safe_message_digest_matches_a_live_safe() -> None:
    """Pinned against getMessageHash() on a Safe 1.4.1 deployed on 4663.

    The owner signs the safe's SafeMessage wrapper, never the inner digest;
    getting this wrong reverts the swap inside Permit2's ERC-1271 check.
    """
    inner = keccak(text="a permit2 digest")
    assert permit.safe_message_digest(LIVE_SAFE_DOMAIN, inner) == LIVE_SAFE_MESSAGE_HASH


def test_permit_input_round_trips() -> None:
    """The router must read back the token, spender and amount we signed."""
    details = permit.PermitDetails(USDG, 1_000_000, 1789473030, 3)
    blob = permit.permit_input(
        details, uniswap.DEPLOYMENTS[4663]["universal_router"], 1789473930, b"\x01" * 65
    )
    single, _ = abi_decode([permit.PERMIT_SINGLE_ABI, "bytes"], blob)
    (token, amount, expiration, nonce), spender, deadline = single
    assert token.lower() == USDG.lower()
    assert (amount, expiration, nonce) == (1_000_000, 1789473030, 3)
    assert spender.lower() == uniswap.DEPLOYMENTS[4663]["universal_router"].lower()
    assert deadline == 1789473930


def test_folded_calldata_leads_with_the_permit_command() -> None:
    """PERMIT2_PERMIT rides in front of the swap in one execute()."""
    action = permit.permit_input(
        permit.PermitDetails(USDG, V4_AMOUNT, V4_DEADLINE, 0),
        uniswap.DEPLOYMENTS[4663]["universal_router"],
        V4_DEADLINE,
        b"\x02" * 65,
    )
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE, action
    )
    commands, inputs, _ = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    assert commands == bytes([uniswap.COMMAND_PERMIT2_PERMIT, uniswap.COMMAND_V4_SWAP])
    assert len(inputs) == 2


def test_verify_execute_still_checks_the_swap_behind_a_permit() -> None:
    """The permit action must not blind the calldata check that follows it."""
    action = permit.permit_input(
        permit.PermitDetails(USDG, V4_AMOUNT, V4_DEADLINE, 0),
        uniswap.DEPLOYMENTS[4663]["universal_router"],
        V4_DEADLINE,
        b"\x03" * 65,
    )
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE, action
    )
    uniswap.verify_execute(
        calldata, V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    with pytest.raises(evm.SwapError, match="recipient"):
        uniswap.verify_execute(
            calldata,
            V4_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            uniswap.DEPLOYMENTS[4663]["permit2"],
            V4_DEADLINE,
        )


@pytest.mark.parametrize("chain_id", sorted(uniswap.DEPLOYMENTS))
def test_deployment_addresses_are_checksummed(chain_id: int) -> None:
    """web3 refuses a non-checksummed target, and a refused quote scores zero.

    An un-checksummed table therefore reads as "no liquidity anywhere" and
    routes the trade into whichever pool did answer.
    """
    for name, address in uniswap.deployment(chain_id).items():
        assert isinstance(address, str), name
        if name.endswith("_init_code_hash"):
            assert len(bytes.fromhex(address[2:])) == 32, name
            continue
        assert address == to_checksum_address(address), name


def test_a_chain_without_v2_or_v4_yields_no_such_candidates() -> None:
    """Gnosis has v3 only; the missing versions are skipped, not an error."""

    class _W3:
        """Web3 stub that fails if a missing-version lookup reaches the chain."""

        class eth:  # pylint: disable=invalid-name
            """Eth namespace."""

            @staticmethod
            def call(_tx: dict) -> bytes:
                """Any call here means we tried a version the chain lacks."""
                raise AssertionError("called the chain for an absent version")

    assert "v2_factory" not in uniswap.deployment(100)
    assert "v4_state_view" not in uniswap.deployment(100)
    assert (
        uniswap._v2_candidate(_W3(), 100, USDG, NVDA) is None
    )  # pylint: disable=protected-access
    assert (
        uniswap._v4_candidates(_W3(), 100, USDG, NVDA) == []
    )  # pylint: disable=protected-access


def test_deployment_refuses_an_unknown_chain() -> None:
    """A chain with no recorded deployment fails loudly, not silently."""
    with pytest.raises(evm.SwapError, match="no Uniswap deployment"):
        uniswap.deployment(1)


def _typed_permit(details: permit.PermitDetails, spender: str, deadline: int) -> dict:
    """Spell the same PermitSingle for an independent EIP-712 encoder."""
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "PermitDetails": [
                {"name": "token", "type": "address"},
                {"name": "amount", "type": "uint160"},
                {"name": "expiration", "type": "uint48"},
                {"name": "nonce", "type": "uint48"},
            ],
            "PermitSingle": [
                {"name": "details", "type": "PermitDetails"},
                {"name": "spender", "type": "address"},
                {"name": "sigDeadline", "type": "uint256"},
            ],
        },
        "primaryType": "PermitSingle",
        "domain": {
            "name": "Permit2",
            "chainId": CHAIN_ID,
            "verifyingContract": PERMIT2,
        },
        "message": {
            "details": {
                "token": details.token,
                "amount": details.amount,
                "expiration": details.expiration,
                "nonce": details.nonce,
            },
            "spender": spender,
            "sigDeadline": deadline,
        },
    }


def test_permit_single_digest_matches_an_independent_encoder() -> None:
    """The struct hash the safe signs, checked against eth_account's encoder.

    Nothing else pins field order or ABI types here; get them wrong and
    Permit2 rejects every signature on-chain.
    """
    from eth_account.messages import (  # pylint: disable=import-outside-toplevel
        _hash_eip191_message,
        encode_typed_data,
    )

    details = permit.PermitDetails(USDG, 1_000_000, 1789473030, 7)
    spender = uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    ours = permit.permit_single_digest(CHAIN_ID, PERMIT2, details, spender, 1789473930)
    theirs = _hash_eip191_message(
        encode_typed_data(full_message=_typed_permit(details, spender, 1789473930))
    )
    assert ours == theirs


def test_verify_action_rejects_a_tampered_permit() -> None:
    """The allowance we sign is re-read before it is sent."""
    spender = uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    action = permit.permit_input(
        permit.PermitDetails(USDG, 1_000_000, 1789473930, 0), spender, 1789473930, b"s"
    )
    permit.verify_action(action, USDG, spender, 1_000_000, 1789473930)
    with pytest.raises(evm.SwapError, match="permit amount"):
        permit.verify_action(action, USDG, spender, 999, 1789473930)
    with pytest.raises(evm.SwapError, match="permit spender"):
        permit.verify_action(action, USDG, PERMIT2, 1_000_000, 1789473930)


def test_verify_action_checks_both_time_bounds() -> None:
    """A miscomputed expiry would leave the router a standing allowance."""
    spender = uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    for expiration, sig_deadline, field in [
        (1789473931, 1789473930, "permit expiration"),
        (1789473930, 1789473931, "permit sig_deadline"),
    ]:
        action = permit.permit_input(
            permit.PermitDetails(USDG, 1_000, expiration, 0),
            spender,
            sig_deadline,
            b"s",
        )
        with pytest.raises(evm.SwapError, match=field):
            permit.verify_action(action, USDG, spender, 1_000, 1789473930)


def test_decode_allowance_refuses_a_short_read() -> None:
    """A truncated allowance() must not become nonce zero."""
    assert permit.decode_allowance(b"\x00" * 96) == (0, 0, 0)
    with pytest.raises(evm.SwapError, match="returned 0 bytes"):
        permit.decode_allowance(b"")


def test_build_execute_refuses_an_unknown_pool_version() -> None:
    """An unrecognised version must not fall through to the v2 encoder."""
    with pytest.raises(evm.SwapError, match="unknown pool version"):
        uniswap.build_execute(
            t.cast(uniswap.Pool, {"version": "v9", "fee": 500, "address": USDG}),
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


SAFE = to_checksum_address("0x00000000000000000000000000000000000Fa5e0")


class _StubW3:
    """A web3 that answers nothing; every network read is monkeypatched out."""

    class eth:  # pylint: disable=invalid-name
        """Eth namespace."""

        chain_id = CHAIN_ID

        @staticmethod
        def call(_tx: dict) -> bytes:
            """Fail loudly if a test forgot to stub a read."""
            raise AssertionError("unstubbed eth_call")


@pytest.fixture(autouse=True)
def _fresh_registry() -> t.Iterator[None]:
    """Clear the per-process registry cache; tests must not inherit each other's."""
    stocktokens.asset_book.cache_clear()
    yield
    stocktokens.asset_book.cache_clear()


@pytest.fixture(name="traded")
def traded_fixture(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Stage a ticker, a pool and a Robinhood price, with no network anywhere."""
    state: dict[str, t.Any] = {
        "bid": 249.9,
        "ask": 250.0,
        "halted": False,
        "quoted": 3_970_000_000_000_000_000,
        "multiplier": "1.0",
        "multiplier_asked": [],
    }
    monkeypatch.setattr(
        swap.stocktokens,
        "asset_book",
        lambda: stocktokens.AssetBook(
            {
                "NVDA": {
                    "address": NVDA,
                    "pending_multiplier": "",
                    "name": "",
                    "status": "",
                }
            },
            {},
        ),
    )
    monkeypatch.setattr(
        swap.stocktokens,
        "token_multiplier",
        lambda _w3, token: state["multiplier"],
    )

    def _reference(_symbol: str, multiplier: str) -> tuple:
        """Record the multiplier the reference was scaled by."""
        state["multiplier_asked"].append(multiplier)
        return state["bid"], state["ask"], state["halted"]

    monkeypatch.setattr(swap.stocktokens, "reference_price", _reference)
    monkeypatch.setattr(swap.pools, "cached_discover", lambda *a, **k: [V3_POOL])
    monkeypatch.setattr(
        swap.uniswap, "best_route", lambda *a, **k: (V3_POOL, state["quoted"])
    )
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    return state


def test_plan_swap_buy_prices_and_builds_three_calls(traded: dict) -> None:
    """The default buy path: floor from the lower price, approvals then swap."""
    del traded
    plan = swap.plan_swap(_StubW3(), "NVDA", USDG, NVDA, 1_000 * 10**6, 0.5, SAFE)
    reference = int(1_000 / 250.0 * 10**18)
    assert plan["reference_out"] == reference
    assert plan["quoted_out"] < reference
    assert plan["minimum_out"] == int(plan["quoted_out"] * Decimal("0.995"))
    assert plan["price_gap_bps"] == pytest.approx(75.0, abs=0.5)
    assert "bps worse" in plan["price_warning"]
    assert plan["slippage"] == 0.5
    assert plan["token"] == NVDA
    assert [call["what"] for call in plan["calls"]] == [
        "approve Permit2",
        "approve router",
        "swap",
    ]
    assert plan["permit"] == "separate transaction"


def test_plan_swap_sell_prices_against_the_bid(traded: dict) -> None:
    """Selling values the shares at the bid, not the ask, and returns USDG."""
    traded["quoted"] = int(5 * 249.9 * 10**6)
    plan = swap.plan_swap(_StubW3(), "NVDA", NVDA, USDG, 5 * 10**18, 0.5, SAFE)
    assert plan["reference_out"] == int(5 * 249.9 * 10**6)
    assert plan["quoted_out"] == traded["quoted"]
    assert plan["minimum_out"] == int(traded["quoted"] * Decimal("0.995"))
    assert plan["implied_price"] is None
    assert plan["calls"][0]["to"] == NVDA


def test_plan_swap_refuses_a_halted_ticker(traded: dict) -> None:
    """A halt at Robinhood stops the trade before anything is built."""
    traded["halted"] = True
    with pytest.raises(evm.SwapError, match="halted at Robinhood"):
        swap.plan_swap(_StubW3(), "NVDA", USDG, NVDA, 1_000 * 10**6, 0.5, SAFE)


def test_plan_swap_refuses_a_dislocated_pool(traded: dict) -> None:
    """The gap guard fires on the real path, not just in isolation."""
    traded["quoted"] = 10**18
    with pytest.raises(evm.SwapError, match="bps worse than Robinhood"):
        swap.plan_swap(_StubW3(), "NVDA", USDG, NVDA, 1_000 * 10**6, 0.5, SAFE)


def test_plan_swap_folds_the_permit_when_a_signer_is_present(
    traded: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a signer the allowance rides in the swap: two calls, not three."""
    del traded
    seen: dict = {}

    def _capture(
        w3: object,
        chain_id: int,
        signer: object,
        owner: str,
        token: str,
        amount: int,
        permit2: str,
        spender: str,
        expiry: int,
        placeholder: bool,
    ) -> bytes:
        """Record what the fold path asks to be signed."""
        del w3, signer, placeholder
        seen.update(
            chain_id=chain_id,
            owner=owner,
            token=token,
            amount=amount,
            permit2=permit2,
            spender=spender,
            expiry=expiry,
        )
        seen["action"] = permit.permit_input(
            permit.PermitDetails(token, amount, expiry, 0), spender, expiry, b"sig"
        )
        return bytes(seen["action"])

    monkeypatch.setattr(permit, "signed_action", _capture)
    plan = swap.plan_swap(
        _StubW3(),
        "NVDA",
        USDG,
        NVDA,
        1_000 * 10**6,
        0.5,
        SAFE,
        signer=object(),
    )
    assert [call["what"] for call in plan["calls"]] == ["approve Permit2", "swap"]
    assert plan["permit"] == "signed into the swap"
    assert uniswap.permit_action_in(plan["calls"][-1]["data"]) == seen["action"]
    assert seen["expiry"] == plan["deadline"]
    assert seen["chain_id"] == CHAIN_ID
    assert seen["amount"] == 1_000 * 10**6
    assert seen["token"] == USDG
    assert seen["owner"] == SAFE
    assert seen["spender"] == uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    erc20 = abi_decode(
        ["address", "uint256"], bytes.fromhex(plan["calls"][0]["data"][10:])
    )
    assert erc20[0].lower() == uniswap.DEPLOYMENTS[CHAIN_ID]["permit2"].lower()
    assert erc20[1] == 1_000 * 10**6


def test_plan_swap_rejects_a_permit_for_the_wrong_amount(
    traded: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A permit that does not match the trade must never reach the signer."""
    del traded
    wrong = permit.permit_input(
        permit.PermitDetails(USDG, 1, 1789473030, 0),
        uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"],
        1789473930,
        b"sig",
    )
    monkeypatch.setattr(permit, "signed_action", lambda *a, **k: wrong)
    with pytest.raises(evm.SwapError, match="permit amount"):
        swap.plan_swap(
            _StubW3(),
            "NVDA",
            USDG,
            NVDA,
            1_000 * 10**6,
            0.5,
            SAFE,
            signer=object(),
        )


class _SigningW3:
    """A web3 that answers the reads signed_action makes."""

    def __init__(self, domain: bytes = b"\x11" * 32, allowance: int = 3) -> None:
        """Answer with this domain separator and this current nonce."""
        self.eth = self
        self._domain = domain
        self._allowance = allowance

    def call(self, tx: dict) -> bytes:
        """Permit2 gets the allowance tuple; anything else gets the domain."""
        if tx["to"] == uniswap.DEPLOYMENTS[CHAIN_ID]["permit2"]:
            return (
                (0).to_bytes(32, "big")
                + (0).to_bytes(32, "big")
                + self._allowance.to_bytes(32, "big")
            )
        return self._domain


def _signed(w3: object, signer: object) -> bytes:
    """Run signed_action against the stubs with this chain's addresses."""
    return permit.signed_action(
        w3,
        CHAIN_ID,
        signer,
        SAFE,
        USDG,
        1_000 * 10**6,
        uniswap.DEPLOYMENTS[CHAIN_ID]["permit2"],
        uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"],
        1789473930,
    )


def test_signed_action_signs_the_allowance_it_was_asked_for() -> None:
    """The action carries this trade's token, spender, amount and live nonce."""

    class _Signer:
        """Signer stub."""

        def sign_digest(self, digest: bytes) -> str:
            """Return a signature and remember what it signed."""
            self.digest = digest  # pylint: disable=attribute-defined-outside-init
            return "0x" + "ab" * 65

    signer = _Signer()
    action = _signed(_SigningW3(), signer)
    details, spender, _deadline = permit.decode_action(action)
    assert details.token == USDG
    assert details.amount == 1_000 * 10**6
    assert details.nonce == 3
    assert spender == uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    assert signer.digest == permit.safe_message_digest(
        b"\x11" * 32,
        permit.permit_single_digest(
            CHAIN_ID,
            uniswap.DEPLOYMENTS[CHAIN_ID]["permit2"],
            details,
            spender,
            _deadline,
        ),
    )


def test_signed_action_refuses_an_owner_that_is_not_a_safe() -> None:
    """No domainSeparator() means no ERC-1271 wrapper we can produce."""

    class _Signer:
        """Signer stub that must never be reached."""

        def sign_digest(self, digest: bytes) -> str:
            """Fail if called."""
            raise AssertionError("signed against a non-safe owner")

    with pytest.raises(evm.SwapError, match="did not answer domainSeparator"):
        _signed(_SigningW3(domain=b""), _Signer())


def test_signed_action_points_at_the_fallback_when_signing_is_refused() -> None:
    """A refused digest tells the caller the flag that works instead."""

    class _Signer:
        """Signer stub that refuses."""

        def sign_digest(self, digest: bytes) -> str:
            """Refuse the way the guard would."""
            raise RuntimeError("raw digest signing is not allowed")

    with pytest.raises(evm.SwapError, match="--separate-approvals"):
        _signed(_SigningW3(), _Signer())


def test_best_route_takes_the_highest_quote(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pool selection picks the best output, not the first or the deepest."""
    pools_in: list[uniswap.Pool] = [
        {**V3_POOL, "fee": 500},  # type: ignore[typeddict-item]
        {**V3_POOL, "fee": 3000},  # type: ignore[typeddict-item]
    ]
    monkeypatch.setattr(
        uniswap,
        "quote_pool",
        lambda _w3, _c, pool, *a: 5 if pool["fee"] == 3000 else 1,
    )
    chosen, out = uniswap.best_route(None, CHAIN_ID, USDG, NVDA, 10, pools_in)
    assert (chosen["fee"], out) == (3000, 5)


def test_best_route_raises_when_nothing_can_fill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty market is an error, not a silent zero."""
    monkeypatch.setattr(uniswap, "quote_pool", lambda *a, **k: 0)
    with pytest.raises(evm.SwapError, match="candidates returned zero"):
        uniswap.best_route(None, CHAIN_ID, USDG, NVDA, 10, [V3_POOL])


def test_quote_pool_scores_a_revert_zero_but_lets_transport_errors_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reverting pool cannot fill; a broken RPC is not an empty market."""
    from web3.exceptions import (  # pylint: disable=import-outside-toplevel
        ContractLogicError,
    )

    def _reverting(*_a: object, **_k: object) -> int:
        """Behave like a pool with no liquidity."""
        raise ContractLogicError("execution reverted")

    def _timing_out(*_a: object, **_k: object) -> int:
        """Behave like a rate-limited RPC."""
        raise TimeoutError("429")

    monkeypatch.setattr(uniswap, "_quote_v3", _reverting)
    assert uniswap.quote_pool(None, CHAIN_ID, V3_POOL, USDG, NVDA, 10) == 0
    monkeypatch.setattr(uniswap, "_quote_v3", _timing_out)
    with pytest.raises(TimeoutError):
        uniswap.quote_pool(None, CHAIN_ID, V3_POOL, USDG, NVDA, 10)


@pytest.fixture(name="cache_file")
def cache_file_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the discovery cache at a throwaway file."""
    path = tmp_path / "stocktokens.pools.json"
    monkeypatch.setattr(pools, "CACHE_FILE", path)
    return path


class _BlockW3:
    """A web3 that only knows its block number."""

    class eth:  # pylint: disable=invalid-name
        """Eth namespace."""

        block_number = 123


def test_cached_discover_serves_the_cache_until_it_expires(
    cache_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeat lookup within the hour costs no RPC calls; --refresh bypasses it."""
    calls: list[int] = []

    def _counted(*_a: object, **_k: object) -> list[uniswap.Pool]:
        """Discovery that records having been reached."""
        calls.append(1)
        return [V3_POOL]

    monkeypatch.setattr(pools, "discover", _counted)
    first = pools.cached_discover(_BlockW3(), NVDA, "USDG")
    assert first == [V3_POOL]
    assert cache_file.exists()
    pools.cached_discover(_BlockW3(), NVDA, "USDG")
    assert len(calls) == 1
    pools.cached_discover(_BlockW3(), NVDA, "USDG", refresh=True)
    assert len(calls) == 2


def test_cached_discover_rediscovers_once_the_entry_is_stale(
    cache_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry older than the TTL is not served."""
    monkeypatch.setattr(pools, "discover", lambda *a, **k: [V3_POOL])
    pools.cached_discover(_BlockW3(), NVDA, "USDG")
    stale = json.loads(cache_file.read_text(encoding="utf-8"))
    for entry in stale.values():
        entry["fetched_at"] = 0.0
    cache_file.write_text(json.dumps(stale), encoding="utf-8")
    calls: list[int] = []

    def _counted(*_a: object, **_k: object) -> list[uniswap.Pool]:
        """Discovery that records having been reached."""
        calls.append(1)
        return [V3_POOL]

    monkeypatch.setattr(pools, "discover", _counted)
    pools.cached_discover(_BlockW3(), NVDA, "USDG")
    assert len(calls) == 1


def test_cached_discover_survives_a_corrupt_cache(
    cache_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half-written JSON means rediscover, not crash."""
    cache_file.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(pools, "discover", lambda *a, **k: [V3_POOL])
    assert pools.cached_discover(_BlockW3(), NVDA, "USDG") == [V3_POOL]


def _forged(cache_file: Path, pool: dict) -> None:
    """Write one pool straight into the cache, as an attacker with the cwd would."""
    cache_file.write_text(
        json.dumps(
            {f"{NVDA}:USDG": {"fetched_at": time.time(), "block": 1, "pools": [pool]}}
        ),
        encoding="utf-8",
    )


def test_a_cached_v3_pool_with_an_off_tier_fee_is_refused(cache_file: Path) -> None:
    """A forged fee routes the trade through a pool the operator never picked."""
    _forged(cache_file, {**V3_POOL, "fee": 1234})
    with pytest.raises(evm.SwapError, match="cached v3 pool has fee"):
        pools.cached_discover(_BlockW3(), NVDA, "USDG")


def test_a_cached_v4_pool_with_an_off_tier_is_refused(cache_file: Path) -> None:
    """A tier is a pair; neither half is the caller's to invent."""
    _forged(cache_file, {**V4_POOL, "tick_spacing": 7})
    with pytest.raises(evm.SwapError, match="cached v4 pool has tier"):
        pools.cached_discover(_BlockW3(), NVDA, "USDG")


def test_a_cached_v4_pool_with_hooks_is_refused(cache_file: Path) -> None:
    """Discovery only ever writes hook-less pools."""
    _forged(cache_file, {**V4_POOL, "hooks": NVDA})
    with pytest.raises(evm.SwapError, match="carries hooks"):
        pools.cached_discover(_BlockW3(), NVDA, "USDG")


def test_a_cached_v4_pool_id_must_match_its_own_poolkey(cache_file: Path) -> None:
    """The stored id is re-derived, never trusted."""
    _forged(cache_file, {**V4_POOL, "pool_id": "0x" + "11" * 32})
    with pytest.raises(evm.SwapError, match="is not the id its own PoolKey derives"):
        pools.cached_discover(_BlockW3(), NVDA, "USDG")


def test_a_cached_v4_pool_that_derives_its_own_id_is_served(cache_file: Path) -> None:
    """The honest entry discovery wrote must still survive the check."""
    real = uniswap.v4_pool_id(NVDA, USDG, 100, 1, uniswap.NO_HOOKS)
    _forged(cache_file, {**V4_POOL, "pool_id": "0x" + real.hex()})
    served = t.cast(
        list[uniswap.PoolV4], pools.cached_discover(_BlockW3(), NVDA, "USDG")
    )
    assert served[0]["pool_id"] == "0x" + real.hex()


@pytest.mark.parametrize(
    ("chain_id", "version", "token_a", "token_b", "fee", "live"),
    [
        (4663, "v2", NVDA, USDG, 0, LIVE_NVDA_USDG_V2),
        (4663, "v3", NVDA, USDG, 500, LIVE_NVDA_USDG_V3_500),
        (
            137,
            "v2",
            "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
            "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619",
            0,
            "0xdE32C9ebdd5f587E0F677d5AdCac593ecFfFD91A",
        ),
        (
            137,
            "v3",
            "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
            "0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619",
            500,
            "0x45dDa9cb7c25131DF268515131f647d726f50608",
        ),
        (
            100,
            "v3",
            "0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d",
            "0xDDAfbb505ad214D7b80b1f830fcCc89B60fb7A83",
            100,
            "0xE9E1793954f32D880Ec0B2186E96d88e2b870e40",
        ),
    ],
)
def test_derived_pool_addresses_match_the_live_factories(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    chain_id: int, version: str, token_a: str, token_b: str, fee: int, live: str
) -> None:
    """Pinned against getPair/getPool answers read from each chain."""
    derived = (
        uniswap.pair_address(chain_id, token_a, token_b)
        if version == "v2"
        else uniswap.pool_address(chain_id, token_a, token_b, fee)
    )
    assert derived == live
    swapped = (
        uniswap.pair_address(chain_id, token_b, token_a)
        if version == "v2"
        else uniswap.pool_address(chain_id, token_b, token_a, fee)
    )
    assert swapped == live


def test_a_chain_without_v2_cannot_derive_a_pair() -> None:
    """Gnosis records no v2 factory, so there is nothing to derive from."""
    with pytest.raises(evm.SwapError, match="no v2 factory"):
        uniswap.pair_address(100, USDG, NVDA)


@pytest.mark.parametrize(
    ("pool", "match"),
    [
        ({**V3_POOL, "address": NVDA}, "is not 0xd4EB"),
        ({**V3_POOL, "address": "0xdeadbeef"}, "is not 0xd4EB"),
        ({**V3_POOL, "address": None}, "is not 0xd4EB"),
        (
            {**V3_POOL, "fee": 3000},
            "is not " + uniswap.pool_address(4663, NVDA, USDG, 3000)[:6],
        ),
        (
            {
                "version": "v2",
                "fee": 3000,
                "address": NVDA,
                "quote": "USDG",
                "quote_address": USDG,
            },
            "is not 0xeE6F",
        ),
        (
            {
                "version": "v2",
                "address": LIVE_NVDA_USDG_V2,
                "quote": "USDG",
                "quote_address": USDG,
            },
            "cached v2 pool has fee None",
        ),
    ],
)
def test_a_cached_v2_or_v3_pool_must_be_this_pairs_own(
    cache_file: Path, pool: dict, match: str
) -> None:
    """A forged address would be quoted, and its fake numbers shown."""
    _forged(cache_file, pool)
    with pytest.raises(evm.SwapError, match=match):
        pools.cached_discover(_BlockW3(), NVDA, "USDG")


def test_honest_cached_v2_and_v3_pools_are_served(cache_file: Path) -> None:
    """The entries discovery really writes must survive the check."""
    v2_pool = {
        "version": "v2",
        "fee": 3000,
        "address": LIVE_NVDA_USDG_V2,
        "quote": "USDG",
        "quote_address": USDG,
    }
    _forged(cache_file, v2_pool)
    assert pools.cached_discover(_BlockW3(), NVDA, "USDG") == [v2_pool]
    _forged(cache_file, dict(V3_POOL))
    assert pools.cached_discover(_BlockW3(), NVDA, "USDG") == [V3_POOL]


def test_discover_output_composes_with_best_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The library's own two functions must work in sequence."""
    monkeypatch.setattr(uniswap, "_v2_candidate", lambda *a: None)
    monkeypatch.setattr(uniswap, "_v4_candidates", lambda *a: [])
    monkeypatch.setattr(
        uniswap,
        "_v3_candidates",
        lambda *a: [{"version": "v3", "fee": 500, "address": LIVE_NVDA_USDG_V3_500}],
    )
    monkeypatch.setattr(uniswap, "quote_pool", lambda *a: 42)
    found = uniswap.discover(None, 4663, NVDA, USDG.lower())
    assert found[0]["quote_address"] == USDG
    pool, out = uniswap.best_route(None, 4663, USDG, NVDA, 10, found)
    assert (pool, out) == (found[0], 42)


@pytest.mark.parametrize(
    ("pool", "match"),
    [
        ({"version": "v3", "fee": 500, "address": NVDA}, "carries no quote_address"),
        (
            {"version": "v3", "fee": 500, "address": NVDA, "quote_address": PERMIT2},
            "neither side of this trade",
        ),
    ],
)
def test_best_route_refuses_a_pool_not_tied_to_this_pair(
    pool: dict, match: str
) -> None:
    """Both guards run before anything is quoted."""
    with pytest.raises(evm.SwapError, match=match):
        uniswap.best_route(None, 4663, USDG, NVDA, 10, [t.cast(uniswap.Pool, pool)])


def test_discover_orders_priced_pools_before_the_singleton(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v2/v3 sort by depth, v4 by liquidity, and v4 comes last."""
    thin: uniswap.PoolV3 = {"version": "v3", "fee": 500, "address": USDG}
    deep: uniswap.PoolV3 = {"version": "v3", "fee": 3000, "address": NVDA}
    singleton: uniswap.PoolV4 = {
        "version": "v4",
        "fee": 100,
        "tick_spacing": 1,
        "hooks": uniswap.NO_HOOKS,
        "pool_id": "0x" + "00" * 32,
        "liquidity": 5,
    }
    monkeypatch.setattr(uniswap, "discover", lambda *a, **k: [thin, deep, singleton])
    monkeypatch.setattr(pools.evm, "token_decimals", lambda *a: 6)
    monkeypatch.setattr(
        pools.evm, "balance_of", lambda _w3, _q, pool, _d: 9.0 if pool == NVDA else 1.0
    )
    found = pools.discover(None, NVDA, "USDG")
    assert [pool["version"] for pool in found] == ["v3", "v3", "v4"]
    assert found[0]["fee"] == 3000
    assert all(pool["quote"] == "USDG" for pool in found)


class _Recorder:
    """Stands in for a subcommand and records the parsed namespace."""

    def __init__(self) -> None:
        """Start with nothing recorded."""
        self.args: t.Optional[argparse.Namespace] = None

    def __call__(self, args: argparse.Namespace) -> int:
        """Record and succeed."""
        self.args = args
        return 0


@pytest.mark.parametrize(
    ("command", "argv", "expected"),
    [
        (
            "_cmd_buy",
            ["buy", "--symbol", "NVDA", "--usdg", "1000", "--dry-run"],
            {"dry_run": True},
        ),
        (
            "_cmd_buy",
            [
                "buy",
                "--symbol",
                "NVDA",
                "--usdg",
                "1000",
                "--separate-approvals",
                "--max-gap-bps",
                "200",
            ],
            {"separate_approvals": True, "max_gap_bps": 200.0},
        ),
        (
            "_cmd_sell",
            ["sell", "--symbol", "NVDA", "--shares", "4.7", "--slippage", "0.5"],
            {"slippage": 0.5},
        ),
        (
            "_cmd_quote",
            ["quote", "--symbol", "NVDA", "--usdg", "1000", "--refresh"],
            {"refresh": True},
        ),
    ],
)
def test_documented_swap_invocations_parse(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    argv: list[str],
    expected: dict[str, object],
) -> None:
    """Every command line SKILL.md prints must reach its subcommand.

    The flags used to live on the top-level parser, where argparse rejects
    them after the subcommand - and the obvious recovery from "unrecognized
    arguments: --dry-run" is to drop it and send the trade for real.
    """
    recorder = _Recorder()
    monkeypatch.setattr(swap, command, recorder)
    monkeypatch.setattr(sys, "argv", ["swap.py", *argv])
    assert swap.main() == 0
    assert recorder.args is not None
    for field, value in expected.items():
        assert getattr(recorder.args, field) == value


@pytest.mark.parametrize(
    ("command", "argv"),
    [
        ("_cmd_list", ["list", "--symbol", "NVDA", "--refresh"]),
        ("_cmd_census", ["census", "--limit", "25", "--quote", "WETH"]),
    ],
)
def test_documented_pools_invocations_parse(
    monkeypatch: pytest.MonkeyPatch, command: str, argv: list[str]
) -> None:
    """The discovery commands parse as documented too."""
    recorder = _Recorder()
    monkeypatch.setattr(pools, command, recorder)
    monkeypatch.setattr(sys, "argv", ["pools.py", *argv])
    assert pools.main() == 0


class _FakeSigner:
    """Records what would be sent and answers chain_info with a safe."""

    def __init__(self, safe: str = SAFE) -> None:
        """Answer chain_info with this safe."""
        self.sent: list[dict] = []
        self.signed: list[bytes] = []
        self._safe = safe

    def sign_digest(self, digest: bytes) -> str:
        """Sign the way the connect signer does: raw digest, 65-byte answer."""
        self.signed.append(digest)
        return "0x" + "cd" * 65

    def chain_info(self, _chain: str) -> dict:
        """Return the wallet entry the skill reads the safe from."""
        return {"safe": self._safe, "rpc": "http://localhost"}

    def send_transaction(self, tx: dict) -> str:
        """Record and return a hash."""
        self.sent.append(tx)
        return "0x" + f"{len(self.sent):064x}"


class _ReceiptW3:
    """A web3 whose receipts carry a configurable status."""

    chain_id = CHAIN_ID

    def __init__(self, status: int = 1) -> None:
        """Answer every receipt with this status."""
        self.eth = self
        self.status = status
        self.waited: list[str] = []

    def call(self, tx: dict) -> bytes:
        """Permit2 gets the allowance tuple; anything else gets the domain."""
        if tx["to"] == uniswap.DEPLOYMENTS[CHAIN_ID]["permit2"]:
            return (0).to_bytes(96, "big")
        return b"\x11" * 32

    def wait_for_transaction_receipt(
        self, tx_hash: str, timeout: float, poll_latency: float = 0.1
    ) -> dict:
        """Record the wait and answer."""
        del timeout, poll_latency
        self.waited.append(tx_hash)
        return {"status": self.status}


def _plan_args(**over: object) -> argparse.Namespace:
    """Build a namespace shaped like the one argparse produces for buy."""
    base = {
        "symbol": "NVDA",
        "usdg": 1_000.0,
        "slippage": 0.5,
        "dry_run": False,
        "refresh": False,
        "max_gap_bps": stocktokens.MAX_PRICE_GAP_BPS,
        "separate_approvals": False,
    }
    base.update(over)
    return argparse.Namespace(**base)


def test_dry_run_sends_nothing(traded: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """The preview path must not reach the signer at all."""
    del traded
    signer = _FakeSigner()
    w3 = _ReceiptW3()
    monkeypatch.setattr(evm, "connect", lambda _chain: (w3, signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    assert (
        swap._cmd_buy(_plan_args(dry_run=True)) == 0
    )  # pylint: disable=protected-access
    assert signer.sent == []


def test_a_real_run_confirms_every_call_and_pays_the_safe(
    traded: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """The default path: two calls, the permit folded into the swap itself."""
    del traded
    signer = _FakeSigner()
    w3 = _ReceiptW3()
    monkeypatch.setattr(evm, "connect", lambda _chain: (w3, signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    assert swap._cmd_buy(_plan_args()) == 0  # pylint: disable=protected-access
    assert len(signer.sent) == 2
    assert len(signer.signed) == 1
    assert len(w3.waited) == 2
    printed = capsys.readouterr().out.splitlines()
    for index, tx in enumerate(signer.sent, start=1):
        assert printed.count(f"{tx['what']}: 0x{index:064x}") == 1
    swap_data = signer.sent[-1]["data"]
    assert uniswap.permit_action_in(swap_data) is not None
    recipient = uniswap._decode_execute(  # pylint: disable=protected-access
        swap_data, V3_POOL
    )[2]
    assert to_checksum_address(recipient) == SAFE


def test_separate_approvals_sends_three_calls_and_folds_nothing(
    traded: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fallback for a signer that will not sign a permit digest."""
    del traded
    signer = _FakeSigner()
    w3 = _ReceiptW3()
    monkeypatch.setattr(evm, "connect", lambda _chain: (w3, signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    args = _plan_args(separate_approvals=True)
    assert swap._cmd_buy(args) == 0  # pylint: disable=protected-access
    assert len(signer.sent) == 3
    assert uniswap.permit_action_in(signer.sent[-1]["data"]) is None


def test_a_dry_run_previews_the_calls_a_real_run_would_send(
    traded: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """A preview of a different transaction is worse than no preview.

    The operator signs off on what this prints, so it must be the folded
    two-call shape a real run broadcasts, not the separate-approvals fallback.
    """
    del traded
    signer = _FakeSigner()
    monkeypatch.setattr(evm, "connect", lambda _chain: (_ReceiptW3(), signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    assert (
        swap._cmd_buy(_plan_args(dry_run=True)) == 0
    )  # pylint: disable=protected-access
    printed = capsys.readouterr().out
    assert signer.sent == []
    assert signer.signed == []
    assert f'"permit": "{router.PERMIT_AT_SEND}"' in printed
    previewed = [line for line in printed.splitlines() if line.startswith("dry-run ")]
    assert [line.split(":")[0] for line in previewed] == [
        "dry-run approve Permit2",
        "dry-run swap",
    ]


def test_a_reverted_call_stops_the_sequence_and_says_what_landed(
    traded: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mined-and-reverted transaction must not read as success."""
    del traded
    signer = _FakeSigner()
    w3 = _ReceiptW3(status=0)
    monkeypatch.setattr(evm, "connect", lambda _chain: (w3, signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    with pytest.raises(evm.SwapError, match="reverted; confirmed so far"):
        swap._cmd_buy(_plan_args())  # pylint: disable=protected-access
    assert len(signer.sent) == 1


def _quote_payload(
    bid: t.Any = "212.23", ask: t.Any = "212.34", halt: t.Any = False, **extra: t.Any
) -> dict:
    """Build a Robinhood price payload shaped like the live endpoint's."""
    quote = {"tokenSymbol": "NVDA", "bid": bid, "ask": ask, "isTradingHalt": halt}
    quote.update(extra)
    return {"quotes": [{k: v for k, v in quote.items() if v is not _ABSENT}]}


_ABSENT = object()


def test_reference_price_multiplies_by_the_multiplier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One token is `currentMultiplier` shares, so REST prices multiply.

    Every other test uses a multiplier of 1, where divide and multiply are
    indistinguishable; this is the one that pins the direction.
    """
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _quote_payload("100", "200")
    )
    bid, ask, halted = stocktokens.reference_price("NVDA", "4.0")
    assert (bid, ask, halted) == (400.0, 800.0, False)


def test_a_robinhood_outage_is_a_refusal_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The agent is told to report refusals, so transport failure must be one."""

    def _down(*_a: object, **_k: object) -> t.Any:
        """Stand in for an unreachable Robinhood edge."""
        raise OSError("connection reset")

    monkeypatch.setattr(stocktokens.urllib.request, "urlopen", _down)
    with pytest.raises(evm.SwapError, match="could not read"):
        stocktokens.get_json(stocktokens.ASSETS_URL)


@pytest.mark.parametrize(
    ("payload", "missing"),
    [
        ({}, "quotes"),
        ({"quotes": []}, "quotes -> 0"),
        (_quote_payload(bid=_ABSENT), "bid"),
        (_quote_payload(ask=_ABSENT), "ask"),
        (_quote_payload(tokenSymbol=_ABSENT), "tokenSymbol"),
        (_quote_payload(halt=_ABSENT), "isTradingHalt"),
    ],
)
def test_a_quote_missing_a_field_is_a_refusal(
    payload: dict, missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A feed that changed shape must not be indexed into and priced."""
    monkeypatch.setattr(stocktokens, "get_json", lambda _url: payload)
    with pytest.raises(evm.SwapError, match=f"no {missing}"):
        stocktokens.reference_price("NVDA", "1.0")


def test_a_registry_missing_its_assets_is_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry drives every command; an unrecognised shape stops it."""
    monkeypatch.setattr(stocktokens, "get_json", lambda _url: {"data": []})
    with pytest.raises(evm.SwapError, match="no assets"):
        stocktokens.asset_registry()


@pytest.mark.parametrize(
    ("bid", "multiplier"),
    [
        ("0", "1.0"),
        ("-1", "1.0"),
        ("nan", "1.0"),
        ("inf", "1.0"),
        ("abc", "1.0"),
        (None, "1.0"),
        (True, "1.0"),
        ("212", ""),
        ("212", None),
        ("212", "0"),
        ("212", "nan"),
    ],
)
def test_reference_price_refuses_an_unusable_number(
    bid: t.Any, multiplier: t.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No price or multiplier is ever defaulted, including an empty multiplier."""
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _quote_payload(bid, "212")
    )
    with pytest.raises(evm.SwapError, match="without a usable reference price"):
        stocktokens.reference_price("NVDA", multiplier)


@pytest.mark.parametrize("halt", [None, "false", 0, 1, "true"])
def test_a_halt_flag_that_is_not_a_boolean_is_refused(
    halt: t.Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A null halt flag must never read as "not halted"."""
    monkeypatch.setattr(stocktokens, "get_json", lambda _url: _quote_payload(halt=halt))
    with pytest.raises(evm.SwapError, match="without knowing whether"):
        stocktokens.reference_price("NVDA", "1.0")


def test_a_quote_for_another_ticker_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The symbol check has to fire, not default itself to the one we asked for."""
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _quote_payload(tokenSymbol="TSLA")
    )
    with pytest.raises(evm.SwapError, match="got a quote for 'TSLA'"):
        stocktokens.reference_price("NVDA", "1.0")


def _assets_payload(*entries: dict) -> dict:
    """Build a registry payload shaped like /rhj/assets."""
    return {"assets": list(entries)}


def _asset(symbol: str = "NVDA", chain: int = 4663, multiplier: str = "1.0") -> dict:
    """One registry entry."""
    return {
        "tokenSymbol": symbol,
        "tokenName": symbol,
        "currentMultiplier": multiplier,
        "pendingMultiplier": "",
        "status": "ASSET_STATUS_ACTIVE",
        "deployments": [{"contractAddress": NVDA, "chainId": chain}],
    }


def test_asset_registry_keeps_only_this_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deployment on another chain is not this chain's token."""
    monkeypatch.setattr(
        stocktokens,
        "get_json",
        lambda _url: _assets_payload(_asset("NVDA"), _asset("TSLA", chain=1)),
    )
    registry = stocktokens.asset_registry()
    assert sorted(registry) == ["NVDA"]


class _MultiplierW3:
    """Answers uiMultiplier() with a fixed word, or nothing."""

    def __init__(self, answer: bytes) -> None:
        """Answer every call with these bytes."""
        self.eth = self
        self.answer = answer
        self.asked: list[dict] = []

    def call(self, tx: dict) -> bytes:
        """Record the call and answer."""
        self.asked.append(tx)
        return self.answer


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (4 * 10**18, "4"),
        (1000775159164630595, "1.000775159164630595"),
    ],
)
def test_token_multiplier_reads_the_token_contract(raw: int, expected: str) -> None:
    """The chain, not the REST registry, says how many shares a token is."""
    w3 = _MultiplierW3(raw.to_bytes(32, "big"))
    assert stocktokens.token_multiplier(w3, NVDA) == expected
    assert w3.asked[0]["data"] == stocktokens.SEL_UI_MULTIPLIER
    assert w3.asked[0]["to"] == to_checksum_address(NVDA)


@pytest.mark.parametrize(
    ("answer", "match"),
    [(bytes(32), "uiMultiplier 0"), (b"", "returned 0 bytes")],
)
def test_token_multiplier_refuses_nothing_or_zero(answer: bytes, match: str) -> None:
    """Defaulting the multiplier to 1 would misprice every comparison."""
    with pytest.raises(evm.SwapError, match=match):
        stocktokens.token_multiplier(_MultiplierW3(answer), NVDA)


def test_a_missing_rest_multiplier_no_longer_excludes_a_ticker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry no longer carries the multiplier, so it cannot gate on it."""
    listed = _asset("TSLA")
    del listed["currentMultiplier"]
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _assets_payload(_asset("NVDA"), listed)
    )
    assert sorted(stocktokens.asset_registry()) == ["NVDA", "TSLA"]
    assert "multiplier" not in stocktokens.lookup("TSLA")


def test_plan_swap_scales_the_reference_by_the_chains_multiplier(
    traded: dict,
) -> None:
    """The multiplier read at trade time is the one the price is checked with."""
    traded["multiplier"] = "4"
    plan = swap.plan_swap(
        _StubW3(),
        "NVDA",
        USDG,
        NVDA,
        1_000 * 10**6,
        0.5,
        SAFE,
        separate_approvals=True,
    )
    assert traded["multiplier_asked"] == ["4"]
    assert plan["multiplier"] == "4"


def test_a_duplicate_ticker_excludes_only_that_ticker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Last-one-wins would silently pick a contract nobody chose."""
    monkeypatch.setattr(
        stocktokens,
        "get_json",
        lambda _url: _assets_payload(_asset("NVDA"), _asset("TSLA"), _asset("NVDA")),
    )
    assert sorted(stocktokens.asset_registry()) == ["TSLA"]
    with pytest.raises(evm.SwapError, match="listed twice"):
        stocktokens.lookup("NVDA")


def test_a_suspended_ticker_excludes_only_that_ticker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One delisted token must not take the other two hundred down with it."""
    halted = _asset("TSLA")
    halted["status"] = "ASSET_STATUS_SUSPENDED"
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _assets_payload(_asset("NVDA"), halted)
    )
    assert sorted(stocktokens.asset_registry()) == ["NVDA"]
    with pytest.raises(evm.SwapError, match="ASSET_STATUS_SUSPENDED"):
        stocktokens.lookup("TSLA")


def _broken(kind: str) -> dict:
    """One TSLA listing, broken in the named way."""
    asset = _asset("TSLA")
    if kind == "no contract":
        del asset["deployments"][0]["contractAddress"]
    elif kind == "short contract":
        asset["deployments"][0]["contractAddress"] = "0xdeadbeef"
    elif kind == "deployments not a list":
        asset["deployments"] = "4663"
    elif kind == "two deployments here":
        asset["deployments"].append(dict(asset["deployments"][0]))
    return asset


@pytest.mark.parametrize(
    "kind",
    ["no contract", "short contract", "deployments not a list", "two deployments here"],
)
def test_a_malformed_listing_excludes_only_that_ticker(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every failure path in the loop is isolated to its own listing."""
    monkeypatch.setattr(
        stocktokens,
        "get_json",
        lambda _url: _assets_payload(_asset("NVDA"), _broken(kind)),
    )
    assert sorted(stocktokens.asset_registry()) == ["NVDA"]
    with pytest.raises(evm.SwapError, match="TSLA is not tradable"):
        stocktokens.lookup("TSLA")


def test_a_listing_without_a_symbol_excludes_only_itself(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A listing with no name cannot be refused by name, but cannot sink the rest."""
    nameless = _asset("TSLA")
    del nameless["tokenSymbol"]
    monkeypatch.setattr(
        stocktokens,
        "get_json",
        lambda _url: {"assets": [_asset("NVDA"), nameless, "not a dict"]},
    )
    book = stocktokens.asset_book()
    assert sorted(book.tokens) == ["NVDA"]
    assert sorted(book.excluded) == ["<listing 1>", "<listing 2>"]


def test_lookup_names_an_unknown_ticker(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ticker nobody lists is a refusal, not a KeyError."""
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _assets_payload(_asset("NVDA"))
    )
    with pytest.raises(evm.SwapError, match="unknown ticker FOO"):
        stocktokens.lookup("FOO")


def test_an_empty_chain_still_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing listed at all is a broken feed, not an empty market."""
    monkeypatch.setattr(
        stocktokens, "get_json", lambda _url: _assets_payload(_asset("NVDA", chain=1))
    )
    with pytest.raises(evm.SwapError, match="no stock tokens for chain"):
        stocktokens.asset_registry()


def test_check_price_gap_refuses_an_implausibly_good_quote() -> None:
    """A pool far better than the underlying is a broken reading."""
    with pytest.raises(evm.SwapError, match="better than Robinhood"):
        stocktokens.check_price_gap(10_000, 1_000)


def test_plan_swap_refuses_slippage_that_is_not_protection(traded: dict) -> None:
    """--slippage 100 would accept one wei of output."""
    del traded
    with pytest.raises(evm.SwapError, match="not slippage protection"):
        swap.plan_swap(_StubW3(), "NVDA", USDG, NVDA, 1_000 * 10**6, 100.0, SAFE)


def test_to_base_units_is_exact_at_eighteen_decimals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Float conversion lands over a million wei above what was typed."""
    monkeypatch.setattr(swap.evm, "token_decimals", lambda _w3, _t: 18)
    got = evm.to_base_units(_StubW3(), NVDA, 12345.6789)
    assert got == 12345678900000000000000
    assert got != int(12345.6789 * 10**18)


def test_token_decimals_refuses_an_implausible_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A token claiming 99 decimals is not one we can price."""

    class _W3:
        """Web3 stub answering decimals()."""

        class eth:  # pylint: disable=invalid-name
            """Eth namespace."""

            @staticmethod
            def call(_tx: dict) -> bytes:
                """Answer 99."""
                return (99).to_bytes(32, "big")

    with pytest.raises(evm.SwapError, match="implausible decimals"):
        evm.token_decimals(_W3(), NVDA)


def test_call_int_refuses_an_empty_return() -> None:
    """Treat an empty return as unknown, not as a contract saying zero."""

    class _W3:
        """Web3 stub answering nothing."""

        class eth:  # pylint: disable=invalid-name
            """Eth namespace."""

            @staticmethod
            def call(_tx: dict) -> bytes:
                """Answer with no data."""
                return b""

    with pytest.raises(evm.SwapError, match="expected at least 32"):
        evm.call_int(_W3(), NVDA, b"\x00\x00\x00\x00")


V4_SWAP_TO = "0x8876789976dEcBfCbBbe364623C63652db8C0904"


def test_router_address_matches_the_captured_swap() -> None:
    """Pinned to the `to` of the same Trading API capture as the calldata.

    Every other address assertion compares the table against itself; this one
    compares it against an independent capture, so a valid-but-wrong router
    cannot pass.
    """
    assert uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"] == to_checksum_address(
        V4_SWAP_TO
    )


class _DiscoveryW3:
    """Answers the factory and StateView reads discovery makes."""

    def __init__(self, v3_fees: tuple[int, ...] = (500, 3000), v4: bool = True) -> None:
        """Pretend these v3 fee tiers exist, and optionally one v4 pool."""
        self.eth = self
        self.probed: list[int] = []
        self._v3_fees = v3_fees
        self._v4 = v4

    def call(self, tx: dict) -> bytes:
        """Answer getPool/getPair/getLiquidity from the stub's configuration."""
        data = tx["data"]
        if data[:4] == uniswap.SEL_GET_PAIR:
            return (0).to_bytes(32, "big")
        if data[:4] == uniswap.SEL_GET_POOL:
            fee = int.from_bytes(data[-32:], "big")
            self.probed.append(fee)
            found = int(NVDA, 16) if fee in self._v3_fees else 0
            return found.to_bytes(32, "big")
        if data[:4] == uniswap.SEL_GET_LIQUIDITY:
            return (7 if self._v4 else 0).to_bytes(32, "big")
        raise AssertionError("unexpected call")


def test_discovery_probes_every_v3_fee_tier() -> None:
    """Missing a tier routes the trade into a shallower pool at a worse price."""
    w3 = _DiscoveryW3()
    found = uniswap.discover(w3, CHAIN_ID, NVDA, USDG)
    assert tuple(w3.probed) == uniswap.V3_FEES
    assert [pool["fee"] for pool in found if pool["version"] == "v3"] == [500, 3000]


def test_discovery_drops_the_zero_address_and_keeps_v4() -> None:
    """A zero address is not a pool; v4 pools are still discovered."""
    found = uniswap.discover(_DiscoveryW3(v3_fees=()), CHAIN_ID, NVDA, USDG)
    assert [pool["version"] for pool in found] == ["v4"] * len(uniswap.V4_TIERS)
    assert not any(pool.get("address") for pool in found)


def test_v4_pool_id_sorts_its_currencies() -> None:
    """The id must not depend on which side the caller passed first."""
    one = uniswap.v4_pool_id(NVDA, USDG, 100, 1, uniswap.NO_HOOKS)
    other = uniswap.v4_pool_id(USDG, NVDA, 100, 1, uniswap.NO_HOOKS)
    assert one == other


def test_decode_execute_refuses_an_extra_command() -> None:
    """A second router command behind the swap must not pass verification."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    commands, inputs, deadline = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    tampered = (
        "0x"
        + (
            uniswap.SEL_UR_EXECUTE
            + abi_encode(
                ["bytes", "bytes[]", "uint256"],
                [commands + bytes([0x04]), [*inputs, b""], deadline],
            )
        ).hex()
    )
    with pytest.raises(evm.SwapError, match="expected one swap command"):
        uniswap.verify_execute(
            tampered, V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )


def test_verify_execute_checks_the_pool_the_quote_came_from() -> None:
    """A different fee tier is a different pool than the one that was priced."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    other: uniswap.PoolV4 = {**V4_POOL, "fee": 3000}  # type: ignore[typeddict-item]
    with pytest.raises(evm.SwapError, match="venue"):
        uniswap.verify_execute(
            calldata, other, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )


def test_verify_action_checks_the_token() -> None:
    """A permit for the wrong token is a permit for the wrong money."""
    spender = uniswap.DEPLOYMENTS[CHAIN_ID]["universal_router"]
    action = permit.permit_input(
        permit.PermitDetails(USDG, 1_000, 1789473030, 0), spender, 1789473930, b"s"
    )
    with pytest.raises(evm.SwapError, match="permit token"):
        permit.verify_action(action, NVDA, spender, 1_000, 1789473930)


def test_approvals_carry_the_expiry_they_were_given() -> None:
    """The allowance window is a safety property, so pin it."""
    expiry = 1789473930
    _erc20, permit2 = router.approval_calls(CHAIN_ID, USDG, 1_000, expiry)
    decoded = abi_decode(
        ["address", "address", "uint160", "uint48"], bytes.fromhex(permit2["data"][10:])
    )
    assert decoded[3] == expiry


def test_cached_discover_returns_the_cached_pools_on_a_hit(
    cache_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A hit must serve this key's pools, not an empty list or a neighbour's."""
    del cache_file
    monkeypatch.setattr(pools, "discover", lambda *a, **k: [V3_POOL])
    first = pools.cached_discover(_BlockW3(), NVDA, "USDG")
    monkeypatch.setattr(
        pools, "discover", lambda *a, **k: pytest.fail("cache miss on a fresh entry")
    )
    assert pools.cached_discover(_BlockW3(), NVDA, "USDG") == first


def test_cache_ttl_is_an_hour() -> None:
    """The cache window is documented to the agent; pin it."""
    assert pools.CACHE_MAX_AGE_S == 3600.0


def test_command_byte_must_match_the_pool_version() -> None:
    """0x01 and 0x09 are the exact-OUTPUT variants; a typo must not pass.

    Swapped in, the router would read (amount, minimum) as
    (amountOut, amountInMax) and spend the whole input to buy the floor.
    """
    calldata = uniswap.build_execute(
        V3_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    commands, inputs, deadline = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    assert commands == bytes([uniswap.COMMAND_V3_SWAP_EXACT_IN])
    tampered = (
        "0x"
        + (
            uniswap.SEL_UR_EXECUTE
            + abi_encode(
                ["bytes", "bytes[]", "uint256"], [bytes([0x01]), inputs, deadline]
            )
        ).hex()
    )
    with pytest.raises(evm.SwapError, match="exact-input swap is 0x00"):
        uniswap.verify_execute(
            tampered, V3_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )


def _reencode(
    calldata: str, swap_input: bytes, deadline: t.Optional[int] = None
) -> str:
    """Rebuild an execute() call around a replaced swap input."""
    commands, _inputs, old_deadline = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    body = abi_encode(
        ["bytes", "bytes[]", "uint256"],
        [commands, [swap_input], old_deadline if deadline is None else deadline],
    )
    return "0x" + (uniswap.SEL_UR_EXECUTE + body).hex()


def _v4_input(calldata: str) -> tuple[bytes, list[bytes]]:
    """Unpack the v4 actions and params inside a one-command execute()."""
    _c, inputs, _d = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    actions, params = abi_decode(["bytes", "bytes[]"], inputs[0])
    return actions, list(params)


def test_verify_execute_checks_the_deadline() -> None:
    """A stale swap window is exactly what the deadline exists to bound."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    with pytest.raises(evm.SwapError, match="calldata deadline"):
        uniswap.verify_execute(
            calldata,
            V4_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE + 1,
        )


@pytest.mark.parametrize(
    "tamper",
    [
        "settle currency",
        "take currency",
        "settle amount",
        "payer",
        "min hop",
        "two hops",
        "hook data",
        "extra param",
    ],
)
def test_verify_execute_checks_every_v4_leg(tamper: str) -> None:
    """Settle and take must move the planned currencies, over one hop."""
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    actions, params = _v4_input(calldata)
    swap_t = [uniswap.V4_EXACT_INPUT_PARAMS]
    cin, path, hop, amt, floor = abi_decode(swap_t, params[0])[0]
    path = [tuple(k) for k in path]
    if tamper == "settle currency":
        params[1] = abi_encode(["address", "uint256", "bool"], [PERMIT2, 0, True])
    elif tamper == "take currency":
        params[2] = abi_encode(
            ["address", "address", "uint256"], [PERMIT2, V4_RECIPIENT, 0]
        )
    elif tamper == "settle amount":
        params[1] = abi_encode(["address", "uint256", "bool"], [USDG, 5, True])
    elif tamper == "payer":
        params[1] = abi_encode(["address", "uint256", "bool"], [USDG, 0, False])
    elif tamper == "min hop":
        params[0] = abi_encode(swap_t, [(cin, path, [1], amt, floor)])
    elif tamper == "two hops":
        params[0] = abi_encode(swap_t, [(cin, path + path, list(hop), amt, floor)])
    elif tamper == "hook data":
        path[0] = (*path[0][:4], b"\x01")
        params[0] = abi_encode(swap_t, [(cin, path, list(hop), amt, floor)])
    else:
        params.append(b"")
    tampered = _reencode(calldata, abi_encode(["bytes", "bytes[]"], [actions, params]))
    with pytest.raises(evm.SwapError, match="legs|one-hop|three v4 action"):
        uniswap.verify_execute(
            tampered,
            V4_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


def test_verify_execute_refuses_a_multi_hop_v3_path() -> None:
    """A longer path would otherwise verify against its first hop alone."""
    calldata = uniswap.build_execute(
        V3_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    fields = ["address", "uint256", "uint256", "bytes", "bool", "uint256[]"]
    _c, inputs, _d = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    to, amt, floor, path, payer, hop = abi_decode(fields, inputs[0])
    longer = path + (500).to_bytes(3, "big") + bytes.fromhex(PERMIT2[2:])
    tampered = _reencode(
        calldata, abi_encode(fields, [to, amt, floor, longer, payer, list(hop)])
    )
    with pytest.raises(evm.SwapError, match="one-hop v3 path"):
        uniswap.verify_execute(
            tampered,
            V3_POOL,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


@pytest.mark.parametrize("tamper", ["three tokens", "payer", "min hop"])
def test_verify_execute_checks_the_v2_legs(tamper: str) -> None:
    """The v2 path is exactly two tokens, paid by the caller, unlimited per hop."""
    v2_pool: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": NVDA}
    calldata = uniswap.build_execute(
        v2_pool, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    fields = ["address", "uint256", "uint256", "address[]", "bool", "uint256[]"]
    _c, inputs, _d = abi_decode(
        ["bytes", "bytes[]", "uint256"], bytes.fromhex(calldata[10:])
    )
    to, amt, floor, path, payer, hop = abi_decode(fields, inputs[0])
    path, hop = list(path), list(hop)
    if tamper == "three tokens":
        path = [path[0], PERMIT2, path[1]]
    elif tamper == "payer":
        payer = False
    else:
        hop = [7]
    tampered = _reencode(
        calldata, abi_encode(fields, [to, amt, floor, path, payer, hop])
    )
    with pytest.raises(evm.SwapError, match="legs|one-hop v2 path"):
        uniswap.verify_execute(
            tampered,
            v2_pool,
            USDG,
            NVDA,
            V4_AMOUNT,
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


def test_swap_commands_are_the_exact_input_opcodes() -> None:
    """Pinned literally: the neighbouring opcodes spend the whole input."""
    assert uniswap.SWAP_COMMANDS == {"v2": 0x08, "v3": 0x00, "v4": 0x10}


def test_plan_swap_verifies_the_calldata_it_returns(
    traded: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The verifier must run on the production path, not only in its own test."""
    del traded
    seen: list[str] = []
    monkeypatch.setattr(
        uniswap, "verify_execute", lambda *a, **k: seen.append("checked")
    )
    swap.plan_swap(_StubW3(), "NVDA", USDG, NVDA, 1_000 * 10**6, 0.5, SAFE)
    assert seen == ["checked"]


@pytest.mark.parametrize("field", ["token_in", "token_out", "amount_in"])
def test_verify_execute_checks_every_field_it_claims(field: str) -> None:
    """Each comparison in the checks dict must actually reject a mismatch."""
    calldata = uniswap.build_execute(
        V3_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    wrong = {
        "token_in": (NVDA, NVDA, V4_AMOUNT),
        "token_out": (USDG, USDG, V4_AMOUNT),
        "amount_in": (USDG, NVDA, V4_AMOUNT + 1),
    }[field]
    with pytest.raises(evm.SwapError, match=field):
        uniswap.verify_execute(
            calldata,
            V3_POOL,
            wrong[0],
            wrong[1],
            wrong[2],
            V4_MIN,
            V4_RECIPIENT,
            V4_DEADLINE,
        )


def test_sell_sizes_the_amount_in_the_token_being_sold(
    traded: dict, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """--shares is denominated in the stock token's 18 decimals, not USDG's 6."""
    traded["quoted"] = int(5 * 249.9 * 10**6)
    signer = _FakeSigner()
    monkeypatch.setattr(evm, "connect", lambda _chain: (_ReceiptW3(), signer))
    monkeypatch.setattr(
        swap.evm, "token_decimals", lambda _w3, token: 6 if token == USDG else 18
    )
    args = _plan_args(shares=5.0, dry_run=True)
    assert swap._cmd_sell(args) == 0  # pylint: disable=protected-access
    printed = capsys.readouterr().out
    plan = json.loads(printed[: printed.index("\ndry-run ")])
    assert plan["amount_in"] == 5 * 10**18
    assert signer.sent == []


class _QuoterW3:
    """Records the one quoter call and answers with a fixed output."""

    def __init__(self) -> None:
        """Start with nothing recorded."""
        self.eth = self
        self.data = b""
        self.to = ""

    def call(self, tx: dict) -> bytes:
        """Record the request."""
        self.to, self.data = tx["to"], bytes(tx["data"])
        return (77).to_bytes(32, "big")


@pytest.mark.parametrize(
    ("token_in", "token_out", "zero_for_one"),
    [(USDG, NVDA, True), (NVDA, USDG, False)],
)
def test_quote_v4_sets_the_direction_from_the_sorted_key(
    token_in: str, token_out: str, zero_for_one: bool
) -> None:
    """A reversed flag would price every v4 trade backwards."""
    w3 = _QuoterW3()
    out = uniswap._quote_v4(  # pylint: disable=protected-access
        w3, CHAIN_ID, V4_POOL, token_in, token_out, 123
    )
    assert out == 77
    assert w3.to == uniswap.DEPLOYMENTS[CHAIN_ID]["v4_quoter"]
    assert w3.data[:4] == uniswap.SEL_QUOTE_V4
    ((key, direction, amount, hook_data),) = abi_decode(
        ["((address,address,uint24,int24,address),bool,uint128,bytes)"], w3.data[4:]
    )
    assert int(key[0], 16) < int(key[1], 16)
    assert {to_checksum_address(key[0]), to_checksum_address(key[1])} == {
        to_checksum_address(USDG),
        to_checksum_address(NVDA),
    }
    assert (key[2], key[3], to_checksum_address(key[4])) == (100, 1, uniswap.NO_HOOKS)
    assert (direction, amount, hook_data) == (zero_for_one, 123, b"")


def test_quote_v3_asks_for_this_trade_at_this_fee() -> None:
    """Transposed tokens or a dropped fee would quote a different trade."""
    w3 = _QuoterW3()
    out = uniswap._quote_v3(  # pylint: disable=protected-access
        w3, CHAIN_ID, V3_POOL, NVDA, USDG, 456
    )
    assert out == 77
    assert w3.to == uniswap.DEPLOYMENTS[CHAIN_ID]["quoter_v2"]
    assert w3.data[:4] == uniswap.SEL_QUOTE_V3
    (params,) = abi_decode(["(address,address,uint256,uint24,uint160)"], w3.data[4:])
    assert (to_checksum_address(params[0]), to_checksum_address(params[1])) == (
        to_checksum_address(NVDA),
        to_checksum_address(USDG),
    )
    assert params[2:] == (456, 500, 0)


def test_signed_permit_carries_the_signature_and_the_window_it_was_given() -> None:
    """The allowance must not lapse before the swap it authorises can land."""

    class _Signer:
        """Signer stub."""

        def sign_digest(self, digest: bytes) -> str:
            """Answer with a recognisable signature."""
            del digest
            return "0x" + "ab" * 65

    action = _signed(_SigningW3(), _Signer())
    single, signature = abi_decode([permit.PERMIT_SINGLE_ABI, "bytes"], action)
    (_token, _amount, expiration, _nonce), _spender, sig_deadline = single
    assert signature == bytes.fromhex("ab" * 65)
    assert expiration == 1789473930
    assert sig_deadline == 1789473930


BOOTSTRAP = SKILL / "bootstrap_env.sh"


def _bash_works() -> bool:
    """Whether `bash` here is a POSIX shell rather than the Windows WSL stub."""
    try:
        probe = subprocess.run(  # nosec B603 B607 - fixed argv
            ["bash", "-c", "printf ok"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return probe.stdout.strip() == "ok"


needs_bash = pytest.mark.skipif(not _bash_works(), reason="no POSIX bash here")


def _venv_with_pip_log(root: Path, sentinels: tuple[str, ...] = ()) -> Path:
    """Build a venv stub whose pip records its arguments instead of installing."""
    venv = root / ".venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\necho /fake/cacert.pem\n", encoding="utf-8")
    pip = venv / "bin" / "pip"
    pip.write_text(f'#!/bin/sh\necho "$@" >> {venv}/pip.log\n', encoding="utf-8")
    python.chmod(0o755)
    pip.chmod(0o755)
    for sentinel in sentinels:
        (venv / sentinel).touch()
    return venv


def _bootstrap(cwd: Path, script: Path = BOOTSTRAP, **env: str) -> t.Any:
    """Run a bootstrap wrapper the way SKILL.md tells the agent to."""
    return subprocess.run(  # nosec B603 B607 - fixed argv, test-controlled paths
        ["bash", str(script)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "HOME": str(cwd), **env},
        check=False,
    )


@needs_bash
def test_bootstrap_installs_what_these_scripts_import(tmp_path: Path) -> None:
    """web3 at the pin pearl-connect names, and certifi for the trust store."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    venv = _venv_with_pip_log(tmp_path)
    result = _bootstrap(tmp_path)
    assert result.returncode == 0, result.stderr
    assert f"export PY={venv / 'bin' / 'python'}" in result.stdout
    assert "export SSL_CERT_FILE=/fake/cacert.pem" in result.stdout
    installed = (venv / "pip.log").read_text(encoding="utf-8")
    assert "web3>=7.15,<8 certifi" in installed
    assert (venv / ".bootstrap-connect-stocktokens").is_file()


@needs_bash
def test_a_venv_polymarket_finished_still_gets_these_packages(tmp_path: Path) -> None:
    """The venv is shared, so one skill's sentinel says nothing about the other's."""
    (tmp_path / ".mcp.json").write_text("{}", encoding="utf-8")
    _venv_with_pip_log(tmp_path, sentinels=(".bootstrap-complete",))
    result = _bootstrap(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "installing dependencies" in result.stderr
    reused = _bootstrap(tmp_path)
    assert "reusing venv" in reused.stderr


@needs_bash
def test_the_venv_location_can_be_overridden(tmp_path: Path) -> None:
    """CONNECT_STOCKTOKENS_VENV names the venv, as the polymarket variable does."""
    elsewhere = tmp_path / "elsewhere"
    venv = _venv_with_pip_log(elsewhere, sentinels=(".bootstrap-connect-stocktokens",))
    result = _bootstrap(tmp_path, CONNECT_STOCKTOKENS_VENV=str(venv))
    assert result.returncode == 0, result.stderr
    assert f"export PY={venv / 'bin' / 'python'}" in result.stdout


@needs_bash
def test_a_missing_shared_bootstrap_fails_the_callers_eval(tmp_path: Path) -> None:
    """Without the shared script, eval must fail rather than leave $PY unset."""
    scripts = tmp_path / "skills" / "connect-stocktokens" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(BOOTSTRAP, scripts / "bootstrap_env.sh")
    result = _bootstrap(tmp_path, scripts / "bootstrap_env.sh")
    assert result.returncode != 0
    assert "shared bootstrap missing" in result.stdout
    assert result.stdout.rstrip().endswith("false")


def _stage_bootstrap(root: Path, with_lib: bool) -> Path:
    """Lay out .claude/{lib,skills} the way the server installs them."""
    scripts = root / ".claude" / "skills" / "connect-stocktokens" / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy(SKILL / "_bootstrap.py", scripts / "_bootstrap.py")
    if with_lib:
        (root / ".claude" / "lib").mkdir()
        (root / ".claude" / "lib" / "evm.py").write_text("", encoding="utf-8")
    return scripts / "_bootstrap.py"


def test_the_path_shim_names_a_missing_lib_tree(tmp_path: Path) -> None:
    """A bare "No module named evm" hides that the server installs this tree."""
    shim = _stage_bootstrap(tmp_path, with_lib=False)
    with pytest.raises(ImportError, match="installs into .claude/lib"):
        runpy.run_path(str(shim))


def test_the_path_shim_names_a_missing_web3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first command on a clean install must say what to install and where."""
    shim = _stage_bootstrap(tmp_path, with_lib=True)
    real = __import__("importlib.util").util.find_spec
    monkeypatch.setattr(
        "importlib.util.find_spec",
        lambda name, *a: None if name == "web3" else real(name, *a),
    )
    with pytest.raises(ImportError, match="web3>=7.15,<8"):
        runpy.run_path(str(shim))


def test_the_path_shim_puts_the_lib_tree_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With both present, the shared modules become importable."""
    shim = _stage_bootstrap(tmp_path, with_lib=True)
    monkeypatch.setattr(sys, "path", list(sys.path))
    runpy.run_path(str(shim))
    assert sys.path[0] == str((tmp_path / ".claude" / "lib").resolve())


class _AnsweringW3:
    """A web3 whose eth_call answers from a selector -> bytes table."""

    def __init__(self, answers: dict[bytes, bytes]) -> None:
        """Answer each selector with its bytes; anything else is empty."""
        self.eth = self
        self.answers = answers

    def call(self, tx: dict) -> bytes:
        """Look the selector up."""
        return self.answers.get(bytes(tx["data"])[:4], b"")


def _word(value: int) -> bytes:
    """One ABI word."""
    return value.to_bytes(32, "big")


def test_token_decimals_and_balance_read_the_chain() -> None:
    """Both are read, never assumed."""
    w3 = _AnsweringW3(
        {evm.SEL_DECIMALS: _word(6), evm.SEL_BALANCE_OF: _word(2_500_000)}
    )
    assert evm.token_decimals(w3, USDG) == 6
    assert evm.balance_of(w3, USDG, SAFE, 6) == 2.5


def test_discover_keeps_a_v2_pair_the_factory_names() -> None:
    """A pair the factory returns is a candidate, stamped with its quote."""
    w3 = _AnsweringW3(
        {
            uniswap.SEL_GET_PAIR: bytes(12) + bytes.fromhex(LIVE_NVDA_USDG_V2[2:]),
            uniswap.SEL_GET_POOL: _word(0),
            uniswap.SEL_GET_LIQUIDITY: _word(0),
        }
    )
    found = uniswap.discover(w3, 4663, NVDA, USDG)
    assert found == [
        {
            "version": "v2",
            "fee": uniswap.V2_FEE,
            "address": LIVE_NVDA_USDG_V2,
            "quote_address": USDG,
        }
    ]


def test_missing_factories_and_quoters_are_handled_per_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No v3 factory means no v3 candidates; no quoter is a refusal, not a zero."""
    bare: uniswap.Deployment = {"universal_router": PERMIT2, "permit2": PERMIT2}
    monkeypatch.setitem(uniswap.DEPLOYMENTS, 999, bare)
    assert (
        uniswap._v3_candidates(None, 999, USDG, NVDA) == []
    )  # pylint: disable=protected-access
    with pytest.raises(evm.SwapError, match="no quoter_v2"):
        uniswap._quote_v3(
            None, 999, V3_POOL, USDG, NVDA, 1
        )  # pylint: disable=protected-access
    with pytest.raises(evm.SwapError, match="no v4_quoter"):
        uniswap._quote_v4(
            None, 999, V4_POOL, USDG, NVDA, 1
        )  # pylint: disable=protected-access


@pytest.mark.parametrize(
    ("reserves", "token0", "match"),
    [
        (_word(1)[:31], bytes(12) + bytes.fromhex(USDG[2:]), "bytes of reserves"),
        (_word(1) + _word(1), b"", "did not answer token0"),
        (_word(1) + _word(1), bytes(12) + bytes.fromhex(PERMIT2[2:]), "neither side"),
    ],
)
def test_a_v2_pair_that_answers_badly_is_refused(
    reserves: bytes, token0: bytes, match: str
) -> None:
    """A short or foreign answer must not be read as reserves."""
    w3 = _AnsweringW3({uniswap.SEL_GET_RESERVES: reserves, uniswap.SEL_TOKEN0: token0})
    pair: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": NVDA}
    with pytest.raises(evm.SwapError, match=match):
        uniswap._quote_v2(w3, pair, USDG, NVDA, 10)  # pylint: disable=protected-access


def test_an_empty_v2_pair_quotes_zero_and_the_other_side_orients() -> None:
    """Zero reserves fill nothing; token0 on the output side flips the reserves."""
    token0 = bytes(12) + bytes.fromhex(NVDA[2:])
    pair: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": NVDA}
    empty = _AnsweringW3(
        {uniswap.SEL_GET_RESERVES: _word(0) + _word(5), uniswap.SEL_TOKEN0: token0}
    )
    assert (
        uniswap._quote_v2(empty, pair, USDG, NVDA, 10) == 0
    )  # pylint: disable=protected-access
    full = _AnsweringW3(
        {uniswap.SEL_GET_RESERVES: _word(100) + _word(1000), uniswap.SEL_TOKEN0: token0}
    )
    assert uniswap._quote_v2(
        full, pair, USDG, NVDA, 10
    ) == (  # pylint: disable=protected-access
        10 * 997 * 100 // (1000 * 1000 + 10 * 997)
    )


def test_quote_pool_dispatches_every_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each version reaches its own quoter."""
    monkeypatch.setattr(uniswap, "_quote_v3", lambda *a: 3)
    monkeypatch.setattr(uniswap, "_quote_v4", lambda *a: 4)
    monkeypatch.setattr(uniswap, "_quote_v2", lambda *a: 2)
    v2_pool: uniswap.PoolV2 = {"version": "v2", "fee": 3000, "address": NVDA}
    got = [
        uniswap.quote_pool(None, 4663, pool, USDG, NVDA, 1)
        for pool in (V3_POOL, V4_POOL, v2_pool)
    ]
    assert got == [3, 4, 2]


def test_decode_execute_refuses_mismatched_commands_and_foreign_actions() -> None:
    """Commands without inputs, and v4 actions we never write, are refused."""
    body = abi_encode(["bytes", "bytes[]", "uint256"], [bytes([0x10]), [], 1])
    with pytest.raises(evm.SwapError, match="malformed commands"):
        uniswap.verify_execute(
            "0x" + (uniswap.SEL_UR_EXECUTE + body).hex(),
            V4_POOL,
            USDG,
            NVDA,
            1,
            1,
            V4_RECIPIENT,
            1,
        )
    calldata = uniswap.build_execute(
        V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
    )
    _actions, params = _v4_input(calldata)
    foreign = _reencode(
        calldata, abi_encode(["bytes", "bytes[]"], [bytes([0x07, 0x0B, 0x0F]), params])
    )
    with pytest.raises(evm.SwapError, match="unexpected v4 actions"):
        uniswap.verify_execute(
            foreign, V4_POOL, USDG, NVDA, V4_AMOUNT, V4_MIN, V4_RECIPIENT, V4_DEADLINE
        )
