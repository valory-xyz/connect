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

"""Tests for the read-only chain tools (OPE-2035 T5)."""

import typing as t

from web3 import Web3

from connect import chain_read

TOKEN = "0x" + "70" * 20
PROXY = "0x" + "71" * 20
IMPL = "0x" + "72" * 20
NFT = "0x" + "73" * 20
MULTI = "0x" + "74" * 20
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"


class _Eth:
    """eth_call / storage stand-in keyed by (address, selector)."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], bytes] = {}
        self.slots: dict[str, int] = {}
        self.raise_for: set[str] = set()

    def call(self, tx: dict, block_identifier: t.Any = "latest") -> bytes:
        to = tx["to"].lower()
        if to in self.raise_for:
            raise ValueError("execution reverted")
        data = tx["data"]
        for (address, prefix), answer in self.answers.items():
            if address == to and data.startswith(prefix):
                return answer
        return b""

    def get_storage_at(self, address: str, slot: int) -> bytes:
        return self.slots.get(address.lower(), 0).to_bytes(32, "big")


class _W3:
    def __init__(self) -> None:
        self.eth = _Eth()


def _w3() -> t.Any:
    w3 = _W3()
    supports = chain_read.selector_of("supportsInterface(bytes4)")
    one = (1).to_bytes(32, "big")
    w3.eth.answers[(TOKEN, chain_read.selector_of("decimals()"))] = (18).to_bytes(
        32, "big"
    )
    w3.eth.answers[(NFT, supports + "80ac58cd")] = one
    w3.eth.answers[(MULTI, supports + "d9b67a26")] = one
    w3.eth.slots[PROXY] = int(IMPL, 16)
    w3.eth.answers[(IMPL, chain_read.selector_of("decimals()"))] = one
    return w3


def _names(abi: list[dict]) -> set[str]:
    return {entry["name"] for entry in abi}


def test_chain_call_reports_result_or_revert() -> None:
    """A read answers its bytes; a revert says so instead of raising."""
    w3 = _w3()
    assert chain_read.chain_call(t.cast(Web3, w3), TOKEN, "0x313ce567") == {
        "result": "0x" + "00" * 31 + "12"
    }
    w3.eth.raise_for.add(TOKEN)
    reverted = chain_read.chain_call(t.cast(Web3, w3), TOKEN, "0x313ce567")
    assert reverted == {"reverted": True, "reason": "execution reverted"}


def test_get_abi_by_interface_and_known_address() -> None:
    """ERC-20 by decimals(), 721/1155 by ERC-165, Multicall3 by address."""
    w3 = t.cast(Web3, _w3())
    erc20 = chain_read.get_abi(w3, TOKEN)
    assert erc20["verified"] is False
    assert "transfer" in _names(erc20["abi"])
    assert "ownerOf" in _names(chain_read.get_abi(w3, NFT)["abi"])
    assert "safeBatchTransferFrom" in _names(chain_read.get_abi(w3, MULTI)["abi"])
    known = chain_read.get_abi(w3, MULTICALL3)
    assert known["verified"] is True
    assert _names(known["abi"]) == {"aggregate3"}
    assert known["abi"][0]["inputs"] == [
        {"name": "arg0", "type": "(address,bool,bytes)[]"}
    ]


def test_get_abi_follows_the_eip1967_slot_and_says_when_it_knows_nothing() -> None:
    """A proxy reports its implementation's ABI; an unknown contract says so."""
    w3 = t.cast(Web3, _w3())
    proxy = chain_read.get_abi(w3, PROXY)
    assert proxy["implementation"] == Web3.to_checksum_address(IMPL)
    assert "approve" in _names(proxy["implementation_abi"])
    assert "note" not in proxy
    unknown = chain_read.get_abi(w3, "0x" + "99" * 20)
    assert unknown["abi"] == []
    assert "no ABI Connect ships" in unknown["note"]


def test_decode_calldata() -> None:
    """Known selectors decode; short, unknown or undecodable data says why."""
    decoded = chain_read.decode_calldata(
        "0xa9059cbb" + "00" * 12 + "aa" * 20 + (5).to_bytes(32, "big").hex()
    )
    assert decoded == {
        "selector": "0xa9059cbb",
        "signature": "transfer(address,uint256)",
        "args": ["0x" + "aa" * 20, "5"],
    }
    assert chain_read.decode_calldata("0x12")["error"].startswith("calldata shorter")
    assert chain_read.decode_calldata("0x12345678")["error"] == "unknown selector"
    truncated = chain_read.decode_calldata("0xa9059cbb" + "00" * 4)
    assert truncated["error"] == "the arguments do not decode as this signature"
    nested = chain_read.decode_calldata(
        "0xac9650d8"
        + (32).to_bytes(32, "big").hex()
        + (1).to_bytes(32, "big").hex()
        + (32).to_bytes(32, "big").hex()
        + (2).to_bytes(32, "big").hex()
        + "abcd".ljust(64, "0")
    )
    assert nested["args"] == [["0xabcd"]]
    assert chain_read._jsonable(True) is True  # pylint: disable=protected-access
