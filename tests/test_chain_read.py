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

"""Tests for the read-only chain tools."""

import typing as t

import pytest
from web3 import Web3
from web3.exceptions import ContractLogicError

from connect import chain_read

TOKEN = "0x" + "70" * 20
PROXY = "0x" + "71" * 20
IMPL = "0x" + "72" * 20
NFT = "0x" + "73" * 20
MULTI = "0x" + "74" * 20
MULTICALL3 = "0xcA11bde05977b3631167028862bE2a173976CA11"
EIP1967_SLOT = 0x360894A13BA1A3210667C828492DB98DCA3E2076CC3735A920A3CA505D382BBC


class _Eth:
    """eth_call / storage stand-in keyed by (address, selector)."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], bytes] = {}
        self.slots: dict[str, int] = {}
        self.raise_for: set[str] = set()
        self.down: set[str] = set()
        self.blocks: list[t.Any] = []

    def call(self, tx: dict, block_identifier: t.Any = "latest") -> bytes:
        self.blocks.append(block_identifier)
        to = tx["to"].lower()
        if to in self.raise_for:
            raise ContractLogicError("execution reverted")
        if to in self.down:
            raise ConnectionError("rpc down")
        data = tx["data"]
        for (address, prefix), answer in self.answers.items():
            if address == to and data.startswith(prefix):
                return answer
        if data.startswith(chain_read.selector_of("supportsInterface(bytes4)")):
            return b"\0" * 32  # ABI-encoded false, as a real ERC-165 answers
        return b""

    def get_storage_at(self, address: str, slot: int) -> bytes:
        # keyed on the literal EIP-1967 slot, not the module's constant
        if slot != EIP1967_SLOT:
            return b"\0" * 32
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
    w3.eth.down.add(NFT)
    with pytest.raises(ConnectionError):  # unreachable is not a revert
        chain_read.chain_call(t.cast(Web3, w3), NFT, "0x313ce567")


@pytest.mark.parametrize(
    ("to", "data", "block", "match"),
    [
        ("0x1234", "0x", "latest", None),
        (TOKEN, "313ce567", "latest", "0x-hex"),
        (TOKEN, "0xzz", "latest", None),
        (TOKEN, "0x", "yesterday", "block must be"),
        (TOKEN, "0x", "-1", "block must be >= 0"),
    ],
)
def test_chain_call_refuses_a_malformed_argument_rather_than_reverting(
    to: str, data: str, block: str, match: str | None
) -> None:
    """A typo is the caller's mistake: it raises, it never reads as a revert."""
    w3 = _w3()
    with pytest.raises(ValueError, match=match):
        chain_read.chain_call(t.cast(Web3, w3), to, data, block)


def test_chain_call_takes_a_block_tag_or_number() -> None:
    """Named tags pass through; a number in decimal or hex is read at that block."""
    w3 = _w3()
    for block in ("finalized", "123", "0x7b"):
        assert "result" in chain_read.chain_call(t.cast(Web3, w3), TOKEN, "0x", block)
    assert w3.eth.blocks == ["finalized", 123, 123]


def test_an_erc721_is_not_read_as_an_erc1155() -> None:
    """An encoded false from supportsInterface is a no, not an answer."""
    abi = chain_read.get_abi(t.cast(Web3, _w3()), NFT)
    assert "ownerOf" in _names(abi["abi"])
    assert "safeBatchTransferFrom" not in _names(abi["abi"])


def test_an_implementation_address_with_leading_zeros_is_followed() -> None:
    """The EIP-1967 slot is a number: a leading zero byte must be padded back."""
    w3 = _w3()
    low = "0x00" + "72" * 19
    w3.eth.slots[PROXY] = int(low, 16)
    proxy = chain_read.get_abi(t.cast(Web3, w3), PROXY)
    assert proxy["implementation"] == Web3.to_checksum_address(low)


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


def _addresses_in(relative: str, names: list[str]) -> dict[str, str]:
    """Read named address constants out of a bundled skill's source, lower-case."""
    import re  # pylint: disable=import-outside-toplevel
    from pathlib import Path  # pylint: disable=import-outside-toplevel

    source = (Path(chain_read.__file__).parent / "assets" / relative).read_text()
    found = {}
    for name in names:
        match = re.search(
            rf'{name}\s*=\s*(?:to_checksum_address\()?\s*"(0x[0-9a-fA-F]{{40}})"',
            source,
        )
        assert match, name
        found[name] = match.group(1).lower()
    return found


@pytest.mark.parametrize(
    ("relative", "names"),
    [
        (
            "skills/connect-polymarket/scripts/pm_common.py",
            [
                "PUSD",
                "USDC_E",
                "USDC",
                "COLLATERAL_ONRAMP",
                "CTF",
                "CTF_COLLATERAL_ADAPTER",
                "NEG_RISK_CTF_COLLATERAL_ADAPTER",
            ],
        ),
        (
            "skills/connect-pons/scripts/pons.py",
            ["WETH", "USDG", "MEME_HOOK", "FEE_ESCROW"],
        ),
    ],
)
def test_the_skills_contracts_are_shipped(relative: str, names: list[str]) -> None:
    """get_abi knows every contract the bundled skills call, at their address."""
    for name, address in _addresses_in(relative, names).items():
        assert address in chain_read.KNOWN_CONTRACTS, name


def test_every_universal_router_is_shipped() -> None:
    """Each chain's router in the lib's Uniswap deployments has its execute ABI."""
    import re  # pylint: disable=import-outside-toplevel
    from pathlib import Path  # pylint: disable=import-outside-toplevel

    source = (Path(chain_read.__file__).parent / "assets/lib/uniswap.py").read_text()
    routers = re.findall(r'"universal_router": "(0x[0-9a-fA-F]{40})"', source)
    assert routers
    for router in routers:
        name, signatures = chain_read.KNOWN_CONTRACTS[router.lower()]
        assert name == "Uniswap Universal Router"
        assert "execute(bytes,bytes[],uint256)" in signatures


def test_a_skill_contract_is_verified_with_its_calls() -> None:
    """The CTF comes back verified, with the calls the Polymarket skill makes."""
    ctf = chain_read.get_abi(
        t.cast(Web3, _w3()), "0x4D97DCd97eC945f40cF65F87097ACe5EA0476045"
    )
    assert ctf["verified"] is True
    assert {"redeemPositions", "setApprovalForAll"} <= _names(ctf["abi"])
