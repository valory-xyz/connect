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

"""The one list of chains Connect supports, and what each offers a session.

Connect learns which chains it runs on from the ledger config Pearl passes
(`connect.config`); this table says what each of those chains is: its chain id,
its native symbol, and whether a mech marketplace or the mech facilitator is
there. `wallet_info` reports it per chain, so a session knows up front that a
chain has no marketplace instead of finding out from a failed request.
"""

import json
import typing as t
from importlib import resources

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

# Connect's chain names are the middleware's Chain values; mech-client names a
# few of them differently in its own config.
MECH_CLIENT_CHAIN_NAMES = {"arbitrum_one": "arbitrum"}


class ChainInfo(t.TypedDict):
    """What one supported chain offers a session."""

    chain_id: int
    native_symbol: str
    marketplace: bool
    facilitator: bool


# chain -> (chain id, native symbol). Ethereum carries no agent but is a
# configured ledger in the service, so it is listed for completeness.
_CHAINS: dict[str, tuple[int, str]] = {
    "arbitrum_one": (42161, "ETH"),
    "base": (8453, "ETH"),
    "celo": (42220, "CELO"),
    "ethereum": (1, "ETH"),
    "gnosis": (100, "xDAI"),
    "mode": (34443, "ETH"),
    "optimism": (10, "ETH"),
    "polygon": (137, "POL"),
    "robinhood": (4663, "ETH"),
}

# No facilitator route is configured in Connect, and no repo it reads lists
# the facilitator's chains, so every chain starts without one; the facilitator
# team says where it runs (OPE-2035 D2).
FACILITATOR_CHAINS: frozenset[str] = frozenset()


def _marketplaces() -> dict[str, str]:
    """Return mech-client's marketplace contract per mech-client chain name."""
    raw = (resources.files("mech_client") / "configs" / "mechs.json").read_text()
    return {
        name: str(entry.get("mech_marketplace_contract") or ZERO_ADDRESS)
        for name, entry in json.loads(raw).items()
    }


def _has_marketplace(chain: str, marketplaces: t.Mapping[str, str]) -> bool:
    """Whether mech-client knows a non-zero marketplace contract on `chain`."""
    name = MECH_CLIENT_CHAIN_NAMES.get(chain, chain)
    return marketplaces.get(name, ZERO_ADDRESS).lower() != ZERO_ADDRESS


def supported_chains() -> dict[str, ChainInfo]:
    """Return the supported-chain table, reading mech-client's marketplaces."""
    marketplaces = _marketplaces()
    return {
        chain: ChainInfo(
            chain_id=chain_id,
            native_symbol=symbol,
            marketplace=_has_marketplace(chain, marketplaces),
            facilitator=chain in FACILITATOR_CHAINS,
        )
        for chain, (chain_id, symbol) in _CHAINS.items()
    }


SUPPORTED_CHAINS: dict[str, ChainInfo] = supported_chains()


def chain_info(chain: str) -> ChainInfo | None:
    """Return what `chain` offers, or None for a chain Connect does not list."""
    return SUPPORTED_CHAINS.get(chain.lower())
