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

"""Unit tests for the pearl-connect skill's bundled web3 client.

``signer_client`` is what every spawned script sends through, so what is
pinned here is the shape of the web3 that ``connect`` hands back — the sender
its reads assume, and the round trips a send is allowed to make — plus the
.mcp.json parsing that locates the signer at all. No network: chain RPC is
answered from a table, and the signer's own HTTP surface is stubbed.
"""

# The skill modules are imported at runtime via a sys.path insert (they ship
# as bundled assets, not an installed package), which mypy cannot follow.
# mypy: ignore-errors

import json
import sys
from pathlib import Path

import pytest
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import ExtraDataLengthError
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware

from connect import workspace
from connect.config import AGENT_HTTP_PORT, BIND_HOST

# The skill ships as bundled assets, not an installed package; put its scripts
# dir on the path so we can import the client under test.
_SCRIPTS = (
    Path(__file__).resolve().parent.parent
    / "connect"
    / "assets"
    / "skills"
    / "pearl-connect"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS))

import signer_client  # noqa: E402

ADDR_A = to_checksum_address("0x" + "11" * 20)
ADDR_B = to_checksum_address("0x" + "22" * 20)
SAFE_ADDR = to_checksum_address("0x" + "5a" * 20)

ERC20_APPROVE_ABI = [
    {
        "name": "approve",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "amount", "type": "uint256"},
        ],
        "outputs": [{"type": "bool"}],
    }
]


# --- connect(): the web3 the documented send path needs -------------------------


def _connected(monkeypatch, chain_entry: dict):
    """Build the client's web3 without touching .mcp.json or the network."""
    monkeypatch.setattr(
        signer_client, "load_mcp_config", lambda: ("http://127.0.0.1:8716", "t0ken")
    )
    monkeypatch.setattr(
        signer_client.SignerClient, "chain_info", lambda self, c=None: chain_entry
    )
    return signer_client.connect("polygon")


def _record_chain_rpc(monkeypatch, answers: dict) -> list:
    """Answer chain RPC from `answers`, returning the list of methods asked.

    Anything the client asks that is not in `answers` fails the test rather
    than reaching the network — an unexpected round trip is the thing these
    tests are here to notice.
    """
    seen: list = []

    def make_request(self, method, params):  # noqa: ARG001
        seen.append(method)
        assert method in answers, f"unexpected chain RPC: {method}"
        return {"jsonrpc": "2.0", "id": 1, "result": answers[method]}

    monkeypatch.setattr(signer_client.HTTPProvider, "make_request", make_request)
    return seen


def test_connect_disarms_the_middleware_that_broke_contract_calls(
    monkeypatch,
) -> None:
    """Two failures cost real transactions: local gas estimation, and PoA blocks.

    web3 estimates gas for a send with `from` unset — the node then simulates
    from the zero address and an approve reverts before anything is sent — and
    its block formatter refuses Polygon's oversized extraData, which the fee
    middleware reads on the way to every send.
    """
    w3, _ = _connected(monkeypatch, {"rpc": "http://127.0.0.1:9", "safe": SAFE_ADDR})
    installed = [name for _, name in w3.middleware_onion.middleware]
    assert "gas_estimate" not in installed
    assert "gas_price_strategy" not in installed
    assert ExtraDataToPOAMiddleware in [
        entry[0] for entry in w3.middleware_onion.middleware
    ]
    # the safe makes the call, so it is the `from` a simulation should assume
    assert w3.eth.default_account == SAFE_ADDR


def test_a_contract_send_reaches_the_signer_without_estimating_locally(
    monkeypatch,
) -> None:
    """The behaviour the middleware removal is for, watched at the RPC layer.

    An approve is what reverted in the field. Here the only chain traffic a
    send may cause is web3's own chain-id read: an ``eth_estimateGas`` (the
    call that reverted from the zero address) or an ``eth_getBlockByNumber``
    (the fee lookup) appearing again fails this, whatever the middleware
    happens to be called by then.
    """
    seen = _record_chain_rpc(monkeypatch, {"eth_chainId": hex(137)})
    sent: list = []
    monkeypatch.setattr(
        signer_client.SignerClient,
        "_post",
        lambda self, path, payload: sent.append((path, payload))
        or {"tx_hash": "0x" + "ab" * 32},
    )
    w3, _ = _connected(monkeypatch, {"rpc": "http://127.0.0.1:9", "safe": SAFE_ADDR})
    token = w3.eth.contract(address=ADDR_A, abi=ERC20_APPROVE_ABI)
    token.functions.approve(ADDR_B, 10**6).transact()

    assert "eth_estimateGas" not in seen
    assert "eth_getBlockByNumber" not in seen
    ((path, payload),) = sent
    assert path == "/safe-transaction"  # made by the safe, not the EOA
    assert payload["to"] == ADDR_A
    assert payload["data"].startswith("0x095ea7b3")  # approve(address,uint256)


def test_connect_reads_a_block_whose_extradata_is_oversized(monkeypatch) -> None:
    """Polygon's extraData must not blow up a block read (it once did).

    web3's default formatter rejects extraData past 32 bytes, so without the
    PoA middleware this read raises and takes every receipt wait with it.
    """
    block = {"number": "0x1", "extraData": "0x" + "ab" * 97}
    _record_chain_rpc(monkeypatch, {"eth_getBlockByNumber": block})
    w3, _ = _connected(monkeypatch, {"rpc": "http://127.0.0.1:9", "safe": SAFE_ADDR})
    assert w3.eth.get_block("latest")["number"] == 1

    plain = Web3(provider=signer_client.HTTPProvider("http://127.0.0.1:9"))
    with pytest.raises(ExtraDataLengthError):  # the same read, unprotected
        plain.eth.get_block("latest")


def test_connect_reports_a_middleware_it_could_not_remove(monkeypatch, capsys) -> None:
    """A web3 that renamed one leaves the client doing work it meant to skip.

    Nothing breaks — the send still goes — so the stderr note is the only
    sign, and a silent version of this would be a slow regression nobody
    notices.
    """
    monkeypatch.setattr(signer_client, "UNUSED_SEND_MIDDLEWARE", ("no_such_layer",))
    w3, _ = _connected(monkeypatch, {"rpc": "http://127.0.0.1:9", "safe": SAFE_ADDR})
    assert "no_such_layer" in capsys.readouterr().err
    # the un-stripped middlewares are still installed, and still harmless
    # because the estimate they make now carries a real sender
    installed = [name for _, name in w3.middleware_onion.middleware]
    assert "gas_estimate" in installed
    assert w3.eth.default_account == SAFE_ADDR


def test_connect_says_so_when_there_is_no_safe_to_read_as(monkeypatch, capsys) -> None:
    """No safe: reads fall back to no sender, which can answer wrongly in silence."""
    w3, _ = _connected(monkeypatch, {"rpc": "http://127.0.0.1:9", "safe": None})
    assert not w3.eth.default_account  # nothing to point `from` at, and no crash
    assert "no service safe" in capsys.readouterr().err


# --- .mcp.json base URL: the trailing slash that 404'd a whole live run ----------


def _write_mcp_config(directory: Path, url: str) -> None:
    (directory / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    signer_client.MCP_SERVER_NAME: {
                        "url": url,
                        "headers": {"Authorization": "Bearer t0ken"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8716/mcp",
        "http://127.0.0.1:8716/mcp/",
        "http://127.0.0.1:8716/mcp///",
    ],
)
def test_mcp_base_url_drops_the_suffix_however_it_is_slashed(tmp_path, url) -> None:
    """A trailing slash must not defeat the /mcp strip — it 404s every request."""
    _write_mcp_config(tmp_path, url)
    base_url, token, root = signer_client.load_mcp_config_dir(tmp_path)
    assert base_url == "http://127.0.0.1:8716"
    assert token == "t0ken"  # nosec B105
    assert root == tmp_path.resolve()


def test_base_url_handles_the_url_the_server_actually_writes(tmp_path) -> None:
    """Producer and consumer in one test — the gap that broke every live run.

    ``workspace.mcp_url`` ends in a slash on purpose (a POST to /mcp without
    it hits the agent-UI route and 405s), so the reader must cope with it
    rather than the writer dropping it.
    """
    _write_mcp_config(tmp_path, workspace.mcp_url())
    base_url, _, _ = signer_client.load_mcp_config_dir(tmp_path)
    assert base_url == f"http://{BIND_HOST}:{AGENT_HTTP_PORT}"
    assert not base_url.rstrip("/").endswith("/mcp")
