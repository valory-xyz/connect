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

"""Shared plumbing for the connect-polymarket scripts.

Everything here routes signing through the local connect signer (the same
service the pearl-connect skill uses): raw digests via ``POST /sign-message``
and service-safe calls via ``POST /safe-transaction``. No key material is
ever available to this process.

Polygon mainnet addresses and API hosts mirror the production
``polymarket_trader`` service (valory/trader).
"""

import json
import os
import sys
import typing as t
from pathlib import Path

import requests
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.exceptions import ContractLogicError, TimeExhausted
from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware

# The connect signer HTTP client lives in the sibling pearl-connect skill;
# both skills install side by side under .claude/skills and are refreshed
# every boot, so reuse it rather than re-implement auth, retries and signing.
_PEARL_SCRIPTS = (
    Path(__file__).resolve().parent.parent.parent / "pearl-connect" / "scripts"
)
if str(_PEARL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_PEARL_SCRIPTS))
try:
    import signer_client
except ModuleNotFoundError as exc:  # pragma: no cover - install-shape guard
    raise ImportError(
        "connect-polymarket needs the sibling pearl-connect skill; expected "
        f"signer_client.py under {_PEARL_SCRIPTS}"
    ) from exc

# --- chain -------------------------------------------------------------------
CHAIN = "polygon"
CHAIN_ID = 137

# --- Polymarket contracts (Polygon mainnet, CLOB v2) ---------------------------
PUSD = to_checksum_address("0xC011a7E12a19f7B1f670d46F03B03f3342E82DFB")
USDC_E = to_checksum_address("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174")
COLLATERAL_ONRAMP = to_checksum_address("0x93070a847efEf7F70739046A929D47a521F5B8ee")
CTF = to_checksum_address("0x4D97DCd97eC945f40cF65F87097ACe5EA0476045")
CTF_EXCHANGE = to_checksum_address("0xE111180000d2663C0091e4f400237545B87B996B")
NEG_RISK_CTF_EXCHANGE = to_checksum_address(
    "0xe2222d279d744050d28e00520010520000310F59"
)
NEG_RISK_ADAPTER = to_checksum_address("0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296")
CTF_COLLATERAL_ADAPTER = to_checksum_address(
    "0xAdA100Db00Ca00073811820692005400218FcE1f"
)
NEG_RISK_CTF_COLLATERAL_ADAPTER = to_checksum_address(
    "0xadA2005600Dec949baf300f4C6120000bDB6eAab"
)
# Polymarket DepositWallet factory. All relayer mutations target the factory
# (which dispatches to the per-owner DW), never the DW directly.
DW_FACTORY = to_checksum_address("0x00000000000Fb5C9ADea0298D729A0CB3823Cc07")

MAX_UINT256 = 2**256 - 1
PARENT_COLLECTION_ID = b"\x00" * 32
PUSD_DECIMALS = 6

# --- API hosts -----------------------------------------------------------------
CLOB_HOST = "https://clob.polymarket.com"
GAMMA_API = "https://gamma-api.polymarket.com"
DATA_API = "https://data-api.polymarket.com"
DEFAULT_RELAYER_PROXY_URL = "https://mpp.valory.xyz"

HTTP_TIMEOUT = 30

# Re-export the sibling client's error type so callers can ``except
# pm.ConnectError`` without importing signer_client themselves.
ConnectError = signer_client.SignerRequestError


# --- connect signer client ------------------------------------------------------


def _find_mcp_config(start: Path | None = None) -> tuple[str, str, Path]:
    """Find .mcp.json (cwd upwards); return (base_url, token, workspace_root).

    Delegates the walk + parse to the sibling client's ``load_mcp_config_dir``
    so there is exactly one implementation; the third element is the workspace
    root where this skill keeps its state.
    """
    return signer_client.load_mcp_config_dir(start)


class ConnectSigner(signer_client.SignerClient):
    """The pearl-connect signer client, extended for Polymarket on Polygon.

    Inherits the audited HTTP surface (bearer auth, ``/sign-message``,
    idempotent ``/safe-transaction`` with retries) from the sibling skill and
    adds only what Polymarket needs: a PoA-aware Polygon web3 for reads, the
    agent/safe addresses, an EIP-191 helper and receipt polling. Every
    signature still goes through the signer and requires unrestricted mode.
    """

    def __init__(self, base_url: str, token: str, workspace: Path) -> None:
        """Initialize the shared client on Polygon, plus workspace/w3 state."""
        super().__init__(base_url, token, CHAIN)
        self.workspace = workspace
        self._info: dict | None = None
        self._w3: Web3 | None = None

    @classmethod
    def from_workspace(cls, start: Path | None = None) -> "ConnectSigner":
        """Build a client from the workspace's .mcp.json."""
        base_url, token, root = _find_mcp_config(start)
        return cls(base_url, token, root)

    # -- wallet / chain --------------------------------------------------------

    def wallet_info(self) -> dict:  # type: ignore[override]
        """Agent addresses, per-chain safes/RPCs and native balances (cached)."""
        if self._info is None:
            self._info = super().wallet_info()
        return self._info

    @property
    def agent_eoa(self) -> str:
        """The agent EOA address (the CLOB signer / DW owner)."""
        return to_checksum_address(self.wallet_info()["agent_eoa"])

    @property
    def safe_address(self) -> str:
        """The service safe on Polygon — the treasury every flow returns to."""
        safe = self.wallet_info().get("safes", {}).get(CHAIN)
        if not safe:
            raise ConnectError(
                f"no service safe configured on '{CHAIN}' — Polymarket flows "
                "need the safe as the recoverable treasury; ask the operator "
                "to configure the Polygon chain"
            )
        return to_checksum_address(safe)

    @property
    def w3(self) -> Web3:
        """web3 on the configured Polygon RPC (reads only; sends go via signer)."""
        if self._w3 is None:
            rpc = self.wallet_info().get("rpcs", {}).get(CHAIN)
            if not rpc:
                raise ConnectError(
                    f"no RPC configured for '{CHAIN}' — ask the operator to "
                    "configure the Polygon chain"
                )
            self._w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 60}))
            self._w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
        return self._w3

    # -- signing ---------------------------------------------------------------

    # sign_digest (str or bytes) is inherited from the base SignerClient.

    def personal_sign(self, message: str) -> str:
        """EIP-191 personal_sign of a text message (digest built locally)."""
        raw = message.encode()
        digest = keccak(
            b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode() + raw
        )
        return self.sign_digest(digest)

    def safe_transaction(
        self, to: str, data: str, value: int = 0, request_id: str | None = None
    ) -> str:
        """Have the service safe make this call on Polygon; returns tx_hash.

        Thin wrapper over the inherited idempotent send: the sibling client
        fills nonce/gas, signs, broadcasts, and replays the same request_id
        on a lost response so a retry never double-spends.
        """
        return self.send_transaction(
            {"to": to_checksum_address(to), "value": value, "data": data},
            request_id=request_id,
        )

    def wait_receipt(self, tx_hash: str, timeout: float = 300) -> dict:
        """Wait for the tx receipt via web3; returns {'status': 1|0|None, 'tx_hash'}.

        Delegates polling to web3 (which handles a not-yet-mined tx
        internally). A timeout returns status None rather than raising, so
        ``check_mined`` reports it as an unconfirmed send instead of crashing.
        """
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=timeout, poll_latency=3
            )
        except TimeExhausted:
            return {"tx_hash": tx_hash, "status": None, "note": "receipt timeout"}
        return {"tx_hash": tx_hash, "status": int(receipt["status"])}


# --- workspace state --------------------------------------------------------------

STATE_SUBDIR = "polymarket"
STATE_FILE = "state.json"


def state_path(cs: ConnectSigner) -> Path:
    """Return the skill's state file inside the agent workspace."""
    return cs.workspace / STATE_SUBDIR / STATE_FILE


def load_state(cs: ConnectSigner) -> dict:
    """Load the persisted skill state.

    A missing file is an empty state. A *corrupt* file is NOT silently reset:
    it would send callers down the "no DepositWallet recorded" path and
    redeploy over a funded DW (orphaning it). The atomic write in
    ``save_state`` makes corruption unlikely, but if it happens the operator
    must see it, not have it hidden.
    """
    path = state_path(cs)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SystemExit(
            f"state file {path} is unreadable/corrupt ({e}); refusing to "
            "continue, as treating it as empty could orphan a funded "
            "DepositWallet. Inspect or remove it deliberately before retrying."
        ) from e


def save_state(cs: ConnectSigner, state: dict) -> None:
    """Persist the skill state atomically (0600: caches revocable API creds).

    Write to a temp file in the same dir, fsync, then ``os.replace`` — a
    crash mid-write leaves the previous state intact rather than a truncated
    file the loader would reject.
    """
    path = state_path(cs)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(state, indent=2).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    path.chmod(0o600)


# -- typed state accessors -------------------------------------------------------


def dw_open_tokens(cs: ConnectSigner) -> list:
    """CTF token ids the DW may currently hold (recorded at buy time).

    Backstops the sweep against data-API indexing lag: a token just bought
    is here immediately, before the off-chain indexer reflects it.
    """
    raw = load_state(cs).get("dw_open_tokens") or []
    return [int(t) for t in raw]


def dw_pending_buy_tokens(cs: ConnectSigner) -> list:
    """Token ids whose buy submission outcome is still ambiguous."""
    return sorted(_dw_pending_buy_counts(load_state(cs)))


def _dw_pending_buy_counts(state: dict) -> dict:
    """Return positive pending-intent counts, migrating the legacy token set."""
    raw_counts = state.get("dw_pending_buy_counts")
    if raw_counts is not None:
        return {
            int(token_id): int(count)
            for token_id, count in raw_counts.items()
            if int(count) > 0
        }
    return {int(token_id): 1 for token_id in state.get("dw_pending_buy_tokens") or []}


def _store_dw_pending_buy_counts(state: dict, counts: dict) -> None:
    """Store normalized counts and remove the superseded token-set field."""
    state["dw_pending_buy_counts"] = {
        str(token_id): counts[token_id]
        for token_id in sorted(counts)
        if counts[token_id] > 0
    }
    state.pop("dw_pending_buy_tokens", None)


def record_dw_token(cs: ConnectSigner, token_id: int) -> None:
    """Note that the DW may now hold `token_id` (idempotent)."""
    state = load_state(cs)
    tokens = {int(t) for t in state.get("dw_open_tokens") or []}
    if int(token_id) not in tokens:
        tokens.add(int(token_id))
        state["dw_open_tokens"] = sorted(tokens)
        save_state(cs, state)


def record_dw_buy_intent(cs: ConnectSigner, token_id: int) -> None:
    """Persist a holdings hint and one pending marker for this submission."""
    state = load_state(cs)
    token_id = int(token_id)
    tokens = {int(t) for t in state.get("dw_open_tokens") or []}
    pending = _dw_pending_buy_counts(state)
    tokens.add(token_id)
    pending[token_id] = pending.get(token_id, 0) + 1
    state["dw_open_tokens"] = sorted(tokens)
    _store_dw_pending_buy_counts(state, pending)
    save_state(cs, state)


def confirm_dw_buy_intent(cs: ConnectSigner, token_id: int) -> None:
    """Resolve one accepted buy while retaining its shared holdings hint."""
    state = load_state(cs)
    token_id = int(token_id)
    pending = _dw_pending_buy_counts(state)
    if token_id in pending:
        pending[token_id] -= 1
    _store_dw_pending_buy_counts(state, pending)
    save_state(cs, state)


def reject_dw_buy_intent(cs: ConnectSigner, token_id: int) -> None:
    """Resolve one rejected buy without clobbering a shared holdings hint."""
    state = load_state(cs)
    token_id = int(token_id)
    pending = _dw_pending_buy_counts(state)
    if token_id in pending:
        pending[token_id] -= 1
    _store_dw_pending_buy_counts(state, pending)
    save_state(cs, state)


def record_dw_token_best_effort(cs: ConnectSigner, token_id: int) -> bool:
    """Record a DW token without ever masking an already-completed action.

    Called AFTER an order fills or a transfer confirms on-chain, so a
    state-write failure here must not raise and make the completed action
    look failed (which could prompt a double-spend on retry). Warn instead;
    the operator can still sweep safely with an explicit ``--token-ids``.
    """
    try:
        record_dw_token(cs, token_id)
        return True
    except Exception as e:  # noqa: BLE001 - best-effort after a done action
        print(
            f"WARNING: could not record DW token {token_id} to state ({e}); "
            "the action itself succeeded. If you sweep, pass --token-ids "
            f"{token_id} so it is not left behind.",
            file=sys.stderr,
        )
        return False


def forget_dw_tokens(cs: ConnectSigner, token_ids: list) -> None:
    """Drop swept holdings hints while preserving unresolved buy submissions."""
    state = load_state(cs)
    forgotten = {int(t) for t in token_ids}
    remaining = {int(t) for t in state.get("dw_open_tokens") or []} - forgotten
    state["dw_open_tokens"] = sorted(remaining)
    save_state(cs, state)


# --- receipt enforcement --------------------------------------------------------


def check_mined(receipt: dict, action: str) -> dict:
    """Raise unless the tx receipt confirms success (status == 1).

    Fund-moving commands must fail loudly on a reverted (status 0) or
    unconfirmed (status None, e.g. receipt timeout) transaction rather than
    printing an optimistic label next to a failure.
    """
    if receipt.get("status") != 1:
        raise SystemExit(
            f"{action} did not confirm on-chain "
            f"(status={receipt.get('status')}, tx={receipt.get('tx_hash')}); "
            "verify on-chain before retrying — re-running is not a no-op"
        )
    return receipt


# --- calldata encoding -------------------------------------------------------------


def _call(signature: str, types: list, args: list) -> str:
    return "0x" + (keccak(text=signature)[:4] + abi_encode(types, args)).hex()


def encode_erc20_approve(spender: str, amount: int) -> str:
    """approve(address,uint256)."""
    return _call(
        "approve(address,uint256)",
        ["address", "uint256"],
        [to_checksum_address(spender), amount],
    )


def encode_erc20_transfer(to: str, amount: int) -> str:
    """transfer(address,uint256)."""
    return _call(
        "transfer(address,uint256)",
        ["address", "uint256"],
        [to_checksum_address(to), amount],
    )


def encode_set_approval_for_all(operator: str, approved: bool) -> str:
    """setApprovalForAll(address,bool)."""
    return _call(
        "setApprovalForAll(address,bool)",
        ["address", "bool"],
        [to_checksum_address(operator), approved],
    )


def encode_erc1155_safe_transfer(frm: str, to: str, token_id: int, amount: int) -> str:
    """safeTransferFrom(address,address,uint256,uint256,bytes)."""
    return _call(
        "safeTransferFrom(address,address,uint256,uint256,bytes)",
        ["address", "address", "uint256", "uint256", "bytes"],
        [to_checksum_address(frm), to_checksum_address(to), token_id, amount, b""],
    )


def encode_onramp_wrap(asset: str, to: str, amount: int) -> str:
    """CollateralOnramp.wrap(address,address,uint256) — USDC.e only; mints pUSD to `to`."""
    return _call(
        "wrap(address,address,uint256)",
        ["address", "address", "uint256"],
        [to_checksum_address(asset), to_checksum_address(to), amount],
    )


def encode_redeem_positions(condition_id: str, index_sets: list) -> str:
    """Collateral-adapter redeemPositions(address,bytes32,bytes32,uint256[]).

    Both CtfCollateralAdapter and NegRiskCtfCollateralAdapter expose this
    4-arg signature; only the destination contract differs. The deployed
    adapters ignore the uint256[] argument (they read position balances and
    partition themselves) — passing [1 << outcomeIndex] documents intent.
    """
    condition = bytes.fromhex(condition_id.removeprefix("0x"))
    return _call(
        "redeemPositions(address,bytes32,bytes32,uint256[])",
        ["address", "bytes32", "bytes32", "uint256[]"],
        [PUSD, PARENT_COLLECTION_ID, condition, index_sets],
    )


# --- chain reads --------------------------------------------------------------------


def _eth_call(w3: Web3, to: str, data: str) -> bytes:
    return bytes(w3.eth.call({"to": to_checksum_address(to), "data": data}))


def erc20_balance_of(w3: Web3, token: str, owner: str) -> int:
    """ERC-20 balanceOf(owner), in base units."""
    data = _call("balanceOf(address)", ["address"], [to_checksum_address(owner)])
    return int.from_bytes(_eth_call(w3, token, data), "big")


def erc20_allowance(w3: Web3, token: str, owner: str, spender: str) -> int:
    """ERC-20 allowance(owner, spender)."""
    data = _call(
        "allowance(address,address)",
        ["address", "address"],
        [to_checksum_address(owner), to_checksum_address(spender)],
    )
    return int.from_bytes(_eth_call(w3, token, data), "big")


def erc1155_balance_of(w3: Web3, token: str, owner: str, token_id: int) -> int:
    """ERC-1155 balanceOf(owner, id)."""
    data = _call(
        "balanceOf(address,uint256)",
        ["address", "uint256"],
        [to_checksum_address(owner), token_id],
    )
    return int.from_bytes(_eth_call(w3, token, data), "big")


def is_approved_for_all(w3: Web3, token: str, owner: str, operator: str) -> bool:
    """ERC-1155 isApprovedForAll(owner, operator)."""
    data = _call(
        "isApprovedForAll(address,address)",
        ["address", "address"],
        [to_checksum_address(owner), to_checksum_address(operator)],
    )
    return int.from_bytes(_eth_call(w3, token, data), "big") == 1


def dw_nonce(w3: Web3, dw: str) -> int:
    """Read the DepositWallet nonce() — replay protection for owner-signed batches."""
    data = "0x" + keccak(text="nonce()")[:4].hex()
    return int.from_bytes(_eth_call(w3, dw, data), "big")


def contract_owner(w3: Web3, address: str) -> str | None:
    """owner() of a contract, or None if it genuinely has no owner().

    Returns None ONLY when the address is not an Ownable contract (the call
    reverts, or there is no code / empty return). A transport/RPC failure is
    re-raised, NOT swallowed as None — callers use None to mean "not owned by
    us / not deployed" and would otherwise redeploy over a funded wallet on a
    transient RPC blip.
    """
    try:
        raw = _eth_call(w3, address, "0x" + keccak(text="owner()")[:4].hex())
    except ContractLogicError:
        return None  # reverted → not an Ownable contract
    if len(raw) < 32:
        return None  # no code / empty return → not Ownable
    return to_checksum_address("0x" + raw.hex()[-40:])


# --- canonical approval set ------------------------------------------------------------

# The trading rights the DepositWallet needs: 3 pUSD allowances and 3 CTF
# operator grants, one pair per exchange venue (CTF Exchange, NegRisk CTF
# Exchange, NegRisk Adapter). The two *collateral adapters* are deliberately
# NOT here: redemption runs from the service safe, never the DW (see
# redeem.py, which grants those to the safe itself), so granting the DW
# operator rights over contracts it never calls would be needless authority.
APPROVAL_SPENDERS_PUSD = (CTF_EXCHANGE, NEG_RISK_CTF_EXCHANGE, NEG_RISK_ADAPTER)
APPROVAL_OPERATORS_CTF = (
    CTF_EXCHANGE,
    NEG_RISK_CTF_EXCHANGE,
    NEG_RISK_ADAPTER,
)


def approvals_status(w3: Web3, owner: str) -> dict:
    """Read the on-chain approval state for `owner` against the canonical set."""
    return {
        "pusd_allowances": {
            spender: erc20_allowance(w3, PUSD, owner, spender) > 0
            for spender in APPROVAL_SPENDERS_PUSD
        },
        "ctf_operators": {
            operator: is_approved_for_all(w3, CTF, owner, operator)
            for operator in APPROVAL_OPERATORS_CTF
        },
    }


def missing_approval_calls(w3: Web3, owner: str) -> list:
    """Return the {"target","data"} calls that grant whatever the set lacks."""
    status = approvals_status(w3, owner)
    calls: list = []
    for spender, ok in status["pusd_allowances"].items():
        if not ok:
            calls.append(
                {"target": PUSD, "data": encode_erc20_approve(spender, MAX_UINT256)}
            )
    for operator, ok in status["ctf_operators"].items():
        if not ok:
            calls.append(
                {"target": CTF, "data": encode_set_approval_for_all(operator, True)}
            )
    return calls


# --- misc -------------------------------------------------------------------------------


def usd_to_units(amount: float) -> int:
    """Whole-token pUSD/USDC amount → 6-decimal base units."""
    return int(round(amount * 10**PUSD_DECIMALS))


def units_to_usd(units: int) -> float:
    """6-decimal base units → whole-token amount."""
    return units / 10**PUSD_DECIMALS


def http_get_json(url: str, params: dict | None = None) -> t.Any:
    """GET a public JSON endpoint (Gamma / data-api / CLOB reads)."""
    response = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
    response.raise_for_status()
    return response.json()


def print_json(payload: t.Any) -> None:
    """Print a JSON result for the calling agent to read."""
    print(json.dumps(payload, indent=2, default=str))
