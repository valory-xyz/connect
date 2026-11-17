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

"""The intent gate: simulate a send at head and check it against its intent.

The rules, what the asset diff is read from and what it cannot see are in
the README, "Intent gate"; `Rule` is the full list of rule names.
"""

import re
import typing as t

from connect.chains import NATIVE_ERC20_FACES as _FACES
from connect.safe import ZERO_ADDRESS, calldata_hex
from connect.texts import (
    GATE_PROBLEM,
    NOT_SENT_SUFFIX,
    gate_overspend,
    gate_receive_min,
    gate_undeclared_approval,
    gate_undeclared_recipient,
)

TokenKey = str  # an ERC-20 address, lower-case, or "native"
NATIVE = "native"
MAX_UINT256 = 2**256 - 1
# traceTransfers reports native value as Transfer logs from this address
NATIVE_LOG_ADDRESS = "0x" + "ee" * 20
# a native transfer simulated beside every call, whose log proves the RPC
# honoured traceTransfers: without it no call's native moves can be seen
TRACE_CANARY_FROM = "0x" + "00" * 18 + "c0de"
TRACE_CANARY_TO = "0x" + "00" * 18 + "c0df"
TRACE_CANARY_VALUE = 1
# mapRequesterBalances(address), a mech balance tracker's prepaid balance of a
# requester (the pinned mech-client's tracker ABIs); read before and after the
# call in the same simulated block, from this address
REQUESTER_BALANCE_SELECTOR = "0x6aeeffa8"
PREPAID_READER = "0x" + "00" * 18 + "c0e0"

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
# Permit2 (the same address on every chain) grants allowances of its own:
# Approval(owner, token, spender, amount, expiration) from approve(), and
# Permit(owner, token, spender, amount, expiration, nonce) from a signed permit
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
PERMIT2_APPROVAL = "0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b"
PERMIT2_PERMIT = "0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec"
MAX_UINT160 = 2**160 - 1
TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"
DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"
# an EIP-7702 delegated EOA's code: this prefix and the 20-byte delegate
EIP7702_DELEGATION_PREFIX = bytes.fromhex("ef0100")
EIP7702_DELEGATION_LENGTH = 23

# native ERC-20 faces (Celo's CELO): their Transfer logs are native moves
NATIVE_ERC20_FACES = frozenset(_FACES.values())

Rule = t.Literal[
    "reverts",
    "bad-intent",
    "overspend",
    "receive-min",
    "undeclared-recipient",
    "undeclared-approval",
    "simulation-unavailable",
    "token-cap-positions",
    "approve-hash",
    "bad-exec-transaction",
    "bad-calldata",
]
RULES: tuple[str, ...] = t.get_args(Rule)


class IntentApproval(t.TypedDict):
    """One approval the intent allows: at most `amount` of `token` to `spender`."""

    token: TokenKey
    spender: str
    amount: int


class Intent(t.TypedDict, total=False):
    """What a value-moving transaction may do."""

    spend: dict[TokenKey, int]
    receive_min: dict[TokenKey, int]
    recipients: list[str]
    approvals: list[IntentApproval]
    # set only through Capped, never by a caller: no position may leave
    positions_locked: bool
    # set only by `implied_intent`, never by a caller: what a call with no
    # intent is held to, under which a position leaving is an overspend (or
    # `token-cap-positions`, when `positions_locked`)
    implied: bool


class Capped(t.NamedTuple):
    """The intent of a call made with a value-capped token.

    A cap is a limit per token, and an ERC-721/1155 position is not one, so
    no cap can bound it: under a capped token no position may leave the
    sender. Only the server wraps an intent so; no request body can.
    """

    raw: t.Any


# what an agent surface may hand the gate: an intent as sent, or one Capped.
# Never the signer's SERVER_BUILT, the one gate bypass, so mypy keeps that
# sentinel off every agent path.
AgentIntent = dict | Capped | None


class Problem(t.TypedDict):
    """One rule a simulated transaction broke."""

    rule: Rule
    detail: str


# strict: bytes.fromhex would skip whitespace, and the raw string goes on
_HEX_CALLDATA = re.compile(r"(0[xX])?[0-9a-fA-F]*")


def calldata_problem(data: str) -> Problem | None:
    """Return the bad-calldata problem for calldata that is not hex, else None.

    Checked before anything reaches the RPC, so a caller's typo is refused as
    one rather than as the RPC failing to simulate it.
    """
    raw = data or ""
    if _HEX_CALLDATA.fullmatch(raw) and len(calldata_hex(raw)) % 2 == 0:
        return None
    return Problem(
        rule="bad-calldata",
        detail="cannot decode the calldata: it must be hex of whole bytes, "
        "0x-prefixed or bare, with nothing else in it (no spaces)",
    )


class AssetDiff(t.TypedDict):
    """What a simulated transaction does to the sender's assets.

    `native` and `tokens` include what `prepaid` lists: each fall of the
    sender's prepaid balance at a mech balance tracker, in that tracker's asset.
    """

    ok: bool
    revert: str | None
    native: str
    tokens: dict[str, dict[str, str]]
    prepaid: list[dict[str, str]]
    recipients: list[dict[str, t.Any]]
    approvals: list[dict[str, t.Any]]
    positions: list[dict[str, str]]
    called: list[str]
    gas_used: int


class SimulationUnavailable(Exception):
    """The chain's RPC could not simulate the transaction."""


Rpc = t.Callable[[str, list], t.Any]


def _word(data: str, index: int) -> int:
    """Return the `index`-th 32-byte word of hex `data` as an int."""
    raw = data.removeprefix("0x")
    chunk = raw[index * 64 : (index + 1) * 64]
    return int(chunk, 16) if chunk else 0


def _topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def _revert_reason(error: t.Any, return_data: str) -> str:
    """Decode an `Error(string)` revert, else the RPC's message, else the raw data.

    `error` is the call's error object; some RPCs answer a bare string instead,
    which is read as the message.
    """
    if not isinstance(error, t.Mapping):
        error = {"message": error} if isinstance(error, str) else {}
    data = str(error.get("data") or return_data or "0x")
    raw = data.removeprefix("0x")
    if raw.startswith("08c379a0") and len(raw) >= 8 + 128:
        try:
            length = int(raw[8 + 64 : 8 + 128], 16)
            text = bytes.fromhex(raw[8 + 128 : 8 + 128 + length * 2])
            return text.decode("utf-8", errors="replace")
        except ValueError:
            pass
    message = error.get("message")
    return str(message) if message else ("reverted" if raw == "" else "0x" + raw)


def simulate(  # pylint: disable=too-many-arguments,too-many-locals
    rpc: Rpc,
    *,
    sender: str,
    to: str,
    value: int,
    data: str,
    get_code: t.Callable[[str], bytes],
    prepaid: t.Mapping[str, TokenKey] | None = None,
) -> AssetDiff:
    """Simulate one call at head and return what it does to `sender`'s assets.

    `rpc(method, params)` returns the JSON-RPC result or raises
    SimulationUnavailable; `get_code(address)` tells an EOA from a contract.
    `prepaid` maps each mech balance tracker to the asset its balance is in:
    the sender's balance there is read before and after the call, in the
    same simulated block, and a fall is spent of that asset.
    """
    assets = dict(prepaid or {})
    trackers = sorted(assets)
    reads = [
        {"from": PREPAID_READER, "to": tracker, "data": _balance_read(sender)}
        for tracker in trackers
    ]
    payload = {
        "blockStateCalls": [
            {
                "stateOverrides": {
                    TRACE_CANARY_FROM: {"balance": hex(TRACE_CANARY_VALUE)}
                },
                "calls": [
                    *reads,
                    {
                        "from": sender,
                        "to": to,
                        "value": hex(value),
                        "data": data or "0x",
                    },
                    {
                        "from": TRACE_CANARY_FROM,
                        "to": TRACE_CANARY_TO,
                        "value": hex(TRACE_CANARY_VALUE),
                    },
                    *reads,
                ],
            }
        ],
        "traceTransfers": True,
        "validation": False,
    }
    result = rpc("eth_simulateV1", [payload, "latest"])
    try:
        answered = list(result[0]["calls"])
        before = answered[: len(reads)]
        call, canary = answered[len(reads) : len(reads) + 2]
        after = answered[len(reads) + 2 :]
        ok = str(call.get("status", "0x0")) in ("0x1", "1")
        logs = list(call.get("logs") or [])
        canary_logs = list(canary.get("logs") or [])
    except (IndexError, KeyError, TypeError, AttributeError, ValueError) as e:
        raise SimulationUnavailable(f"unexpected eth_simulateV1 answer: {e}") from e
    try:
        falls = _prepaid_falls(trackers, before, after)
        diff = _diff(sender.lower(), logs, get_code)
        gas_used = int(str(call.get("gasUsed", "0x0")), 16)
        traced = (
            TRACE_CANARY_FROM,
            TRACE_CANARY_TO,
            TRACE_CANARY_VALUE,
        ) in _native_moves(canary_logs)
    except (TypeError, ValueError, AttributeError) as e:
        raise SimulationUnavailable(f"unreadable eth_simulateV1 answer: {e}") from e
    if not traced:
        # an RPC that ignores traceTransfers logs no native move at all, so a
        # call moving native internally, at any value, would look like none
        raise SimulationUnavailable(
            "the RPC did not trace a native transfer (traceTransfers), so the "
            "call's native moves cannot be checked"
        )
    if ok and value > 0:
        sent = sum(a for src, _, a in _native_moves(logs) if src == sender.lower())
        if sent < value:
            # traced, yet short of the value sent: an answer not to trust
            raise SimulationUnavailable(
                "the RPC did not trace the call's native transfer "
                "(traceTransfers), so its native moves cannot be checked"
            )
    for tracker, fall in falls.items():
        if assets[tracker] == NATIVE:
            diff["native"] -= fall
        else:
            diff["tokens"][assets[tracker]] = (
                diff["tokens"].get(assets[tracker], 0) - fall
            )
    called = [to.lower()]
    for log in logs:
        address = str(log.get("address", "")).lower()
        if address and address != NATIVE_LOG_ADDRESS and address not in called:
            called.append(address)
    return AssetDiff(
        ok=ok,
        revert=(
            None
            if ok
            else _revert_reason(call.get("error"), call.get("returnData", ""))
        ),
        native=str(diff["native"]),
        tokens={
            token: {"symbol": _symbol(rpc, token), "delta": str(delta)}
            for token, delta in sorted(diff["tokens"].items())
            if delta
        },
        prepaid=[
            {"tracker": tracker, "token": assets[tracker], "delta": str(-fall)}
            for tracker, fall in falls.items()
        ],
        recipients=diff["recipients"],
        approvals=[
            entry
            for entry in diff["approvals"]
            if not _lowers_an_allowance(rpc, sender.lower(), entry)
        ],
        positions=diff["positions"],
        called=called,
        gas_used=gas_used,
    )


def _balance_read(holder: str) -> str:
    """Return the calldata of mapRequesterBalances(holder)."""
    return REQUESTER_BALANCE_SELECTOR + holder.lower().removeprefix("0x").rjust(64, "0")


def _prepaid_falls(
    trackers: list[str], before: list[dict], after: list[dict]
) -> dict[str, int]:
    """Return how far the prepaid balance fell at each tracker, where it fell.

    A read that did not answer one whole word fails the simulation: a fall
    it hides would be a spend the gate cannot see.
    """
    if len(before) != len(trackers) or len(after) != len(trackers):
        raise SimulationUnavailable("the prepaid mech balance reads went unanswered")
    falls: dict[str, int] = {}
    for tracker, was, now in zip(trackers, before, after):
        balances = []
        for read in (was, now):
            raw = str(read.get("returnData") or "").removeprefix("0x")
            if str(read.get("status")) not in ("0x1", "1") or len(raw) != 64:
                raise SimulationUnavailable(
                    f"could not read the prepaid mech balance at {tracker}"
                )
            balances.append(int(raw, 16))
        if balances[1] < balances[0]:
            falls[tracker] = balances[0] - balances[1]
    return falls


ALLOWANCE_SELECTOR = "0xdd62ed3e"  # allowance(address,address)


def _lowers_an_allowance(rpc: Rpc, holder: str, entry: dict[str, t.Any]) -> bool:
    """Whether an ERC-20 Approval only lowers what the spender already had.

    OpenZeppelin 4.x tokens emit Approval from transferFrom as they spend an
    allowance down: no new grant, so it is not one the intent must declare.
    The allowance is read at head, before the call; a read that fails keeps
    the approval, so a doubt is checked rather than waved through.
    """
    if "id" in entry or "via" in entry or entry["amount"] in ("0", "all"):
        # a revoke is skipped anyway; NFTs have no allowance; a Permit2 grant
        # is not an ERC-20 allowance, so the token's allowance() says nothing
        return False
    data = (
        ALLOWANCE_SELECTOR
        + holder.removeprefix("0x").rjust(64, "0")
        + str(entry["spender"]).removeprefix("0x").rjust(64, "0")
    )
    try:
        before = int(
            str(rpc("eth_call", [{"to": entry["token"], "data": data}, "latest"])), 16
        )
    except (SimulationUnavailable, ValueError):
        return False
    return int(entry["amount"]) <= before


SYMBOL_SELECTOR = "0x95d89b41"  # symbol()
MAX_SYMBOL_CHARS = 32


def _symbol(rpc: Rpc, token: str) -> str:
    """Read an ERC-20's symbol() for the report; "" when it has none to give.

    Display only: nothing is checked against it, and a token answers what it
    likes, so a failed or odd read never fails the simulation.
    """
    try:
        raw = bytes.fromhex(
            str(
                rpc("eth_call", [{"to": token, "data": SYMBOL_SELECTOR}, "latest"])
            ).removeprefix("0x")
        )
    except (SimulationUnavailable, ValueError):
        return ""
    if len(raw) == 32:  # bytes32, as MKR and other early tokens answer
        text = raw.rstrip(b"\0")
    elif len(raw) >= 64:  # an ABI string: offset, length, bytes
        text = raw[64 : 64 + int.from_bytes(raw[32:64], "big")]
    else:
        return ""
    return text.decode("utf-8", "replace")[:MAX_SYMBOL_CHARS]


def _native_moves(logs: list[dict]) -> list[tuple[str, str, int]]:
    """Return native (from, to, amount) moves.

    Two sources, which never report the same move: the synthetic 0xeeee logs
    `traceTransfers` emits for native value, and the Transfer logs of a native
    ERC-20 face (a CELO.transfer emits only the face's). Checked against Celo's
    RPC: a plain send logs only the synthetic one, a face transfer only its own.
    """
    return [
        (src, dst, _word(data, 0))
        for address, src, dst, data in _erc20_transfers(logs)
        if _is_native_log(address)
    ]


def _is_native_log(address: str) -> bool:
    """Whether a `Transfer` log from `address` moves native value, not a token."""
    return address == NATIVE_LOG_ADDRESS or address in NATIVE_ERC20_FACES


def _erc20_transfers(logs: list[dict]) -> t.Iterator[tuple[str, str, str, str]]:
    """Yield (token, from, to, data) of every 3-topic `Transfer` log, lowercased."""
    for log in logs:
        topics = [str(x).lower() for x in log.get("topics") or []]
        if len(topics) == 3 and topics[0] == TRANSFER:
            yield (
                str(log.get("address", "")).lower(),
                _topic_address(topics[1]),
                _topic_address(topics[2]),
                str(log.get("data", "0x")),
            )


def _diff(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    holder: str, logs: list[dict], get_code: t.Callable[[str], bytes]
) -> dict:
    """Fold the simulated logs into `holder`'s balance changes and grants."""
    native = 0
    tokens: dict[str, int] = {}
    positions: dict[tuple[str, str], int] = {}
    approvals: list[dict[str, t.Any]] = []
    receivers: list[str] = []
    minted, burned = _wrapped_by_transfer(holder, logs)

    def _sent_to(receiver: str) -> None:
        if receiver not in (holder, ZERO_ADDRESS) and receiver not in receivers:
            receivers.append(receiver)

    for src, dst, amount in _native_moves(logs):
        if src == holder:
            native -= amount
            _sent_to(dst)
        if dst == holder:
            native += amount

    for address, src, dst, data in _erc20_transfers(logs):
        if _is_native_log(address):
            continue  # native moves, counted above
        amount = _word(data, 0)
        if src == holder:
            tokens[address] = tokens.get(address, 0) - amount
            _sent_to(dst)
        if dst == holder:
            tokens[address] = tokens.get(address, 0) + amount

    for log in logs:  # every other log; a 3-topic Transfer matches no branch
        address = str(log.get("address", "")).lower()
        topics = [str(x).lower() for x in log.get("topics") or []]
        if address == NATIVE_LOG_ADDRESS or not topics:
            continue
        data = str(log.get("data", "0x"))
        kind = topics[0]
        if kind == TRANSFER and len(topics) == 4:  # ERC-721
            src, dst = _topic_address(topics[1]), _topic_address(topics[2])
            key = (address, str(int(topics[3], 16)))
            if src == holder:
                positions[key] = positions.get(key, 0) - 1
                _sent_to(dst)
            if dst == holder:
                positions[key] = positions.get(key, 0) + 1
        elif kind in (TRANSFER_SINGLE, TRANSFER_BATCH) and len(topics) == 4:
            src, dst = _topic_address(topics[2]), _topic_address(topics[3])
            for token_id, amount in _erc1155_items(kind, data):
                key = (address, str(token_id))
                if src == holder:
                    positions[key] = positions.get(key, 0) - amount
                    _sent_to(dst)
                if dst == holder:
                    positions[key] = positions.get(key, 0) + amount
        elif kind == DEPOSIT and len(topics) == 2:  # WETH minted to dst
            if _topic_address(topics[1]) == holder and address not in minted:
                tokens[address] = tokens.get(address, 0) + _word(data, 0)
        elif kind == WITHDRAWAL and len(topics) == 2:  # WETH burned from src
            if _topic_address(topics[1]) == holder and address not in burned:
                tokens[address] = tokens.get(address, 0) - _word(data, 0)
        elif (
            address == PERMIT2
            and kind in (PERMIT2_APPROVAL, PERMIT2_PERMIT)
            and len(topics) == 4
        ):
            # Permit2 lets the spender move the token itself: a grant of the
            # token, keyed as an ERC-20 approval of it would be
            if _topic_address(topics[1]) == holder:
                amount = _word(data, 0)
                approvals.append(
                    {
                        "token": _topic_address(topics[2]),
                        "spender": _topic_address(topics[3]),
                        "amount": str(amount),
                        "infinite": amount == MAX_UINT160,
                        "via": "permit2",
                    }
                )
        elif kind == APPROVAL and len(topics) == 4:  # ERC-721: all indexed
            if _topic_address(topics[1]) == holder:
                spender = _topic_address(topics[2])
                approvals.append(
                    {
                        "token": address,
                        "spender": spender,
                        # approving the zero address clears it: a revoke
                        "amount": "0" if spender == ZERO_ADDRESS else "1",
                        "infinite": False,
                        "id": str(int(topics[3], 16)),
                    }
                )
        elif kind == APPROVAL and len(topics) == 3:
            if _topic_address(topics[1]) == holder:
                amount = _word(data, 0)
                approvals.append(
                    {
                        "token": address,
                        "spender": _topic_address(topics[2]),
                        "amount": str(amount),
                        "infinite": amount == MAX_UINT256,
                    }
                )
        elif kind == APPROVAL_FOR_ALL and len(topics) == 3:
            if _topic_address(topics[1]) == holder:
                approvals.append(
                    {
                        "token": address,
                        "spender": _topic_address(topics[2]),
                        "amount": "all",
                        "infinite": True,
                    }
                )

    recipients = [
        {"address": receiver, "contract": _is_contract(get_code(receiver))}
        for receiver in receivers
    ]
    return {
        "native": native,
        "tokens": tokens,
        "approvals": approvals,
        "recipients": recipients,
        "positions": [
            {"token": token, "id": token_id, "delta": str(delta)}
            for (token, token_id), delta in sorted(positions.items())
            if delta
        ],
    }


def _is_contract(code: bytes) -> bool:
    """Whether code is a contract's, not an EOA's — an EIP-7702 delegation is not.

    A delegated EOA carries only a pointer to its delegate's code, and its
    key still moves what it holds: a transfer there leaves for an EOA.
    """
    delegated = len(code) == EIP7702_DELEGATION_LENGTH and code.startswith(
        EIP7702_DELEGATION_PREFIX
    )
    return bool(code) and not delegated


def _wrapped_by_transfer(holder: str, logs: list[dict]) -> tuple[set, set]:
    """Return the tokens that logged a Transfer mint to, and a burn from, `holder`.

    Solmate- and OpenZeppelin-style WETH log both Transfer and Deposit (or
    Withdrawal) for one wrap; the Transfer is counted, so that Deposit is not.
    """
    minted: set[str] = set()
    burned: set[str] = set()
    for address, src, dst, _ in _erc20_transfers(logs):
        if src == ZERO_ADDRESS and dst == holder:
            minted.add(address)
        if src == holder and dst == ZERO_ADDRESS:
            burned.add(address)
    return minted, burned


def _erc1155_items(kind: str, data: str) -> list[tuple[int, int]]:
    """Return (id, amount) pairs of a TransferSingle or TransferBatch."""
    if kind == TRANSFER_SINGLE:
        return [(_word(data, 0), _word(data, 1))]
    words = len(data.removeprefix("0x")) // 64
    ids_at, amounts_at = _word(data, 0) // 32, _word(data, 1) // 32
    count = _word(data, ids_at)
    # the contract controls these words: an array longer than the data is a
    # malformed log, and must not make the gate loop over it
    if (
        count != _word(data, amounts_at)
        or ids_at + 1 + count > words
        or amounts_at + 1 + count > words
    ):
        raise SimulationUnavailable("malformed TransferBatch log in the simulation")
    return [
        (_word(data, ids_at + 1 + i), _word(data, amounts_at + 1 + i))
        for i in range(count)
    ]


def implied_intent(value: int, target: str, *, positions_locked: bool) -> Intent:
    """Return a no-intent call's implied intent: its own value, to its own target.

    Nothing else: a position leaving is an overspend, or `token-cap-positions`
    when `positions_locked`.
    """
    return Intent(
        spend={NATIVE: value} if value else {},
        receive_min={},
        recipients=[target.lower()],
        approvals=[],
        positions_locked=positions_locked,
        implied=True,
    )


def parse_intent(
    raw: t.Any, *, strict: bool = False
) -> tuple[Intent | None, list[Problem]]:
    """Validate a caller's intent; return it normalised, or a bad-intent problem.

    A key the gate does not read, in the intent or an approval, is ignored, as
    the reference ignores it (B1, D11); `strict` (the `strict_parameters`
    switch) refuses it instead. An ignored key declares nothing: a misspelled
    `spend` leaves nothing to spend, and a misspelled `receive_min` sets no
    floor.
    """
    if not isinstance(raw, Capped):
        return _parse(raw, strict)
    parsed, problems = _parse(raw.raw, strict)
    if parsed is not None:
        parsed["positions_locked"] = True
    return parsed, problems


def _parse(raw: t.Any, strict: bool) -> tuple[Intent | None, list[Problem]]:
    if raw is None:
        return None, []
    if not isinstance(raw, dict):
        return None, [_bad("the intent must be an object")]
    unknown = sorted(set(raw) - {"spend", "receive_min", "recipients", "approvals"})
    if strict and unknown:
        return None, [_bad(f"unknown intent keys {unknown}")]
    try:
        intent = Intent(
            spend=_amounts(raw.get("spend") or {}, "spend"),
            receive_min=_amounts(raw.get("receive_min") or {}, "receive_min"),
            recipients=[_address(a) for a in raw.get("recipients") or []],
            approvals=[_approval(a, strict) for a in raw.get("approvals") or []],
        )
    except KeyError as e:
        return None, [_bad(f"an intent approval is missing {e}")]
    except (TypeError, ValueError, AttributeError) as e:
        return None, [_bad(str(e))]
    return intent, []


def _bad(detail: str) -> Problem:
    return Problem(rule="bad-intent", detail=detail)


def _token(key: t.Any) -> TokenKey:
    text = str(key).lower()
    if text == NATIVE:
        return NATIVE
    return _address(text)


def _address(value: t.Any) -> str:
    text = str(value).lower()
    if not (text.startswith("0x") and len(text) == 42):
        raise ValueError(f"'{value}' is not a 0x-prefixed 20-byte address")
    int(text, 16)
    return text


def parse_amount(value: t.Any) -> int:
    """Parse an amount in base units: an int or an int string, >= 0.

    A float is refused, not truncated: 0.9 must not become a minimum of 0, and
    a large one has already lost its precision. So is a bool.

    :raises TypeError: not a whole number. :raises ValueError: negative.
    """
    if isinstance(value, (bool, float)):
        raise TypeError("an amount must be a whole number of base units")
    parsed = int(value, 0) if isinstance(value, str) else int(value)
    if parsed < 0:
        raise ValueError("an amount must be >= 0")
    return parsed


# the largest integer a JSON number carries exactly (an IEEE-754 double's):
# 2^53 + 1 is the first a double cannot hold, and it rounds to 2^53
MAX_EXACT_JSON_INT = 2**53 - 1


def parse_tool_amount(value: t.Any) -> int:
    """Parse a base-unit amount from the agent tool surface, where it is a string.

    A decimal or 0x-hex string, read as `parse_amount` reads it. A JSON
    integer is taken up to 2^53 - 1, the most a JSON number carries exactly;
    a float, or an integer past that, is refused: a client may already have
    rounded it (2^53 + 1 arrives as 2^53).

    :raises TypeError: not a whole number, or past 2^53 - 1. :raises ValueError:
        negative, or a string that is not a number.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        if value > MAX_EXACT_JSON_INT:
            raise TypeError(
                "a JSON number is exact only up to 2^53 - 1; pass a larger amount "
                "as a decimal or 0x-hex string"
            )
    return parse_amount(value)


def intent_amounts(raw: t.Any) -> list[tuple[str, t.Any]]:
    """Return each base-unit amount a raw intent declares, named by where it sits.

    Only what has an intent's shape is read: `parse_intent` refuses the rest.
    """
    if not isinstance(raw, dict):
        return []
    found: list[tuple[str, t.Any]] = []
    for where in ("spend", "receive_min"):
        entries = raw.get(where)
        if isinstance(entries, dict):
            found += [(f"intent.{where}.{token}", v) for token, v in entries.items()]
    approvals = raw.get("approvals")
    for index, approval in enumerate(approvals if isinstance(approvals, list) else []):
        if isinstance(approval, dict) and "amount" in approval:
            found.append((f"intent.approvals[{index}].amount", approval["amount"]))
    return found


def balance_key(key: t.Any) -> TokenKey:
    """Return the key a balance change of `key` is booked under in a diff.

    A native ERC-20 face (Celo's CELO) moves the native balance, and its
    moves are booked under "native", so a spend or receive_min naming the face
    must too. Raises ValueError for anything but "native" or an address.
    """
    token = _token(key)
    return NATIVE if token in NATIVE_ERC20_FACES else token


def _amounts(raw: t.Any, where: str) -> dict[TokenKey, int]:
    if not isinstance(raw, dict):
        raise TypeError(f"intent '{where}' must be an object of token -> amount")
    amounts: dict[TokenKey, int] = {}
    for token, value in raw.items():
        key = balance_key(token)
        if key in amounts:
            raise ValueError(f"intent '{where}' names {key} twice")
        amounts[key] = parse_amount(value)
    return amounts


def _approval(raw: t.Any, strict: bool) -> IntentApproval:
    if not isinstance(raw, dict):
        raise TypeError("each intent approval must be {token, spender, amount}")
    unknown = sorted(set(raw) - {"token", "spender", "amount"})
    if strict and unknown:
        raise ValueError(f"unknown intent approval keys {unknown}")
    return IntentApproval(
        token=_token(raw["token"]),
        spender=_address(raw["spender"]),
        amount=parse_amount(raw["amount"]),
    )


def check_intent(diff: AssetDiff, intent: Intent | None) -> list[Problem]:
    """Return every rule the simulated transaction breaks under `intent`."""
    problems: list[Problem] = []
    if not diff["ok"]:
        problems.append(Problem(rule="reverts", detail=str(diff["revert"])))
    if intent is None:  # nothing declared: only a revert is refused
        return problems
    spend = intent.get("spend", {})
    deltas = {NATIVE: int(diff["native"])}
    deltas.update({token: int(e["delta"]) for token, e in diff["tokens"].items()})
    for token, delta in deltas.items():
        if delta < 0 and -delta > spend.get(token, 0):
            problems.append(
                Problem(
                    rule="overspend",
                    detail=gate_overspend(
                        _named(diff, token), -delta, spend.get(token, 0)
                    ),
                )
            )
    for token, least in intent.get("receive_min", {}).items():
        if deltas.get(token, 0) < least:
            problems.append(
                Problem(
                    rule="receive-min",
                    detail=gate_receive_min(
                        _named(diff, token), deltas.get(token, 0), least
                    ),
                )
            )
    allowed = set(intent.get("recipients", []))
    for entry in diff["recipients"]:
        if not entry["contract"] and entry["address"] not in allowed:
            problems.append(
                Problem(
                    rule="undeclared-recipient",
                    detail=gate_undeclared_recipient(entry["address"]),
                )
            )
    granted = intent.get("approvals", [])
    for entry in diff["approvals"]:
        if entry["amount"] == "0":
            continue  # an approval of 0 (a revoke) is never refused
        amount = MAX_UINT256 if entry["amount"] == "all" else int(entry["amount"])
        if not any(
            g["token"] == entry["token"]
            and g["spender"] == entry["spender"]
            and g["amount"] >= amount
            for g in granted
        ):
            problems.append(
                Problem(
                    rule="undeclared-approval",
                    detail=gate_undeclared_approval(
                        _named(diff, entry["token"]),
                        entry["spender"],
                        entry["amount"],
                    ),
                )
            )
    # a capped token's rule replaces overspend, so each position is reported once
    for position in _leaving(diff):
        where = f"{position['token']} #{position['id']}"
        if intent.get("positions_locked"):
            problems.append(
                Problem(
                    rule="token-cap-positions",
                    detail=f"moves {where} out, "
                    "and a value-capped token may not move positions",
                )
            )
        elif intent.get("implied"):
            problems.append(
                Problem(
                    rule="overspend",
                    detail=gate_overspend(where, -int(position["delta"]), 0),
                )
            )
    return problems


def _leaving(diff: AssetDiff) -> list[dict]:
    """Return the positions the call moves out of the sender."""
    return [p for p in diff["positions"] if int(p["delta"]) < 0]


def locks_positions(raw: t.Any) -> bool:
    """Whether an intent comes under a capped token, which moves no position."""
    return isinstance(raw, Capped)


def no_intent_hold(
    value: int, target: str, *, strict: bool, capped: bool
) -> Intent | None:
    """Return what a call with no intent is held to, or None for a revert check alone.

    Under `strict`, and always under a capped token (which no cap could bound
    otherwise), it is held to its own value and target (`implied_intent`), a
    capped token's with no position leaving.
    """
    if not (strict or capped):
        return None
    return implied_intent(value, target, positions_locked=capped)


def simulation_answer(
    diff: AssetDiff | None, held_to: Intent | None, problems: list[Problem]
) -> dict:
    """Return what `simulate_transaction` answers: the diff, and its verdict.

    A call held to nothing (`held_to` None: no intent, `simulate-only`, no
    capped token) answers no verdict and no problems, as the reference does:
    a revert shows in the diff's own `ok` and `revert`, not as a problem.
    """
    texts = [problem_text(p) for p in problems]
    if diff is None:
        return {"fits_intent": False, "problems": texts}
    if held_to is None:
        return {**diff, "fits_intent": None, "problems": []}
    return {**diff, "fits_intent": not problems, "problems": texts}


def problem_text(problem: Problem) -> str:
    """Return one problem as the reference words it."""
    return GATE_PROBLEM(problem["rule"], problem["detail"])


def refusal_message(problems: list[Problem]) -> str:
    """Return the one-line refusal a session reads: every rule, then not-sent."""
    return "; ".join(problem_text(p) for p in problems) + NOT_SENT_SUFFIX


def _named(diff: AssetDiff, token: str) -> str:
    """Return how a problem names a token: its symbol, else its key."""
    entry = diff["tokens"].get(token)
    return (entry or {}).get("symbol") or token
