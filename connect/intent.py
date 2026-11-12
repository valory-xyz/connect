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

"""The intent gate: simulate a send and check it against its intent.

A model can report success on a transaction
that moved the wrong amount. So every agent-originated value-moving send
carries an *intent* (what it may spend, the least it must receive, who may
receive and what may be approved),
and the transaction is simulated at head with `eth_simulateV1` before it is
signed. The asset diff comes from the simulated logs: ERC-20/721 `Transfer`,
`Approval`, `ApprovalForAll`, ERC-1155 `TransferSingle`/`TransferBatch`, WETH
`Deposit`/`Withdrawal`, and the synthetic `Transfer` logs `traceTransfers`
emits from `0xeeee...eeee` for native value. There is no fork and no trace,
so "contracts touched" is the target plus every contract that emitted
a log; a contract called without emitting one is not listed.

The rules:
`reverts`, `bad-intent`, `overspend`, `receive-min`, `undeclared-recipient`
(EOAs only; burns to the zero address are skipped) and `undeclared-approval`
(a 0 approval, a revoke, is not checked; `setApprovalForAll` counts as a
maximum approval, even when revoking). The intent is required:
`missing-intent` refuses a value-moving call that carries
none, and `simulation-unavailable` refuses anything an RPC cannot simulate —
nothing falls back to signing unchecked.
"""

import typing as t

from connect.chains import NATIVE_ERC20_FACES as _FACES
from connect.safe import ZERO_ADDRESS

TokenKey = str  # an ERC-20 address, lower-case, or "native"
NATIVE = "native"
MAX_UINT256 = 2**256 - 1
# traceTransfers reports native value as Transfer logs from this address
NATIVE_LOG_ADDRESS = "0x" + "ee" * 20

TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
TRANSFER_SINGLE = "0xc3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62"
TRANSFER_BATCH = "0x4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb"
DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
WITHDRAWAL = "0x7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65"

# native ERC-20 faces (Celo's CELO): their Transfer logs are native moves
NATIVE_ERC20_FACES = frozenset(_FACES.values())

Rule = t.Literal[
    "reverts",
    "bad-intent",
    "missing-intent",
    "overspend",
    "receive-min",
    "undeclared-recipient",
    "undeclared-approval",
    "simulation-unavailable",
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


class Problem(t.TypedDict):
    """One rule a simulated transaction broke."""

    rule: Rule
    detail: str


class AssetDiff(t.TypedDict):
    """What a simulated transaction does to the sender's assets."""

    ok: bool
    revert: str | None
    native: str
    tokens: dict[str, dict[str, str]]
    recipients: list[dict[str, t.Any]]
    approvals: list[dict[str, t.Any]]
    positions: list[dict[str, str]]
    called: list[str]
    gas_used: int


class SimulationUnavailable(Exception):
    """The chain's RPC could not simulate the transaction."""


Rpc = t.Callable[[str, list], t.Any]


def _hex(value: int) -> str:
    return hex(value)


def _word(data: str, index: int) -> int:
    """Return the `index`-th 32-byte word of hex `data` as an int."""
    raw = data.removeprefix("0x")
    chunk = raw[index * 64 : (index + 1) * 64]
    return int(chunk, 16) if chunk else 0


def _topic_address(topic: str) -> str:
    return "0x" + topic.removeprefix("0x")[-40:].lower()


def _revert_reason(error: t.Mapping[str, t.Any] | None, return_data: str) -> str:
    """Decode an `Error(string)` revert, else the RPC's message, else the raw data."""
    data = str((error or {}).get("data") or return_data or "0x")
    raw = data.removeprefix("0x")
    if raw.startswith("08c379a0") and len(raw) >= 8 + 128:
        try:
            length = int(raw[8 + 64 : 8 + 128], 16)
            text = bytes.fromhex(raw[8 + 128 : 8 + 128 + length * 2])
            return text.decode("utf-8", errors="replace")
        except ValueError:
            pass
    message = (error or {}).get("message")
    return str(message) if message else ("reverted" if raw == "" else "0x" + raw)


def simulate(  # pylint: disable=too-many-arguments,too-many-locals
    rpc: Rpc,
    *,
    sender: str,
    to: str,
    value: int,
    data: str,
    get_code: t.Callable[[str], bytes],
) -> AssetDiff:
    """Simulate one call at head and return what it does to `sender`'s assets.

    `rpc(method, params)` returns the JSON-RPC result or raises
    SimulationUnavailable; `get_code(address)` tells an EOA from a contract.
    """
    payload = {
        "blockStateCalls": [
            {
                "calls": [
                    {
                        "from": sender,
                        "to": to,
                        "value": _hex(value),
                        "data": data or "0x",
                    }
                ]
            }
        ],
        "traceTransfers": True,
        "validation": False,
    }
    result = rpc("eth_simulateV1", [payload, "latest"])
    try:
        call = result[0]["calls"][0]
    except (IndexError, KeyError, TypeError) as e:
        raise SimulationUnavailable(f"unexpected eth_simulateV1 answer: {e}") from e
    ok = str(call.get("status", "0x0")) in ("0x1", "1")
    logs = list(call.get("logs") or [])
    try:
        diff = _diff(sender.lower(), logs, get_code)
        gas_used = int(str(call.get("gasUsed", "0x0")), 16)
    except (TypeError, ValueError, AttributeError) as e:
        raise SimulationUnavailable(f"unreadable eth_simulateV1 answer: {e}") from e
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
            token: {"delta": str(delta)}
            for token, delta in sorted(diff["tokens"].items())
            if delta
        },
        recipients=diff["recipients"],
        approvals=diff["approvals"],
        positions=diff["positions"],
        called=called,
        gas_used=gas_used,
    )


def _native_moves(logs: list[dict]) -> list[tuple[str, str, int]]:
    """Return native (from, to, amount) moves.

    Two sources, which never report the same move: the synthetic 0xeeee logs
    `traceTransfers` emits for native value, and the Transfer logs of a native
    ERC-20 face (a CELO.transfer emits only the face's). Checked against Celo's
    RPC: a plain send logs only the synthetic one, a face transfer only its own.
    """
    moves = []
    for log in logs:
        topics = [str(x).lower() for x in log.get("topics") or []]
        if len(topics) != 3 or topics[0] != TRANSFER:
            continue
        address = str(log.get("address", "")).lower()
        if address == NATIVE_LOG_ADDRESS or address in NATIVE_ERC20_FACES:
            moves.append(
                (
                    _topic_address(topics[1]),
                    _topic_address(topics[2]),
                    _word(str(log.get("data", "0x")), 0),
                )
            )
    return moves


def _diff(  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    holder: str, logs: list[dict], get_code: t.Callable[[str], bytes]
) -> dict:
    """Fold the simulated logs into `holder`'s balance changes and grants."""
    native = 0
    tokens: dict[str, int] = {}
    positions: dict[tuple[str, str], int] = {}
    approvals: list[dict[str, t.Any]] = []
    receivers: list[str] = []

    def _sent_to(receiver: str) -> None:
        if receiver not in (holder, ZERO_ADDRESS) and receiver not in receivers:
            receivers.append(receiver)

    for src, dst, amount in _native_moves(logs):
        if src == holder:
            native -= amount
            _sent_to(dst)
        if dst == holder:
            native += amount

    for log in logs:
        address = str(log.get("address", "")).lower()
        if address in (NATIVE_LOG_ADDRESS, *NATIVE_ERC20_FACES):
            continue
        topics = [str(x).lower() for x in log.get("topics") or []]
        if not topics:
            continue
        data = str(log.get("data", "0x"))
        kind = topics[0]
        if kind == TRANSFER and len(topics) == 3:  # ERC-20
            src, dst = _topic_address(topics[1]), _topic_address(topics[2])
            amount = _word(data, 0)
            if src == holder:
                tokens[address] = tokens.get(address, 0) - amount
                _sent_to(dst)
            if dst == holder:
                tokens[address] = tokens.get(address, 0) + amount
        elif kind == TRANSFER and len(topics) == 4:  # ERC-721
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
            if _topic_address(topics[1]) == holder:
                tokens[address] = tokens.get(address, 0) + _word(data, 0)
        elif kind == WITHDRAWAL and len(topics) == 2:  # WETH burned from src
            if _topic_address(topics[1]) == holder:
                tokens[address] = tokens.get(address, 0) - _word(data, 0)
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
        {"address": receiver, "contract": bool(get_code(receiver))}
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


def is_value_moving(diff: AssetDiff) -> bool:
    """Whether the transaction spends, sends or grants anything of the sender's."""
    if int(diff["native"]) < 0:
        return True
    if any(int(entry["delta"]) < 0 for entry in diff["tokens"].values()):
        return True
    if any(int(entry["delta"]) < 0 for entry in diff["positions"]):
        return True
    return any(entry["amount"] != "0" for entry in diff["approvals"])


def parse_intent(raw: t.Any) -> tuple[Intent | None, list[Problem]]:
    """Validate a caller's intent; return it normalised, or a bad-intent problem."""
    if raw is None:
        return None, []
    if not isinstance(raw, dict):
        return None, [_bad("the intent must be an object")]
    unknown = sorted(set(raw) - {"spend", "receive_min", "recipients", "approvals"})
    if unknown:
        return None, [_bad(f"unknown intent keys {unknown}")]
    try:
        intent = Intent(
            spend=_amounts(raw.get("spend") or {}, "spend"),
            receive_min=_amounts(raw.get("receive_min") or {}, "receive_min"),
            recipients=[_address(a) for a in raw.get("recipients") or []],
            approvals=[_approval(a) for a in raw.get("approvals") or []],
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


def _amount(value: t.Any) -> int:
    if isinstance(value, bool):
        raise TypeError("an amount must be a whole number of base units")
    amount = int(value, 0) if isinstance(value, str) else int(value)
    if amount < 0:
        raise ValueError("an amount must be >= 0")
    return amount


def _amounts(raw: t.Any, where: str) -> dict[TokenKey, int]:
    if not isinstance(raw, dict):
        raise TypeError(f"intent '{where}' must be an object of token -> amount")
    return {_token(token): _amount(amount) for token, amount in raw.items()}


def _approval(raw: t.Any) -> IntentApproval:
    if not isinstance(raw, dict):
        raise TypeError("each intent approval must be {token, spender, amount}")
    return IntentApproval(
        token=_token(raw["token"]),
        spender=_address(raw["spender"]),
        amount=_amount(raw["amount"]),
    )


def check_intent(diff: AssetDiff, intent: Intent | None) -> list[Problem]:
    """Return every rule the simulated transaction breaks under `intent`."""
    problems: list[Problem] = []
    if not diff["ok"]:
        problems.append(Problem(rule="reverts", detail=f"reverts: {diff['revert']}"))
    if intent is None:
        if is_value_moving(diff):
            problems.append(
                Problem(
                    rule="missing-intent",
                    detail="this transaction moves value, so it needs an intent "
                    "(spend, receive_min, recipients, approvals)",
                )
            )
        return problems
    spend = intent.get("spend", {})
    deltas = {NATIVE: int(diff["native"])}
    deltas.update({token: int(e["delta"]) for token, e in diff["tokens"].items()})
    for token, delta in deltas.items():
        if delta < 0 and -delta > spend.get(token, 0):
            problems.append(
                Problem(
                    rule="overspend",
                    detail=f"spends {-delta} of {token}, more than the intent's "
                    f"{spend.get(token, 0)}",
                )
            )
    for token, least in intent.get("receive_min", {}).items():
        if deltas.get(token, 0) < least:
            problems.append(
                Problem(
                    rule="receive-min",
                    detail=f"receives {max(deltas.get(token, 0), 0)} of {token}, "
                    f"less than the intent's minimum {least}",
                )
            )
    allowed = set(intent.get("recipients", []))
    for entry in diff["recipients"]:
        if not entry["contract"] and entry["address"] not in allowed:
            problems.append(
                Problem(
                    rule="undeclared-recipient",
                    detail=f"sends to {entry['address']}, an account the intent's "
                    "recipients do not name",
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
                    detail=f"approves {entry['spender']} for {entry['amount']} of "
                    f"{entry['token']}, which the intent's approvals do not cover",
                )
            )
    return problems


def refusal_message(problems: list[Problem]) -> str:
    """Return the one-line refusal a session reads: every rule, each named."""
    return "refused by the intent gate: " + "; ".join(
        f"rule '{p['rule']}': {p['detail']}" for p in problems
    )
