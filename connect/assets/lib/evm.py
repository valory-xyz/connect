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

"""Chain access and primitives: the signer's web3, calls, decimals, ERC-20."""

import math
import re
import secrets
import sys
import time
import typing as t
from decimal import Decimal
from pathlib import Path

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3
from web3.exceptions import Web3Exception, Web3RPCError

_PEARL_SCRIPTS = (
    Path(__file__).resolve().parents[1] / "skills" / "pearl-connect" / "scripts"
)
sys.path.insert(0, str(_PEARL_SCRIPTS))
try:
    from signer_client import (  # noqa: E402  pylint: disable=wrong-import-position
        connect,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - install-shape guard
    if exc.name != "signer_client":
        raise
    raise ImportError(
        "the shared skill modules need the sibling pearl-connect skill; expected "
        f"signer_client.py under {_PEARL_SCRIPTS}"
    ) from exc


NATIVE = "0x0000000000000000000000000000000000000000"
NATIVE_DECIMALS = 18
RECEIPT_TIMEOUT_S = 300
RECEIPT_POLL_S = 2.0
MAX_SLIPPAGE = 5.0
DEFAULT_MAX_IMPACT_BPS = 500.0
MAX_IMPACT_CEILING_BPS = 2000.0
LOG_BACKOFF_CAP_S = 5.0
MULTICALL3 = to_checksum_address("0xcA11bde05977b3631167028862bE2a173976CA11")


class Call(t.TypedDict):
    """One call the safe makes, as the signer expects it."""

    to: str
    data: str
    what: str
    value: t.NotRequired[int]


class SwapError(RuntimeError):
    """A trade could not be quoted, built or verified."""


def selector(signature: str) -> bytes:
    """First four bytes of the keccak hash of a function signature."""
    return keccak(text=signature)[:4]


SEL_BALANCE_OF = selector("balanceOf(address)")
SEL_DECIMALS = selector("decimals()")
SEL_ERC20_APPROVE = selector("approve(address,uint256)")
SEL_WETH_DEPOSIT = selector("deposit()")
SEL_WETH_WITHDRAW = selector("withdraw(uint256)")
SEL_NAME = selector("name()")
SEL_SYMBOL = selector("symbol()")
SEL_AGGREGATE3 = selector("aggregate3((address,bool,bytes)[])")


def read_web3(chain: str, public_rpc: str) -> tuple[Web3, t.Optional[str]]:
    """Return a web3 for reads and the safe: the signer's, else ``public_rpc`` and None."""
    try:
        w3, signer = connect(chain)
        return w3, signer.chain_info(chain).get("safe")
    except (OSError, RuntimeError, KeyError, ValueError) as exc:
        print(
            f"NOTE: no pearl-connect signer here ({type(exc).__name__}: {exc}); "
            f"reading from {public_rpc}",
            file=sys.stderr,
        )
        w3 = Web3(Web3.HTTPProvider(public_rpc, request_kwargs={"timeout": 30}))
        return w3, None


def encode_call(sel: bytes, types: list[str], args: list[t.Any]) -> bytes:
    """Selector followed by ABI-encoded arguments."""
    return sel + abi_encode(types, args)


def abi_tuple(record: type[tuple[t.Any, ...]]) -> str:
    """Return a record's ABI tuple type, read from its field annotations."""
    hints = t.get_type_hints(record, include_extras=True)
    return "(" + ",".join(hints[name].__metadata__[0] for name in hints) + ")"


def parse_bytes32(text: t.Optional[str], flag: str) -> bytes:
    """Return the 32 bytes a flag gave as 0x-hex, or fresh random ones without it.

    Raises:
        SwapError: when the text is not 0x followed by 32 bytes of hex.
    """
    if text is None:
        return secrets.token_bytes(32)
    digits = text.removeprefix("0x")
    if not text.startswith("0x") or len(digits) != 64:
        raise SwapError(f"{flag} must be 0x and 64 hex digits, got {text!r}")
    try:
        return bytes.fromhex(digits)
    except ValueError as exc:
        raise SwapError(f"{flag} is not hex: {text!r}") from exc


def check_slippage(slippage: float) -> None:
    """Refuse a slippage percentage outside 0..MAX_SLIPPAGE.

    Raises:
        SwapError: when the slippage is out of range.
    """
    if not 0 <= slippage <= MAX_SLIPPAGE:
        raise SwapError(
            f"slippage of {slippage}% is outside 0..{MAX_SLIPPAGE}%; a floor "
            f"that loose is not slippage protection"
        )


def check_impact_limit(max_impact_bps: float) -> None:
    """Refuse a price-impact limit that would turn the protection off.

    Raises:
        SwapError: when the limit is outside 0..MAX_IMPACT_CEILING_BPS.
    """
    if not 0 < max_impact_bps <= MAX_IMPACT_CEILING_BPS:
        raise SwapError(
            f"a {max_impact_bps} bps price-impact limit is outside "
            f"0..{MAX_IMPACT_CEILING_BPS}"
        )


def apply_slippage(amount: int, slippage: float) -> int:
    """Return the floor a slippage percentage leaves of an amount, rounded down."""
    return int(amount * (1 - Decimal(str(slippage)) / 100))


def print_dry_run(calls: list[Call]) -> None:
    """Print one line per call a dry run would have sent."""
    for call in calls:
        print(
            f"dry-run {call['what']}: to={call['to']} "
            f"value={call.get('value') or 0} data={call['data'][:74]}..."
        )


def is_native(token: str) -> bool:
    """Whether this address stands for the chain's native coin."""
    return int(token, 16) == 0


def check_fields(kind: str, checks: dict[str, tuple[t.Any, t.Any]]) -> None:
    """Raise unless every decoded field is the one that was planned.

    Raises:
        SwapError: on the first field that disagrees.
    """
    for field, (got, want) in checks.items():
        if got != want:
            raise SwapError(f"{kind} {field} is {got!r}, expected {want!r}")


def call_int(w3: Web3, to: str, data: bytes) -> int:
    """One eth_call whose single return word is read as an unsigned integer.

    Raises:
        SwapError: when the call returns nothing; "the node said nothing" and
            "the contract said zero" are different answers.
    """
    raw = bytes(w3.eth.call({"to": to_checksum_address(to), "data": data}))
    if len(raw) < 32:
        raise SwapError(
            f"{to} returned {len(raw)} bytes, expected at least 32; it may not "
            f"be a contract here"
        )
    return int.from_bytes(raw[:32], "big")


def call_types(w3: Web3, to: str, data: bytes, types: list[str]) -> tuple:
    """One eth_call whose return data is ABI-decoded as ``types``.

    Raises:
        SwapError: when the call returns less than the types need or the return
            does not decode.
    """
    raw = bytes(w3.eth.call({"to": to_checksum_address(to), "data": data}))
    if len(raw) < 32 * len(types):
        raise SwapError(
            f"{to} returned {len(raw)} bytes, expected at least "
            f"{32 * len(types)}; it may not be a contract here"
        )
    try:
        return tuple(abi_decode(types, raw))
    except Exception as exc:  # pylint: disable=broad-except
        raise SwapError(f"{to} returned data that is not {types}: {exc}") from exc


def call_address(w3: Web3, to: str, data: bytes) -> t.Optional[str]:
    """One eth_call returning an address, or None when it answers the zero one."""
    value = call_int(w3, to, data)
    return to_checksum_address(f"0x{value:040x}") if value else None


def call_string(w3: Web3, to: str, data: bytes) -> str:
    """One eth_call whose return is an ABI string.

    Raises:
        SwapError: when the answer does not decode as a string.
    """
    value: str = call_types(w3, to, data, ["string"])[0]
    return value


def _decode_text(raw: bytes) -> t.Optional[str]:
    """Decode an ABI string or a legacy NUL-padded bytes32 one, else None."""
    try:
        text: str = abi_decode(["string"], raw)[0]
        return text
    except Exception:  # pylint: disable=broad-except
        if len(raw) != 32:
            return None
    try:
        return raw.rstrip(b"\0").decode()
    except UnicodeDecodeError:
        return None


def decode_string_result(ok: bool, raw: bytes, what: str) -> str:
    """Decode an aggregate3 string result; empty when it reverted or is unreadable."""
    text = _decode_text(raw) if ok else ""
    if text is None:
        print(f"NOTE: {what} did not decode; recorded as empty", file=sys.stderr)
        return ""
    return text


def multicall(
    w3: Web3, calls: list[tuple[str, bytes]]
) -> tuple[tuple[bool, bytes], ...]:
    """Make (target, calldata) calls through Multicall3, each allowed to fail.

    Raises:
        SwapError: when Multicall3 answers a different number of results.
    """
    batch = [(target, True, data) for target, data in calls]
    data = encode_call(SEL_AGGREGATE3, ["(address,bool,bytes)[]"], [batch])
    results: tuple[tuple[bool, bytes], ...] = call_types(
        w3, MULTICALL3, data, ["(bool,bytes)[]"]
    )[0]
    if len(results) != len(calls):
        raise SwapError(
            f"Multicall3 answered {len(results)} results for {len(calls)} calls"
        )
    return results


def describe_revert(data: t.Any, errors: t.Mapping[bytes, str]) -> str:
    """Name a revert from its data by selector, or return the data verbatim."""
    if not isinstance(data, str) or not data.startswith("0x"):
        return str(data)
    try:
        raw = bytes.fromhex(data[2:])
        signature = errors[raw[:4]]
        name, _, types = signature[:-1].partition("(")
        args = abi_decode(types.split(","), raw[4:]) if types else ()
    except Exception:  # pylint: disable=broad-except
        return data
    shown = ", ".join("0x" + a.hex() if isinstance(a, bytes) else str(a) for a in args)
    return f"{name}({shown})"


def simulate_calls(
    w3: Web3, calls: list[Call], sender: str, errors: t.Mapping[bytes, str]
) -> list[bytes]:
    """Dry-run calls in sequence as ``sender`` and return each one's raw return data.

    Raises:
        SwapError: when a call would revert, naming the error, or the calls
            cannot be simulated.
    """
    batch = [
        {
            "from": to_checksum_address(sender),
            "to": to_checksum_address(call["to"]),
            "data": call["data"],
            "value": hex(call.get("value", 0)),
        }
        for call in calls
    ]
    whats = ", ".join(call["what"] for call in calls)
    try:
        blocks = w3.manager.request_blocking(
            "eth_simulateV1", [{"blockStateCalls": [{"calls": batch}]}, "latest"]
        )
        results = [
            (int(r["status"], 16), r.get("error"), bytes.fromhex(r["returnData"][2:]))
            for r in blocks[0]["calls"]
        ]
    except Web3Exception as exc:
        raise SwapError(f"{whats} could not be simulated: {exc}") from exc
    except (LookupError, TypeError, ValueError) as exc:
        raise SwapError(f"the simulation of {whats} answered {exc!r}") from exc
    if len(results) != len(calls):
        raise SwapError(
            f"the simulation answered {len(results)} results for {len(calls)} calls"
        )
    for call, (status, error, _) in zip(calls, results):
        if status != 1:
            error = error or {}
            reason = describe_revert(error.get("data") or error.get("message"), errors)
            raise SwapError(f"{call['what']} would revert: {reason}")
    return [raw for _, _, raw in results]


def get_logs(
    w3: Web3, query: t.Any, hint: str, retries: int, pause: float
) -> list[t.Any]:
    """One eth_getLogs, pausing first and backing off (doubling, capped) if throttled.

    Raises:
        Web3RPCError: as the node raised it, so a caller can shrink the span.
        SwapError: when the RPC keeps throttling (ending with ``hint``) or
            fails outright.
    """
    for attempt in range(retries + 1):
        time.sleep(min(pause * 2**attempt, LOG_BACKOFF_CAP_S))
        try:
            return list(w3.eth.get_logs(query))
        except Web3RPCError:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            if getattr(getattr(exc, "response", None), "status_code", None) != 429:
                raise SwapError(f"the RPC failed a log query ({exc})") from exc
    raise SwapError(f"the RPC keeps throttling log queries; {hint}")


def scan_logs(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    fetch: t.Callable[[int, int], list[t.Any]],
    first: int,
    last: int,
    forward: bool,
    budget: list[int],
    on_chunk: t.Callable[[list[t.Any], int, int], None],
    chunk: int,
    min_chunk: int,
) -> None:
    """Fetch [first, last] in chunks, halving refused ones, each fetch spending budget.

    Raises:
        SwapError: when even a ``min_chunk`` span is refused.
    """
    while first <= last and budget[0] > 0:
        if forward:
            lo, hi = first, min(last, first + chunk - 1)
        else:
            lo, hi = max(first, last - chunk + 1), last
        budget[0] -= 1
        try:
            logs = fetch(lo, hi)
        except Web3RPCError as exc:
            if chunk <= min_chunk:
                raise SwapError(
                    f"the RPC refuses even {chunk}-block log queries ({exc})"
                ) from exc
            chunk //= 2
            continue
        on_chunk(logs, lo, hi)
        if forward:
            first = hi + 1
        else:
            last = lo - 1


def token_decimals(w3: Web3, token: str) -> int:
    """Decimals read from the token, never assumed.

    Raises:
        SwapError: when the token reports implausible decimals.
    """
    if is_native(token):
        return NATIVE_DECIMALS
    decimals = call_int(w3, token, SEL_DECIMALS)
    if not 0 < decimals <= 36:
        raise SwapError(f"{token} reports implausible decimals: {decimals}")
    return decimals


def token_identity(w3: Web3, token: str) -> tuple[str, str, int]:
    """Name, symbol and decimals read from the token itself."""
    return (
        call_string(w3, token, SEL_NAME),
        call_string(w3, token, SEL_SYMBOL),
        token_decimals(w3, token),
    )


def asset_info(w3: Web3, token: str) -> tuple[str, int]:
    """Symbol and decimals of an asset, native ETH included."""
    if is_native(token):
        return "ETH", token_decimals(w3, NATIVE)
    return call_string(w3, token, SEL_SYMBOL), token_decimals(w3, token)


def raw_balance_of(w3: Web3, token: str, holder: str) -> int:
    """Read a holder's token (or native coin) balance in base units."""
    if is_native(token):
        return int(w3.eth.get_balance(to_checksum_address(holder)))
    data = SEL_BALANCE_OF + abi_encode(["address"], [to_checksum_address(holder)])
    return call_int(w3, token, data)


def balance_of(w3: Web3, token: str, holder: str, decimals: int) -> float:
    """Read a holder's token (or native coin) balance in whole units."""
    return raw_balance_of(w3, token, holder) / 10**decimals


def erc20_approval_call(token: str, spender: str, amount: int, label: str) -> Call:
    """Exact-amount ERC-20 approval, as a call the safe can make."""
    data = SEL_ERC20_APPROVE + abi_encode(
        ["address", "uint256"], [to_checksum_address(spender), amount]
    )
    return {"to": token, "data": "0x" + data.hex(), "what": label}


def to_base_units(w3: Web3, token: str, whole: float) -> int:
    """Whole units to base units, with decimals read from the token.

    Decimal, not float: at eighteen decimals ``int(12345.6789 * 10**18)`` lands
    over a million wei above the number the caller typed.

    Raises:
        SwapError: when the amount is not a finite number.
    """
    if not math.isfinite(whole):
        raise SwapError(f"{whole} is not a finite amount")
    return int(Decimal(str(whole)) * 10 ** token_decimals(w3, token))


def weth_deposit_call(weth: str, amount: int) -> Call:
    """Wrap this much native coin into WETH."""
    return {
        "to": weth,
        "data": "0x" + SEL_WETH_DEPOSIT.hex(),
        "what": "wrap ETH",
        "value": amount,
    }


def weth_withdraw_call(weth: str, amount: int) -> Call:
    """Unwrap this much WETH back into native coin."""
    data = SEL_WETH_WITHDRAW + abi_encode(["uint256"], [amount])
    return {"to": weth, "data": "0x" + data.hex(), "what": "unwrap WETH"}


class Sent(t.NamedTuple):
    """A call that confirmed, with its hash and receipt."""

    what: str
    tx_hash: str
    receipt: t.Any


def summary(sent: list[Sent]) -> list[str]:
    """Name each confirmed call and its hash."""
    return [f"{s.what}: {s.tx_hash}" for s in sent]


class SendError(SwapError):
    """A send_calls failure: what landed, and whether the failed call surely did nothing."""

    def __init__(self, message: str, landed: list[Sent], inert: bool) -> None:
        """Keep what landed and whether the failing call is known to be inert."""
        super().__init__(message, landed, inert)
        self.landed = landed
        self.inert = inert

    def __str__(self) -> str:
        """Return the message alone."""
        return str(self.args[0])


MAY_HAVE_BROADCAST = "It may still have broadcast - check before resending."
REFUSED_BEFORE_SIGNING = "The signer refused it before signing; nothing was broadcast."
REVERTED_BEFORE_SIGNING = (
    "It reverted in simulation before signing; nothing was broadcast."
)
# /safe-transaction refusals raised before signing; pinned to the server by a test.
SIGNER_REFUSALS: dict[int, tuple[str, ...]] = {
    400: (
        "unknown chain '",
        "no service safe is configured for chain '",
        "cannot compose the safe call: ",
        "the safe may not call itself ",
        "the operator's guardrail settings do not allow the safe to call ",
        "the guardrail only allows approve(spender=",
    ),
    401: ("invalid or missing bearer token",),
    403: ("cross-origin requests are not allowed",),
    429: ("too many failed authentication attempts",),
}
SIGNER_SIMULATION_REVERT = re.compile(r"send failed: .*execution reverted", re.DOTALL)


def send_outcome(exc: Exception) -> str:
    """Say whether a failed send can have broadcast, from the signer's answer."""
    answer = re.fullmatch(r"signer returned HTTP (\d+): (.*)", str(exc), re.DOTALL)
    if answer is None:
        return MAY_HAVE_BROADCAST
    status, detail = int(answer.group(1)), answer.group(2)
    if detail.startswith(SIGNER_REFUSALS.get(status, ())):
        return REFUSED_BEFORE_SIGNING
    if status == 400 and SIGNER_SIMULATION_REVERT.match(detail):
        return REVERTED_BEFORE_SIGNING
    return MAY_HAVE_BROADCAST


def send_calls(w3: Web3, signer: t.Any, calls: list[Call]) -> list[Sent]:
    """Send each call and confirm it before sending the next.

    A reverted approval makes the swap behind it impossible, and a reverted
    swap looks exactly like a successful one in a tx hash alone.

    Raises:
        SendError: when a call reverts or does not confirm, naming what landed.
    """
    landed: list[Sent] = []
    for call in calls:
        try:
            tx_hash = signer.send_transaction(dict(call))
        except Exception as exc:  # pylint: disable=broad-except
            outcome = send_outcome(exc)
            raise SendError(
                f"{call['what']} could not be sent ({exc}); confirmed so far: "
                f"{summary(landed)}. {outcome}",
                landed,
                inert=outcome != MAY_HAVE_BROADCAST,
            ) from exc
        try:
            receipt = w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=RECEIPT_TIMEOUT_S, poll_latency=RECEIPT_POLL_S
            )
        except Exception as exc:  # pylint: disable=broad-except
            raise SendError(
                f"{call['what']} ({tx_hash}) has not confirmed within "
                f"{RECEIPT_TIMEOUT_S}s ({exc}); its fate is unknown and it may "
                f"still land, so check that hash before resending anything. "
                f"Confirmed so far: {summary(landed)}",
                landed,
                inert=False,
            ) from exc
        if receipt["status"] != 1:
            raise SendError(
                f"{call['what']} ({tx_hash}) reverted; confirmed so far: {summary(landed)}",
                landed,
                inert=True,
            )
        print(f"{call['what']}: {tx_hash}")
        landed.append(Sent(call["what"], tx_hash, receipt))
    return landed


__all__ = [
    "Call",
    "DEFAULT_MAX_IMPACT_BPS",
    "LOG_BACKOFF_CAP_S",
    "MAX_IMPACT_CEILING_BPS",
    "MULTICALL3",
    "NATIVE",
    "RECEIPT_POLL_S",
    "RECEIPT_TIMEOUT_S",
    "Sent",
    "SEL_AGGREGATE3",
    "SEL_NAME",
    "SEL_SYMBOL",
    "SendError",
    "SwapError",
    "abi_tuple",
    "apply_slippage",
    "asset_info",
    "check_fields",
    "check_impact_limit",
    "balance_of",
    "call_address",
    "call_int",
    "call_string",
    "call_types",
    "connect",
    "decode_string_result",
    "describe_revert",
    "encode_call",
    "erc20_approval_call",
    "get_logs",
    "is_native",
    "multicall",
    "parse_bytes32",
    "raw_balance_of",
    "read_web3",
    "scan_logs",
    "selector",
    "send_calls",
    "send_outcome",
    "simulate_calls",
    "summary",
    "to_base_units",
    "token_decimals",
    "token_identity",
    "weth_deposit_call",
    "weth_withdraw_call",
]
