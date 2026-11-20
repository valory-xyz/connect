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


"""`InputError`, and the reference's checks of an address, amount or hex argument.

`InputError` is a `ValueError`, so existing callers that catch one keep
working, and its own class, so the MCP call boundary can tell Connect's words
from a library's. The checks are OnchainBench's `check_args`, in its order, so
a malformed argument is refused where, and in the words, the reference does.
"""

import re
import typing as t

from connect.texts import ADDRESS_INVALID, AMOUNT_INEXACT, HEX_INVALID

# the largest integer a JSON number carries exactly (an IEEE-754 double's):
# 2^53 + 1 is the first a double cannot hold, and it rounds to 2^53
MAX_EXACT_JSON_INT = 2**53 - 1

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}", re.ASCII)
# the reference's hex rule, for every tool argument; the intent gate's
# `intent.calldata_problem` also reads a `0X` prefix, since it checks HTTP
# routes and the server's own calls, which the reference has no part in
_HEX = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2})*", re.ASCII)
_TX_HASH = re.compile(r"(?:0x)?[0-9a-fA-F]{64}", re.ASCII)


# every tool's address, hex and amount arguments, as the reference's `check_args`
# names them
ADDRESS_ARGUMENTS = ("target", "to", "address", "priority_mech")
HEX_ARGUMENTS = ("data", "digest")
# the amounts a JSON number may already have rounded; a cap is never spent, so
# `max_payment` takes an integer of any size and only a float is inexact
AMOUNT_ARGUMENTS = ("value", "max_payment")


class InputError(ValueError):
    """A caller's input refused by Connect, with a message meant for that caller."""


def checked_address(field: str, value: object) -> str:
    """Return `value` if it is 0x and 40 hex digits; else refuse it, naming `field`."""
    if not (isinstance(value, str) and _ADDRESS.fullmatch(value)):
        raise InputError(ADDRESS_INVALID(field, value))
    return value


def is_tx_hash(value: str) -> bool:
    """Whether `value` is a 32-byte transaction hash, 0x optional, nothing else."""
    return _TX_HASH.fullmatch(value) is not None


def checked_hex(field: str, value: object) -> str:
    """Return `value` as 0x-prefixed whole-byte hex; else refuse it, naming `field`."""
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise InputError(HEX_INVALID(field, value))
    return "0x" + value.removeprefix("0x")


def check_arguments(arguments: t.Mapping[str, t.Any]) -> None:
    """Refuse a malformed address, amount or hex argument, naming it, as the reference does.

    Run on a call's arguments as sent, in the reference's order (addresses,
    then amounts, then hex), by `ConnectMCP.check_call`.

    :raises InputError: the first malformed argument, in the reference's words.
    """
    for name in ADDRESS_ARGUMENTS:
        if arguments.get(name) not in (None, ""):
            checked_address(name, arguments[name])
    for name in AMOUNT_ARGUMENTS:
        if _inexact(arguments.get(name), spent=name == "value"):
            raise InputError(AMOUNT_INEXACT(arguments[name]))
    for name in HEX_ARGUMENTS:
        if arguments.get(name) not in (None, ""):
            checked_hex(name, arguments[name])


def _inexact(value: object, *, spent: bool) -> bool:
    """Whether a JSON number cannot carry this amount exactly.

    A float, or an integer past 2^53 - 1 where the amount is spent.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return True
    return spent and isinstance(value, int) and value > MAX_EXACT_JSON_INT
