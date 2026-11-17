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


"""`InputError`, and the reference's checks of an address or hex argument.

`InputError` is a `ValueError`, so existing callers that catch one keep
working, and its own class, so the MCP call boundary can tell Connect's words
from a library's. The two checks are OnchainBench's `check_args` patterns, so
a malformed argument is refused where, and in the words, the reference does.
"""

import re

from connect.texts import ADDRESS_INVALID, HEX_INVALID

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}", re.ASCII)
# the reference's hex rule, for every tool argument; the intent gate's
# `intent.calldata_problem` also reads a `0X` prefix, since it checks HTTP
# routes and the server's own calls, which the reference has no part in
_HEX = re.compile(r"(?:0x)?(?:[0-9a-fA-F]{2})*", re.ASCII)
_TX_HASH = re.compile(r"(?:0x)?[0-9a-fA-F]{64}", re.ASCII)


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
