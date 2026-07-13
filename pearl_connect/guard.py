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

"""The transaction guardrail — one gate for every signing path.

There is deliberately no bypass: the mech request flow, the MCP tools and the
HTTP signing endpoints all funnel into the same two checks. In restricted mode
the agent EOA may only (a) sweep native funds into its own service safe or
(b) have the safe CALL a whitelisted address via execTransaction; raw digest
signing is disabled entirely (which also rules out off-chain mech requests —
their request-id digest is an opaque hash this gate cannot inspect).
"""

from eth_abi import decode as abi_decode

from pearl_connect.config import AppConfig
from pearl_connect.settings import MODE_RESTRICTED, SettingsStore

# Safe v1.x execTransaction(address,uint256,bytes,uint8,uint256,uint256,
#                           uint256,address,address,bytes)
EXEC_TRANSACTION_SELECTOR = "6a761202"
_EXEC_TRANSACTION_TYPES = [
    "address",  # to
    "uint256",  # value
    "bytes",  # data
    "uint8",  # operation (0 = CALL, 1 = DELEGATECALL)
    "uint256",  # safeTxGas
    "uint256",  # baseGas
    "uint256",  # gasPrice
    "address",  # gasToken
    "address",  # refundReceiver
    "bytes",  # signatures
]
_OPERATION_CALL = 0
_ZERO_ADDRESS = "0x" + "00" * 20


class GuardError(Exception):
    """A transaction or signing request denied by the guardrail."""


class Guard:
    """Mode/whitelist enforcement backed by the tamper-evident settings store."""

    def __init__(self, store: SettingsStore, config: AppConfig) -> None:
        """Initialize."""
        self._store = store
        self._config = config

    def mode(self) -> str:
        """Return the currently enforced mode."""
        return self._store.load().protected.mode

    def check_sign_digest(self) -> None:
        """Raise unless raw digest signing is allowed in the current mode."""
        if self._store.load().protected.mode == MODE_RESTRICTED:
            raise GuardError(
                "raw digest signing is disabled in restricted mode; ask the "
                "operator to switch modes via the agent UI if it is required"
            )

    def check_transaction(self, chain: str, to: str, value: int, data: str) -> None:
        """Raise unless the EOA transaction is allowed in the current mode."""
        settings = self._store.load()
        if settings.protected.mode != MODE_RESTRICTED:
            return
        chain = chain.lower()
        safe = self._config.chain(chain).safe_address
        if safe is None:
            raise GuardError(
                f"restricted mode: no service safe is configured for chain "
                f"'{chain}', so no transaction is allowed there"
            )
        if to.lower() != safe.lower():
            raise GuardError(
                f"restricted mode: transactions may only target the service "
                f"safe {safe}, not {to}"
            )
        calldata = (data or "0x").removeprefix("0x").lower()
        if not calldata:
            return  # plain native sweep into the safe
        self._check_safe_exec(chain, settings.protected.whitelist, value, calldata)

    def _check_safe_exec(
        self,
        chain: str,
        whitelist: dict[str, tuple[str, ...]],
        value: int,
        calldata: str,
    ) -> None:
        if not calldata.startswith(EXEC_TRANSACTION_SELECTOR):
            raise GuardError(
                "restricted mode: calls to the safe must be execTransaction "
                f"(selector 0x{EXEC_TRANSACTION_SELECTOR}), got 0x{calldata[:8]}"
            )
        if value != 0:
            raise GuardError(
                "restricted mode: execTransaction calls must not carry native "
                "value on the outer transaction"
            )
        try:
            decoded = tuple(
                abi_decode(_EXEC_TRANSACTION_TYPES, bytes.fromhex(calldata[8:]))
            )
        except Exception as e:
            raise GuardError(
                f"restricted mode: could not decode execTransaction calldata: {e}"
            ) from e
        inner_to, operation = str(decoded[0]), decoded[3]
        gas_price, gas_token, refund_receiver = (
            decoded[6],
            str(decoded[7]),
            str(decoded[8]),
        )
        if operation != _OPERATION_CALL:
            raise GuardError(
                "restricted mode: only CALL operations are allowed from the "
                f"safe (got operation={operation})"
            )
        # A non-zero gasPrice makes the safe pay a refund (in gasToken, to
        # refundReceiver or tx.origin) — funds leaving the safe past the
        # whitelist. The standard flow always zeroes all three fields.
        if (
            gas_price != 0
            or gas_token.lower() != _ZERO_ADDRESS
            or refund_receiver.lower() != _ZERO_ADDRESS
        ):
            raise GuardError(
                "restricted mode: execTransaction refund fields must be zero "
                "(gasPrice=0, gasToken=0x0, refundReceiver=0x0) — a gas refund "
                "would pay out of the safe outside the whitelist"
            )
        if inner_to.lower() not in whitelist.get(chain, ()):
            # the whitelist is not editable through the API yet, so pointing at
            # it would send the operator down a path that does not exist
            raise GuardError(
                f"restricted mode: {inner_to} is not in the {chain} whitelist; "
                "ask the operator to switch to unrestricted mode via the agent "
                "UI if it is required"
            )
