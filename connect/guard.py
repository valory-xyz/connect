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
HTTP signing endpoints all funnel into the same checks.

Two of those checks hold in *every* mode. The safe may never delegatecall, and
the safe may never call itself. Both are how a Safe changes what it is —
enableModule, addOwnerWithThreshold, setGuard, or arbitrary code run against
its own storage — and what they install goes on moving funds after this signer
stops signing: on-chain, directly, forever. They would outlive a switch back to
restricted mode, which is the one thing an operator flipping that switch is
relying on. For the safe's own configuration, unrestricted is meant to be a
wider gate, not a one-way door.

That guarantee is scoped to the safe itself. State granted on *other*
contracts while unrestricted — an ERC-20 allowance above all — persists until
explicitly revoked, and an unlimited approve lets its spender drain the safe
with no further signing. The floor cannot see allowances; revoking them is
part of flipping the switch back, not a consequence of it.

Everything else is the mode. In restricted mode the agent EOA may only have the
safe CALL a whitelisted address via execTransaction, and raw digest signing is
disabled: a digest is an opaque hash this gate cannot inspect, and the EOA
owns the safe at threshold 1, so an attacker-chosen digest could be the hash
of a safe transaction — one signature over it and the whitelist is bypassed.
The exceptions are allowances the server registers for itself, and the agent
session can register neither. For signing, the mech flow recomputes the
off-chain request id from inputs it already validated, wraps it into the
safe's ERC-1271 SafeMessage hash, and registers exactly that digest
(allow_digest_once) before mech-client asks for the signature.
For transactions, the same flow may pre-authorize the one deposit its 402
top-up would send — the safe paying the mech balance tracker
(allow_safe_deposit_once), shape-checked (a bare native transfer, or
deposit(uint256) with no inner value) and bounded by an amount cap. Every
allowance is single-use and short-lived. A live allowance is a bounded grant,
not a promise about the caller: any matching request may consume it — for the
deposit that means the agent could send the tracker payment itself, moving at
most the cap into a balance the mech flow spends — which is accepted and
audited, not prevented. A dry run (consume=False) makes that window and its
cap observable rather than only guessable, which widens the odds of hitting
it, not the grant itself.

The modes are an operator concept, not an agent one: every agent-facing
refusal names the rule it violated and where the operator can change it, but
never that a mode system exists — the agent is deliberately not told there is
anything to switch.
"""

import logging
import threading
import time
from dataclasses import dataclass

from eth_abi import decode as abi_decode

from connect.config import AppConfig
from connect.safe import (
    EXEC_TRANSACTION_SELECTOR,
    EXEC_TRANSACTION_TYPES,
    OPERATION_CALL,
    ZERO_ADDRESS,
    decode_approve,
    decode_deposit,
)
from connect.settings import MODE_RESTRICTED, SettingsStore, token_approve_targets

logger = logging.getLogger("agent")


class GuardError(Exception):
    """A transaction or signing request denied by the guardrail."""


# The escalation clause every operator-changeable refusal ends with; one
# literal so the two call sites cannot drift apart.
_ASK_OPERATOR = "ask the operator to change them via the agent UI if it is required"

# How long a registered allowance stays consumable. Arming must happen before
# the request leaves: mech-client swallows the 402 -> deposit -> retry cycle
# internally, so the guard cannot arm on the 402 itself. Between arm and
# deposit sit an IPFS metadata pin, the mech's HTTP round trip and the
# deposit's own compose-and-sign — 90s covers that worst case; past it, only
# an entry from a flow that failed in between stays live, and dies here.
ALLOWANCE_TTL = 90.0


@dataclass(frozen=True)
class _DepositAllowance:
    """One pre-authorized safe -> balance-tracker payment, capped and typed.

    `is_token` picks the shape: a `deposit(uint256 amount)` call with no
    inner value (amount capped), or a bare native transfer (inner value
    capped).
    """

    chain: str
    tracker: str  # lowercase
    is_token: bool
    amount_cap: int
    expires: float


@dataclass(frozen=True)
class _SafeExec:
    """The execTransaction fields this gate has an opinion about."""

    to: str
    value: int
    data: str
    operation: int
    gas_price: int
    gas_token: str
    refund_receiver: str

    @classmethod
    def decode(cls, calldata: str) -> "_SafeExec":
        """Read an execTransaction, or :raises GuardError: if it will not read.

        Calldata we cannot parse is calldata we cannot judge, so it is refused
        rather than waved through — mech-client's transactions arrive here too,
        and the agent can still hand-roll its own.
        """
        try:
            decoded = tuple(
                abi_decode(EXEC_TRANSACTION_TYPES, bytes.fromhex(calldata[8:]))
            )
        except Exception as e:
            raise GuardError(f"could not decode execTransaction calldata: {e}") from e
        return cls(
            to=str(decoded[0]),
            value=int(decoded[1]),
            data="0x" + decoded[2].hex(),
            operation=decoded[3],
            gas_price=decoded[6],
            gas_token=str(decoded[7]),
            refund_receiver=str(decoded[8]),
        )


class Guard:
    """Mode/whitelist enforcement backed by the tamper-evident settings store."""

    def __init__(self, store: SettingsStore, config: AppConfig) -> None:
        """Initialize."""
        self._store = store
        self._config = config
        self._allowance_lock = threading.Lock()
        # digest -> monotonic expiry; entries are consumed by check_sign_digest
        self._allowed_digests: dict[bytes, float] = {}
        # pre-authorized deposits; entries are consumed by check_transaction
        self._deposit_allowances: list[_DepositAllowance] = []

    def mode(self) -> str:
        """Return the currently enforced mode."""
        return self._store.load().protected.mode

    def allow_digest_once(self, digest: bytes) -> None:
        """Permit one restricted-mode signature over a server-derived digest.

        Server-side callers only (the mech flow): no MCP tool or HTTP route
        reaches this, so the agent session cannot launder an arbitrary hash
        into an allowance. The caller vouches that it computed the digest
        itself from validated inputs — see the module docstring for why that
        is the entire security argument.
        """
        with self._allowance_lock:
            self._purge_expired()
            self._allowed_digests[bytes(digest)] = time.monotonic() + ALLOWANCE_TTL

    def allow_safe_deposit_once(
        self, *, chain: str, tracker: str, amount_cap: int, is_token: bool
    ) -> None:
        """Permit one restricted-mode safe payment to a mech balance tracker.

        Server-side callers only (the mech flow, arming a request's possible
        402 top-up). The tracker address comes from the pinned mech-client's
        own constants and the cap from the same bound mech-client enforces on
        the deposit it would send, so the allowance never widens what the
        flow could already do — it only lets the guard recognize it.
        """
        with self._allowance_lock:
            self._purge_expired()
            self._deposit_allowances = [
                a
                for a in self._deposit_allowances
                if (a.chain, a.tracker) != (chain.lower(), tracker.lower())
            ]
            self._deposit_allowances.append(
                _DepositAllowance(
                    chain=chain.lower(),
                    tracker=tracker.lower(),
                    is_token=is_token,
                    amount_cap=amount_cap,
                    expires=time.monotonic() + ALLOWANCE_TTL,
                )
            )

    def _purge_expired(self) -> None:
        """Drop expired allowances — loudly; the caller holds the allowance lock.

        An allowance that dies unconsumed means a flow failed between arm
        and use, and the next matching request is refused with the generic
        policy message — these log lines are what tell the two apart.
        """
        now = time.monotonic()
        for digest, expiry in list(self._allowed_digests.items()):
            if expiry <= now:
                logger.warning("digest allowance 0x%s expired unconsumed", digest.hex())
                del self._allowed_digests[digest]
        for allowance in self._deposit_allowances:
            if allowance.expires <= now:
                logger.warning(
                    "deposit allowance for tracker %s on %s expired unconsumed",
                    allowance.tracker,
                    allowance.chain,
                )
        self._deposit_allowances = [
            a for a in self._deposit_allowances if a.expires > now
        ]

    def check_sign_digest(self, digest: bytes) -> None:
        """Raise unless this digest may be signed; consumes its allowance.

        Unrestricted mode signs anything. Restricted mode signs only a digest
        previously registered via allow_digest_once, exactly once — the pop
        makes a replayed request for the same signature a refusal, not a
        second signature.
        """
        if self._store.load().protected.mode != MODE_RESTRICTED:
            return
        with self._allowance_lock:
            self._purge_expired()
            if self._allowed_digests.pop(bytes(digest), None) is not None:
                return
        raise GuardError(
            "raw digest signing is disabled by the operator's guardrail "
            f"settings; {_ASK_OPERATOR}"
        )

    def check_transaction(
        self, chain: str, to: str, value: int, data: str, *, consume: bool = True
    ) -> None:
        """Raise unless the EOA transaction is allowed.

        The floor is checked first and holds in every mode; the rest is the
        mode. Decoding happens once, here, so both answer the same bytes.
        `consume=False` answers without spending a single-use allowance, so
        asking whether a call would pass cannot break the call that follows.
        """
        chain = chain.lower()
        safe = self._config.chain(chain).safe_address
        calldata = (data or "0x").removeprefix("0x").lower()
        exec_call = None
        if calldata.startswith(EXEC_TRANSACTION_SELECTOR):
            # decode and floor-check every execTransaction, whatever it targets
            # and whether or not a safe is configured here: the floor protects
            # any safe the agent reaches, and "protected only if configured"
            # would be a hole an unconfigured chain walks straight through.
            exec_call = _SafeExec.decode(calldata)
            self._check_floor(to, exec_call)
        if self._store.load().protected.mode == MODE_RESTRICTED:
            self._check_restricted(
                chain,
                safe=safe,
                to=to,
                value=value,
                calldata=calldata,
                exec_call=exec_call,
                consume=consume,
            )

    def _check_floor(self, target: str, exec_call: "_SafeExec") -> None:
        """Enforce the two rules no mode lifts; see the module docstring for why.

        `target` is the contract the execTransaction is sent to — the safe
        whose call this is. A safe calling itself is how it changes its own
        owners, modules or guard.
        """
        if exec_call.operation != OPERATION_CALL:
            raise GuardError(
                "the safe may not delegatecall (got operation="
                f"{exec_call.operation}) — the guardrail never allows it"
            )
        if exec_call.to.lower() == target.lower():
            raise GuardError(
                "the safe may not call itself (owner, module and guard changes "
                "are made that way) — the guardrail never allows it"
            )

    def _check_restricted(  # pylint: disable=too-many-arguments
        self,
        chain: str,
        *,
        safe: str | None,
        to: str,
        value: int,
        calldata: str,
        exec_call: "_SafeExec | None",
        consume: bool,
    ) -> None:
        """Restricted mode: the safe CALLs a whitelisted address, or nothing."""
        if safe is None:
            raise GuardError(
                f"the operator's guardrail settings allow no transactions on "
                f"chain '{chain}' (no service safe is configured there)"
            )
        if to.lower() != safe.lower():
            raise GuardError(
                f"the operator's guardrail settings only allow transactions "
                f"targeting the service safe {safe}, not {to}"
            )
        if exec_call is None:
            raise GuardError(
                "the guardrail requires calls to the safe to be execTransaction "
                f"(selector 0x{EXEC_TRANSACTION_SELECTOR}), got 0x{calldata[:8]}"
            )
        if value != 0:
            raise GuardError(
                "the guardrail forbids native value on the outer transaction "
                "of an execTransaction call"
            )
        # A non-zero gasPrice makes the safe pay a refund (in gasToken, to
        # refundReceiver or tx.origin) — funds leaving the safe past the
        # whitelist. The standard flow always zeroes all three fields.
        if (
            exec_call.gas_price != 0
            or exec_call.gas_token.lower() != ZERO_ADDRESS
            or exec_call.refund_receiver.lower() != ZERO_ADDRESS
        ):
            raise GuardError(
                "the guardrail requires execTransaction refund fields to be "
                "zero (gasPrice=0, gasToken=0x0, refundReceiver=0x0) — a gas "
                "refund would pay out of the safe past the allowed targets"
            )
        tracker = token_approve_targets(chain).get(exec_call.to.lower())
        if tracker is not None:
            # a mech payment token: the safe may only approve it for the tracker,
            # never transfer or anything else (an address-level whitelist entry
            # would allow those; a token-paid mech needs just this approve)
            spender = decode_approve(exec_call.data)
            if spender is None or spender.lower() != tracker:
                raise GuardError(
                    f"the guardrail only allows approve(spender={tracker}) on "
                    f"the payment token {exec_call.to}"
                )
            return
        whitelist = self._store.load().protected.whitelist
        if exec_call.to.lower() not in whitelist.get(chain, ()):
            if self._consume_deposit_allowance(chain, exec_call, consume=consume):
                return
            # the whitelist is not editable through the API yet, so pointing at
            # it would send the operator down a path that does not exist
            raise GuardError(
                f"the operator's guardrail settings do not allow the safe to "
                f"call {exec_call.to} on {chain}; {_ASK_OPERATOR}"
            )

    def _consume_deposit_allowance(
        self, chain: str, exec_call: "_SafeExec", *, consume: bool
    ) -> bool:
        """Consume a deposit allowance this safe call matches, if any.

        A non-matching call consumes nothing: an over-cap or wrong-shape
        transaction is refused while the allowance stays live for the
        compliant deposit the flow will actually send.
        """
        with self._allowance_lock:
            self._purge_expired()
            for index, allowance in enumerate(self._deposit_allowances):
                if allowance.chain != chain:
                    continue
                if allowance.tracker != exec_call.to.lower():
                    continue
                if allowance.is_token:
                    amount = decode_deposit(exec_call.data)
                    matches = (
                        amount is not None
                        and amount <= allowance.amount_cap
                        and exec_call.value == 0
                    )
                else:
                    matches = (
                        exec_call.data == "0x"
                        and exec_call.value <= allowance.amount_cap
                    )
                if matches:
                    if consume:
                        del self._deposit_allowances[index]
                    return True
        return False
