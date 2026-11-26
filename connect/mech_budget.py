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

"""What a mech request may pay by default, and the token report beside it."""

import typing as t

from mech_client import payment_token
from mech_client.infrastructure.config.payment_config import PaymentType
from mech_client.services.marketplace_service import (
    MAX_DERIVED_CAP_FACTOR,
    MarketplaceService,
    UINT256_MAX,
)

from connect.mech_types import MechError, MechNotSent, PricedMech, said

# The agent's per-request spending budget, not a guardrail: the caller picks
# max_payment per call and the server does not clamp it — the guardrail only
# checks *where* payments go. A mech pricing above the budget is refused
# before payment, and the accepted price is audited on success. Denominated
# in the mech's payment asset base units; the default is 0.1 of a whole unit
# of that asset, so it depends on the asset's decimals (USDC and Robinhood's
# USDG have 6).
DEFAULT_MAX_PAYMENT = {
    PaymentType.NATIVE: 10**17,
    PaymentType.NATIVE_NVM: 10**17,
    PaymentType.OLAS_TOKEN: 10**17,
    PaymentType.USDC_TOKEN: 10**5,
    PaymentType.TOKEN_NVM_USDC: 10**5,
}


def _payment_token(payment_type: PaymentType, chain: str) -> str | None:
    """Name the token a mech is paid in: "native", mech-client's address, or None.

    None when mech-client knows no such token on the chain, or not the chain.
    """
    if not payment_type.is_token():
        return "native"
    try:
        return payment_token(payment_type, chain)
    except ValueError:
        return None


def price_mech(service: MarketplaceService, chain: str, mech: str) -> PricedMech:
    """Read the mech a request will pay: its service id and per-request price.

    The service id comes back with it because every later check —
    reachability, metadata — is keyed by service rather than by mech address.
    Named rather than a bare tuple because two of the three fields are ints
    of wholly different kinds: transposing a service id and a wei price would
    corrupt the `max_payment` cap silently, and no type checker would object.
    """
    try:
        info = service.mech_info(mech)
    except Exception as e:
        what = f"could not price mech {mech}"
        raise MechError(f"{what}: {said(e, f'{what} on {chain}')}") from e
    return PricedMech(
        mech=mech,
        service_id=int(info.service_id),
        rate=int(info.max_delivery_rate),
        payment_type=str(info.payment_type.value),
    )


def offchain_priced(
    service: MarketplaceService, priced: PricedMech, tool: str, document: t.Any
) -> PricedMech:
    """Return `priced` at the cap mech-client signs for an off-chain `tool`.

    :raises MechNotSent: for a derived cap mech-client signs only with an
        explicit `max_cost`. Connect has no such override yet, so a mech
        pricing a tool that far above its on-chain price cannot be used
        through Connect; that is intended for now.
    """
    kind = PaymentType(priced.payment_type)

    def cap(advertised_max: int) -> int:
        return service._resolve_signed_rate(  # pylint: disable=protected-access
            tools=(tool,),
            metadata=document,
            payment_type=kind,
            advertised_max=advertised_max,
            max_cost=None,
            use_offchain=True,
        )

    try:
        return priced._replace(rate=cap(priced.rate))
    except ValueError as e:
        derived = cap(UINT256_MAX)  # the same cap, with no limit to refuse it
        raise MechNotSent(
            f"mech {priced.mech} prices {tool} at a cap of {derived}, more than "
            f"{MAX_DERIVED_CAP_FACTOR}x its on-chain price of {priced.rate}; "
            "this server does not sign a cap that far above it, so the tool "
            "cannot be requested here"
        ) from e


def payment_report(payment_type: PaymentType, chain: str) -> dict[str, t.Any]:
    """Report the token a mech is paid in and the budget a request defaults to."""
    default = DEFAULT_MAX_PAYMENT.get(payment_type)
    return {
        "payment_token": _payment_token(payment_type, chain),
        "default_max_payment": None if default is None else str(default),
    }


def charged(terms: dict, rate: int, result: dict) -> dict:
    """Return the fields a request's answer carries about the mech and its charge.

    `terms` is mech-client's mech report (or the terms alone). It labels the
    mech's payment asset under `payment`; in the answer that key is the charge
    the request accepted, `rate` for each request id the mech took, in base
    units of the asset (settlement charges at most this), so the label moves
    to `payment_info`.
    """
    fields = dict(terms)
    if "payment" in fields:
        fields["payment_info"] = fields.pop("payment")
    fields["payment"] = rate * len(result.get("request_ids") or [])
    return fields


def settle_payment(payload: dict, rate: int) -> None:
    """Report as `payment` what the mech said it charged, the signed cap as `signed_cap`.

    A request id the mech reported no charge for (`reported_charges`) still
    counts at `rate`, the most it can be charged.
    """
    ids = payload.get("request_ids") or []
    charges = payload.get("reported_charges") or {}
    payload["signed_cap"] = rate * len(ids)
    payload["payment"] = sum(int(charges.get(key, rate)) for key in ids)


def result_charge(report: dict, outcomes: dict, key: str) -> None:
    """Add a delivery's outcomes to a `mech_result` report, its charge as `payment`."""
    report.update(outcomes)
    if key in outcomes.get("reported_charges", {}):
        report["payment"] = int(outcomes["reported_charges"][key])
