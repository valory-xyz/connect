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
from mech_client.services.marketplace_service import MarketplaceService

from connect.mech_types import MechError, PricedMech, said

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
