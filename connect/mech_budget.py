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

"""What a mech request may pay by default, and in which token it pays."""

from mech_client.infrastructure.config.contract_addresses import (
    CHAIN_TO_PRICE_TOKEN_OLAS,
    CHAIN_TO_PRICE_TOKEN_USDC,
)
from mech_client.infrastructure.config.payment_config import PaymentType
from mech_client.utils.constants import CHAIN_NAME_TO_ID

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
PAYMENT_TOKENS = {
    PaymentType.OLAS_TOKEN: CHAIN_TO_PRICE_TOKEN_OLAS,
    PaymentType.USDC_TOKEN: CHAIN_TO_PRICE_TOKEN_USDC,
    PaymentType.TOKEN_NVM_USDC: CHAIN_TO_PRICE_TOKEN_USDC,
}


def payment_token(payment_type: PaymentType, chain: str) -> str:
    """Name the token a mech is paid in on a chain: "native", an address, or ""."""
    if payment_type not in PAYMENT_TOKENS:
        return "native"
    chain_id = CHAIN_NAME_TO_ID.get(chain)
    return PAYMENT_TOKENS[payment_type].get(chain_id, "") if chain_id else ""


def payment_report(payment_type_value: str, chain: str) -> dict[str, str]:
    """Report the token a mech is paid in and the budget a request defaults to."""
    kind = PaymentType(payment_type_value)
    report = {"payment_token": payment_token(kind, chain)}
    if kind in DEFAULT_MAX_PAYMENT:
        report["default_max_payment"] = str(DEFAULT_MAX_PAYMENT[kind])
    return report
