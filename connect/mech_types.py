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

"""The vocabulary the mech flow's modules share.

`mech.py` drives the flow and `mech_allowances.py` pre-authorizes what it will
sign; both raise the same error and speak about the same priced mech, so these
live here rather than in either one — importing them from `mech.py` would make
the pair circular. Nothing here has behavior; it is names and shapes only.

`from connect.mech import MechError` keeps working: `mech.py` imports these,
so they remain attributes of that module for every existing caller.
"""

import typing as t


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


class MechUnknownRequest(MechError):
    """No delivery is being awaited for this request id.

    Distinct from a failed read: this id will never become pending again,
    where a failed read says nothing about whether the mech answered.
    """


# Marks a stored report whose request reached the paying call and then failed,
# so the outcome — and the spend — is genuinely unknown to this server.
SPEND_UNCERTAIN = "uncertain"


class PricedMech(t.NamedTuple):
    """The mech a request will pay, with the price the cap must bind."""

    mech: str
    service_id: int
    # per-request price in the mech's payment asset base units (wei for
    # native mechs, token base units for OLAS/USDC ones)
    rate: int
    payment_type: str
