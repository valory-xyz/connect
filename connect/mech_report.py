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

"""Whose mech a session is about to pay, as mech-client reports it."""

import logging

from mech_client.infrastructure.subgraph.queries import query_mech_record
from mech_client.services.marketplace_service import MarketplaceService

logger = logging.getLogger("agent")


def mech_report(
    service: MarketplaceService, chain: str, mech: str, document: dict | None
) -> dict:
    """Ask mech-client whose mech this is and what its record says.

    With a document this is ``ToolManager.mech_report``: whose terms apply,
    the operator the manifest claims and whether its domain backs the claim,
    the benchmark links, the on-chain delivery record and the payment method.
    The record comes from the marketplace indexer. When it cannot be read the
    report is the terms alone and ``report_note`` says so: the terms decide
    what a request agrees to, the record only informs the choice, so an
    indexer outage must neither hide the terms nor block the request. Without
    a document only the terms can be checked. Every check and label is
    mech-client's; nothing is recomputed here.
    """
    if document is None:
        return service.tool_manager.terms_report(mech, None)
    try:
        record = query_mech_record(chain, mech)
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.warning("mech record unavailable for %s on %s: %s", mech, chain, e)
        report = service.tool_manager.terms_report(mech, document)
        report["report_note"] = (
            f"operator and delivery record unavailable ({type(e).__name__}: "
            f"{e}); only the terms are reported"
        )
        return report
    return service.tool_manager.mech_report(mech, document, record=record)
