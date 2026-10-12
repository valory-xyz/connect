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

"""mech-client's pre-payment report, within a deadline connect sets."""

import logging
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError

from mech_client.services.marketplace_service import MarketplaceService

from connect.mech_rpc import listing_mechs

logger = logging.getLogger("agent")

# How long a session waits for the report before it pays. The report reads
# the indexers and fetches a proof from a host the mech's operator controls,
# so without a bound a slow host could hold the request indefinitely.
REPORT_DEADLINE = 10.0
# Reports share one capped pool. A report given up on keeps its thread until
# its reads end, so the cap bounds how many a slow host can hold; once all are
# held, later reports wait their deadline and fall back to the terms.
REPORT_WORKERS = 4
REPORT_TIMEOUT_NOTE = (
    "The operator and delivery record took longer than {deadline:g}s to read; "
    "only the terms are reported."
)

_EXECUTOR = ThreadPoolExecutor(
    max_workers=REPORT_WORKERS, thread_name_prefix="mech-report"
)


def _report(service: MarketplaceService, mech: str, document: dict | None) -> dict:
    """Run mech-client's report as a listing, so its RPC check stays quiet.

    :param service: the chain's marketplace service
    :param mech: the mech about to be paid
    :param document: the mech's already read manifest, or None
    :return: mech-client's report
    """
    # The indexer reads re-read MECHX_CHAIN_RPC only to compare it with the
    # chain; listing_mechs is per thread, so it is entered here, in the worker.
    with listing_mechs():
        return service.tool_manager.mech_report_or_terms(mech, document)


def mech_report(service: MarketplaceService, mech: str, document: dict | None) -> dict:
    """Ask mech-client whose mech this is, giving up at REPORT_DEADLINE.

    The terms decide what a request agrees to, the rest only informs the
    choice, so a report that does not finish in time falls back to
    mech-client's terms check alone, with ``report_note`` saying why.

    :param service: the chain's marketplace service
    :param mech: the mech about to be paid
    :param document: the mech's already read manifest, or None
    :return: mech-client's report, or its terms report and a note
    """
    future = _EXECUTOR.submit(_report, service, mech, document)
    try:
        return future.result(timeout=REPORT_DEADLINE)
    except FuturesTimeoutError:
        future.cancel()
        logger.warning(
            "mech report for %s took longer than %ss; reporting the terms only",
            mech,
            REPORT_DEADLINE,
        )
        report = service.tool_manager.terms_report(mech, document)
        report["report_note"] = REPORT_TIMEOUT_NOTE.format(deadline=REPORT_DEADLINE)
        return report
