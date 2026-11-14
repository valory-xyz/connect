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

"""Mech marketplace requests driven through the signing choke point.

mech-client composes the flows (IPFS metadata, marketplace contract calls via
the service safe, delivery watching) and hands every transaction and digest to
our Signer through its ``Signer`` protocol — so mech requests pass the exact
same guardrail as any other signing request. In restricted mode the on-chain
flow works because the mech system contracts ship in the default whitelist;
the off-chain flow signs the safe's ERC-1271 SafeMessage wrap of the
request id (the safe is the requester of record in agent mode), which
restricted mode allows only through a scoped allowance, as does the prepaid
top-up (auto_deposit) that moves funds safe -> balance tracker. Both grants
are registered by `connect/mech_allowances.py`, which this drives at the two
points a request needs them; the reasoning for each lives there.
"""

import asyncio
import logging
import threading
import time
import typing as t
from collections.abc import Mapping

from eth_typing import URI
from mech_client import (
    MechPriceExceeded,
    NonceRefused,
    PreSignHook,
    RULE_ANSWER_UNKNOWN,
    chat_report,
    is_chat_prompt,
    offchain_blocker,
    send_with_nonce,
)
from mech_client.domain.delivery import (
    OffchainDeliveryWatcher,
    OnchainDeliveryWatcher,
)
from mech_client.infrastructure.config.payment_config import PaymentType
from mech_client.infrastructure.subgraph.queries import query_mm_mechs_info
from mech_client.services.marketplace_service import MarketplaceService
from safe_eth.eth import EthereumClient

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard
from connect.idempotency import InFlightError, LedgerEntry, RequestLedger
from connect.mech_allowances import Armed, MechAllowances, read_map_nonces
from connect.mech_budget import DEFAULT_MAX_PAYMENT, payment_report
from connect.mech_queue import HardCancelRefused, MechQueue
from connect.mech_signer import MechSigner
from connect.mech_stamp import canonical_context, metadata_extras, request_stamp
from connect.mech_types import (
    MechAnswerUnknown,
    MechError,
    MechNotSent,
    MechUnknownRequest,
    PendingDelivery,
    PricedMech,
    SPEND_UNCERTAIN,
    published_tools,
    request_key,
    request_label,
    said,
)
from connect.signer import Signer, SignerError

logger = logging.getLogger("agent")

DEFAULT_MECH_CHAIN = "gnosis"
DEFAULT_DELIVERY_TIMEOUT = 300.0
# A tool call must not pin its worker forever, and waiting longer than the mech
# itself was given cannot help: mech-client writes responseTimeout=300 into the
# request, so past that the mech is out of time by the request's own terms.
# 900s matches mech-client's own delivery-watcher default and leaves room past
# responseTimeout for settlement and log indexing.
MAX_DELIVERY_TIMEOUT = 900.0
# mech_result resumes a wait rather than starting one, so it polls briefly by
# default: the caller decides when to give up, and a long block here buys
# nothing a second call would not.
DEFAULT_RESULT_TIMEOUT = 30.0
# how long an off-chain send waits for a delivery under the nonce lock;
# positive, since mech-client reads 0 as its 300 s default
ACK_WAIT_SECONDS = 1.0
DEFAULT_MECH_PAGE_SIZE = 20
MAX_MECH_PAGE_SIZE = 100


class _RequestPlan(t.NamedTuple):
    """Everything a request needs, settled before any payment can happen.

    Its existence is the payment boundary: a failure with no plan spent
    nothing, a failure with one may have spent funds.
    """

    chain: str
    service: MarketplaceService
    priced: PricedMech
    extra_attributes: dict | None
    offchain: bool  # the flow; False is the on-chain one
    auto_deposit: bool
    tool: str
    max_payment: int
    terms: dict  # mech-client's mech report, merged into the request's report
    armed: Armed  # the guard grants this request armed, revoked if nothing is sent

    @property
    def legacy_on_chain(self) -> bool:
        """Whether the request goes on-chain: read off `offchain`, never apart."""
        return not self.offchain


def _clamp_timeout(timeout: float) -> float:
    """Clamp a caller-supplied wait to [1, MAX_DELIVERY_TIMEOUT] seconds."""
    return min(max(float(timeout), 1.0), MAX_DELIVERY_TIMEOUT)


class MechService:  # pylint: disable=too-many-instance-attributes
    """Per-chain mech-client marketplace services over the guarded signer."""

    def __init__(
        self, signer: Signer, config: AppConfig, activity: ActivityLog, guard: Guard
    ) -> None:
        """Initialize."""
        self._signer = signer
        self._config = config
        self._activity = activity
        self._allowances = MechAllowances(config, guard, activity)
        self._lock = threading.Lock()
        self._services_lock = threading.Lock()
        self._services: dict[str, MarketplaceService] = {}
        # requests that returned without a delivery, keyed by request id, so
        # mech_result can resume the watch a paid-for request deserves
        self._pending: dict[str, PendingDelivery] = {}
        self._requests = RequestLedger()
        # the one allocator on STORE_PATH: the app's lifespan closes it
        self.queue = MechQueue(config, activity)
        self._nonces = self.queue.allocator

    def hard_cancel(self, chain: str) -> dict:
        """Run the operator's hard cancel on `chain`; a chain with no safe is `no-safe`."""
        chain = chain.lower()
        if self._config.chain(chain).safe_address is None:
            raise HardCancelRefused(
                "no-safe", f"no service safe is configured for chain '{chain}'"
            )
        return self.queue.hard_cancel(self._service(chain), chain)

    def _resolve_chain(self, chain: str | None, *, needs_safe: bool = True) -> str:
        """Resolve the chain: an explicit one wins, else one that has a safe.

        A fixed default strands an agent whose safe lives on another chain: it
        discovers the mismatch only when a request fails, having already been
        shown a listing of mechs it could never pay. An explicit chain is still
        honoured without a safe, because discovery alone needs none.

        `needs_safe=False` is discovery, which only queries the subgraph: with
        no safe anywhere it falls back to the default chain rather than
        refusing, since a listing was answerable before this method existed
        and is still answerable now.
        """
        if chain is not None:
            return chain.lower()
        funded = sorted(
            name
            for name, chain_config in self._config.chains.items()
            if chain_config.safe_address is not None
        )
        if DEFAULT_MECH_CHAIN in funded:
            return DEFAULT_MECH_CHAIN
        if funded:
            return funded[0]
        if not needs_safe:
            # a configured chain, not merely the default one: falling back to
            # a chain this deployment never configured swaps "no safe" for
            # "unknown chain" and still answers nothing
            if DEFAULT_MECH_CHAIN in self._config.chains:
                return DEFAULT_MECH_CHAIN
            if self._config.chains:
                return sorted(self._config.chains)[0]
        raise MechError(
            "no configured chain has a service safe, and mech requests are "
            f"paid by the safe (configured chains: {sorted(self._config.chains)})"
        )

    def _service(self, chain: str) -> MarketplaceService:
        """Lazily build the MarketplaceService for a configured chain."""
        chain = chain.lower()
        chain_config = self._config.chain(chain)  # raises ValueError on unknown
        safe = chain_config.safe_address
        if safe is None:
            raise MechError(
                f"no service safe is configured for chain '{chain}'; mech "
                "requests are paid by the safe"
            )
        with self._services_lock:
            service = self._services.get(chain)
            if service is None:
                # rpc_url, not the process-global MECHX_CHAIN_RPC: each chain's
                # service talks to its own RPC, whatever the others do
                service = MarketplaceService(
                    chain_config=chain,
                    agent_mode=True,
                    safe_address=safe,
                    ethereum_client=EthereumClient(URI(chain_config.rpc_url)),
                    signer=MechSigner(self._signer, chain),
                    rpc_url=chain_config.rpc_url,
                )
                self._services[chain] = service
            return service

    def tools(
        self,
        *,
        chain: str | None = None,
        priority_mech: str | None = None,
        limit: int = DEFAULT_MECH_PAGE_SIZE,
        offset: int = 0,
    ) -> dict:
        """Discover live mechs (paginated), or one mech's tools and reachability.

        Both the tool list and the off-chain endpoint come from the same
        service metadata document, so a single mech report answers whether the
        mech can be reached off-chain (`offchain_capable`) and with which
        tools. An unreadable document degrades to notes rather than an error:
        the mech remains usable on-chain, which is what the notes say.

        Every report names the `chain` it describes, since an omitted one is
        resolved here and the caller would otherwise have no way to tell which
        chain the answer came from.
        """
        chain = self._resolve_chain(chain, needs_safe=priority_mech is not None)
        if priority_mech is None:
            self._config.chain(chain)
            return self._list_mechs(chain, limit=limit, offset=offset)
        service = self._service(chain)
        mech_info = service.mech_info(priority_mech)
        payment_type, service_id = mech_info.payment_type, mech_info.service_id
        max_delivery_rate = mech_info.max_delivery_rate
        info: dict = {
            "chain": chain,
            "mech": priority_mech,
            "payment_type": payment_type.name,
            **payment_report(payment_type, chain),
            "service_id": service_id,
            "max_delivery_rate": str(max_delivery_rate),
        }
        read = service.tool_manager.read_tools_metadata(service_id)
        tool_names = published_tools(read.document)
        if tool_names:
            info["tools"] = tool_names
        elif read.document is None:
            # the two causes stay distinct: one may clear on retry, one will not
            info["tools_note"] = "tool metadata unreadable; a known tool still works"
        else:
            info["tools_note"] = "metadata lists no tools; a known tool still works"
        blocker = offchain_blocker(read)
        info["offchain_capable"] = blocker is None
        if blocker is not None:
            info["offchain_note"] = blocker
        info |= service.tool_manager.mech_report_or_terms(priority_mech, read.document)
        return info

    def _list_mechs(self, chain: str, *, limit: int, offset: int) -> dict:
        """Return a page of live marketplace mechs, most active first.

        The subgraph query is not paginated upstream (it returns the filtered
        list in one response), so pages are sliced here; `total` lets the
        caller know whether another page exists.
        """
        limit = max(1, min(limit, MAX_MECH_PAGE_SIZE))
        offset = max(0, offset)
        try:
            mechs = query_mm_mechs_info(chain) or []
            # inside the try: a malformed subgraph entry must surface as the
            # structured MechError this method promises, not a raw KeyError
            page = [
                {
                    "address": m["address"],
                    "service_id": m.get("service", {}).get("id"),
                    "total_deliveries": int(m["totalDeliveriesTransactions"]),
                    "mech_type": m.get("mech_type"),
                }
                for m in mechs[offset : offset + limit]
            ]
        except Exception as e:
            what = f"could not list mechs for '{chain}'"
            raise MechError(f"{what}: {said(e, what)}") from e
        return {
            "chain": chain,
            "mechs": page,
            "total": len(mechs),
            "offset": offset,
            "limit": limit,
            "note": (
                "call mech_tools with priority_mech=<address> for a mech's "
                "payment type, tool list and whether it can be reached "
                "off-chain; page with limit/offset"
            ),
        }

    def request(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        prompt: str,
        tool: str,
        *,
        chain: str | None = None,
        legacy_on_chain: bool = False,
        priority_mech: str | None = None,
        auto_deposit: bool = True,
        timeout: float = DEFAULT_DELIVERY_TIMEOUT,
        max_payment: int | None = None,
        request_id: str | None = None,
        request_context: dict | None = None,
    ) -> dict:
        """Send one mech request and wait for its delivery.

        ``legacy_on_chain=False`` (default) uses the off-chain prepaid flow;
        ``True`` sends the request on-chain through the marketplace. The
        mech's per-request price must not exceed ``max_payment``, in the
        mech's payment asset base units; left out, it is 0.1 of that asset.

        Pass a ``request_id`` to make an attempt replayable — see README,
        "Mech requests", for what that covers and what it deliberately does
        not.
        """
        timeout = _clamp_timeout(timeout)
        planned: _RequestPlan | None = None

        def attempt() -> dict:
            nonlocal planned
            plan = self._prepare(
                tool,
                chain=chain,
                legacy_on_chain=legacy_on_chain,
                priority_mech=priority_mech,
                auto_deposit=auto_deposit,
                max_payment=max_payment,
                request_context=request_context,
            )
            # past this point a failure cannot be reported as "nothing was spent"
            planned = plan
            return self._dispatch(
                plan,
                prompt,
                timeout=timeout,
                request_id=request_id,
            )

        if request_id is None:
            return attempt()
        stamp = request_stamp(
            prompt,
            tool,
            chain=self._resolve_chain(chain),
            priority_mech=priority_mech,
            legacy_on_chain=legacy_on_chain,
            request_context=request_context,
        )
        try:
            entry = self._requests.reserve(request_id)
        except InFlightError:
            self._refused(request_id, "in-flight", "another call holds this id")
            raise MechError(
                f"mech request '{request_id}' is already in flight; retry shortly"
            ) from None
        try:
            if entry is not None:
                merged = self._replay(request_id, entry, stamp, timeout=timeout)
                self._requests.complete(request_id, merged, stamp)
                self._activity.record(
                    "mech_request_replayed",
                    request_id=request_id,
                    pending_request_ids=merged.get("pending_request_ids") or [],
                )
                return merged
            payload = attempt()
        except Exception as e:
            if planned is not None and not isinstance(e, MechNotSent):
                self._requests.complete(
                    request_id,
                    self._uncertain(planned, e, request_id),
                    stamp,
                    spend_uncertain=True,
                )
            else:
                self._requests.release(request_id)
            raise
        self._requests.complete(request_id, payload, stamp)
        return payload

    def _uncertain(self, plan: _RequestPlan, error: Exception, request_id: str) -> dict:
        """Record that a request was sent and its outcome is unknown.

        Releasing the id here would be the friendly-looking mistake: the
        caller would retry, and mech-client pays before it watches, so the
        retry would buy a second answer to a question already paid for.
        """
        self._activity.record(
            "mech_request_uncertain",
            chain=plan.chain,
            tool=plan.tool,
            request_id=request_id,
            error=str(error),
        )
        return {"chain": plan.chain, "spend": SPEND_UNCERTAIN, "error": str(error)}

    def _replay(  # pylint: disable=too-many-locals
        self, request_id: str, entry: LedgerEntry, stamp: str, *, timeout: float
    ) -> dict:
        """Re-answer a request already sent, collecting any late delivery.

        Handing back the stored report unchanged would be the cheap thing and
        the wrong one: the first call may have returned before the mech
        answered, and the answer may have landed since. So this resumes each
        outstanding watch. What it must never do is send again.
        """
        if entry.stamp is not None and entry.stamp != stamp:
            self._refused(request_id, "stamp-mismatch", "reused for a different ask")
            raise MechError(
                f"request id '{request_id}' was already used for a different "
                "prompt, tool, chain, mech, flow or context; choose a new id "
                "rather than replaying this one, which would answer the wrong "
                "question"
            )
        payload = entry.payload
        if entry.spend_uncertain:
            self._refused(
                request_id, "spend-uncertain", str(payload.get("error") or "")
            )
            raise MechError(
                f"request '{request_id}' reached the paying call and then "
                f"failed ({payload.get('error')}), so this server cannot tell "
                "whether it was paid for. Sending it again risks a second "
                "payment — use a new id only if you accept that."
            )
        waiting = list(payload.get("pending_request_ids") or [])
        if not waiting:
            return {**payload, "replayed": True}
        delivered = dict(payload.get("delivery_results") or {})
        urls = dict(payload.get("delivery_urls") or {})
        still_waiting: list[str] = []
        unrecoverable: list[str] = []
        errors: dict[str, str] = {}
        for key in waiting:
            try:
                report = self.result(key, timeout=timeout)
            except MechUnknownRequest:
                unrecoverable.append(key)
            except MechError as e:
                logger.warning("replay could not read delivery for %s: %s", key, e)
                errors[key] = str(e)
                still_waiting.append(key)
            else:
                if report.get("url"):
                    urls[key] = report["url"]
                if report.get("delivered"):
                    delivered[key] = report["result"]
                else:
                    still_waiting.append(key)
        merged = {**payload, "delivery_results": delivered, "replayed": True}
        if urls:
            merged["delivery_urls"] = urls
        merged.pop("pending_request_ids", None)
        merged.pop("unrecoverable_request_ids", None)
        merged.pop("replay_errors", None)
        if still_waiting:
            merged["pending_request_ids"] = still_waiting
        if unrecoverable:
            merged["unrecoverable_request_ids"] = unrecoverable
        if errors:
            merged["replay_errors"] = errors
        return merged

    def _prepare(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        tool: str,
        *,
        chain: str | None,
        legacy_on_chain: bool,
        priority_mech: str | None,
        auto_deposit: bool,
        max_payment: int | None,
        request_context: dict | None,
    ) -> _RequestPlan:
        """Settle everything a request needs before any payment can happen.

        Each refusal below is audited before it raises: the activity log is
        what an operator reconstructs an incident from, and a request blocked
        by policy must not look identical there to one never attempted.
        """
        canonical_context(request_context)
        chain = self._resolve_chain(chain)
        service = self._service(chain)
        priced = self._priced_mech(service, chain, priority_mech)
        priority_mech, service_id = priced.mech, priced.service_id
        if max_payment is None:
            max_payment = DEFAULT_MAX_PAYMENT.get(PaymentType(priced.payment_type))
            if max_payment is None:
                self._blocked(
                    chain, tool, "no-default-max-payment", priced.payment_type
                )
                raise MechError(
                    f"mech {priority_mech} is paid in an asset this server has no "
                    "default budget for; pass max_payment to set one"
                )
        extra_attributes: dict | None
        armed: Armed = []
        if not legacy_on_chain:
            # mech-client discovers the endpoint mid-flow and fails there with
            # a message about metadata, which reads as a transient gateway
            # problem. Most listed mechs publish no endpoint at all, so decide
            # it here, before any payment, and name the flow that does work.
            read = service.tool_manager.read_tools_metadata(service_id)
            blocker = offchain_blocker(read)
            if blocker is not None:
                self._blocked(chain, tool, "offchain-unreachable", blocker)
                raise MechError(
                    f"mech {priority_mech} (service {service_id}) cannot serve "
                    f"off-chain requests: {blocker}"
                )
            # before any allowance is armed, so a failure here spends nothing
            terms = service.tool_manager.mech_report_or_terms(
                priority_mech, read.document
            )
            # the pinned metadata salt: a resend of the allocator's nonce
            # signs the same request id
            extra_attributes = metadata_extras(request_context)
            offchain = True
            if auto_deposit:
                auto_deposit = self._allowances.keeps_auto_deposit(chain, priced)
        else:
            # nothing reads the document on-chain, so no operator link here
            terms = service.tool_manager.terms_report(priority_mech, None)
            offchain = False
            extra_attributes = (
                None
                if request_context is None
                else {"request_context": request_context}
            )
        return _RequestPlan(
            chain=chain,
            service=service,
            priced=priced,
            extra_attributes=extra_attributes,
            offchain=offchain,
            auto_deposit=auto_deposit,
            tool=tool,
            max_payment=max_payment,
            terms=terms,
            armed=armed,
        )

    def _dispatch(  # pylint: disable=too-many-locals,too-many-statements
        self,
        plan: _RequestPlan,
        prompt: str,
        *,
        timeout: float,
        request_id: str | None,
    ) -> dict:
        """Pay for the planned request, send it, and wait out its delivery.

        Everything here is past the point of no return: mech-client pays
        before it watches, so a failure below may still have spent funds.
        """
        deadline = time.monotonic() + timeout
        try:
            result = self._send(plan, prompt, timeout)
        except MechAnswerUnknown as e:  # the mech may hold it: keep its id pending
            self._with_pending(
                {"request_ids": e.pending_request_ids},
                chain=plan.chain,
                mech=plan.priced.mech,
                service_id=plan.priced.service_id,
                offchain=not plan.legacy_on_chain,
            )
            self._allowances.record_deposit(plan.chain, request_id, e.deposited)
            self._activity.record(
                "mech_request_failed",
                chain=plan.chain,
                tool=plan.tool,
                request_id=request_id,
                error=str(e),
                pending_request_ids=e.pending_request_ids,
            )
            raise
        except MechPriceExceeded as e:  # mech-client's cap: nothing was paid
            self._blocked(plan.chain, plan.tool, "over-max-payment", str(e))
            raise MechNotSent(
                f"mech {plan.priced.mech} charges {e.price} per request (in its "
                f"payment asset base units), above max_payment={e.max_price}; "
                "pass a higher max_payment to accept that price"
            ) from e
        except NonceRefused as e:
            note = self.queue.note(plan.chain)
            deposited = getattr(e.__cause__, "deposited", 0)
            self._allowances.record_deposit(plan.chain, request_id, deposited)
            self._activity.record(
                "refusal",
                rule=e.rule,
                chain=plan.chain,
                tool=plan.tool,
                request_id=request_id,
                reason=str(e),
            )
            raise MechNotSent(f"rule '{e.rule}': {e}{note}") from e
        except MechNotSent as e:  # failed before reaching the mech: nothing paid
            self._activity.record(
                "mech_request_not_sent",
                chain=plan.chain,
                tool=plan.tool,
                request_id=request_id,
                error=str(e),
            )
            raise
        except (MechError, SignerError):
            raise
        except Exception as e:
            self._activity.record(
                "mech_request_failed",
                chain=plan.chain,
                tool=plan.tool,
                request_id=request_id,
                error=str(e),
            )
            what = request_label(plan.chain, plan.priced.mech, plan.tool, request_id)
            raise MechError(f"mech request failed: {said(e, what)}") from e
        finally:  # nothing more is signed for this request, sent or not
            self._allowances.revoke(plan.armed)
        self._activity.record(
            "mech_request",
            chain=plan.chain,
            tool=plan.tool,
            request_id=request_id,
            offchain=not plan.legacy_on_chain,
            rate=str(plan.priced.rate),
            max_payment=str(plan.max_payment),
            context_keys=sorted(
                (plan.extra_attributes or {}).get("request_context") or {}
            ),
            request_ids=list(result.get("request_ids") or []),
        )
        payload = self._with_pending(
            dict(result),
            chain=plan.chain,
            mech=plan.priced.mech,
            service_id=plan.priced.service_id,
            offchain=not plan.legacy_on_chain,
        )
        payload.update(plan.terms)
        if plan.offchain:
            # nothing in the signed request expires it (mech-client sends no
            # deadline): it can settle whenever the mech delivers it, or the
            # operator's hard cancel consumes its nonce
            payload["expires"] = None
            payload.update(self.queue.report(plan.chain))
        self._resume_watch(payload, deadline)
        if plan.offchain:  # a delivery starts the settle clock
            by_key = zip(result.get("request_ids") or [], result.get("nonces") or [])
            got = payload.get("delivery_results") or {}
            self._nonces.delivered(
                plan.chain,
                t.cast(str, self._config.chain(plan.chain).safe_address),
                [nonce for key, nonce in by_key if key in got],
            )
        try:  # paid and delivered by now: a delivery it cannot read loses nothing
            if is_chat_prompt(prompt):
                for data in (payload.get("delivery_results") or {}).values():
                    chat = chat_report(data)
                    if chat is not None:
                        payload.update(chat)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("could not read a chat completion: %s", e)
            payload["chat_error"] = str(e)
        return payload

    def _resume_watch(self, payload: dict, deadline: float) -> None:
        """Spend the rest of the caller's wait on deliveries, off the nonce lock.

        Both sends wait only ACK_WAIT_SECONDS under the queue's lock, so other
        requests from the safe queue for a send, not for its delivery. The
        request is paid for by now: a failed read keeps its id pending, with
        the cause in `watch_errors`, and never loses the payload.
        """
        for key in list(payload.get("pending_request_ids") or []):
            remaining = deadline - time.monotonic()
            if remaining < 1:
                break
            try:
                report = self.result(key, timeout=remaining)
            except MechError as e:
                logger.warning("could not read the delivery for %s: %s", key, e)
                payload.setdefault("watch_errors", {})[key] = str(e)
                continue
            if report.get("url"):
                payload.setdefault("delivery_urls", {})[key] = report["url"]
            if report.get("delivered"):
                payload.setdefault("delivery_results", {})[key] = report["result"]
                payload["pending_request_ids"].remove(key)
        if not payload.get("pending_request_ids"):
            payload.pop("pending_request_ids", None)

    def _send(  # pylint: disable=too-many-locals
        self, plan: _RequestPlan, prompt: str, timeout: float
    ) -> dict:
        """Send the planned request, off-chain through mech-client's allocator."""
        safe = t.cast(str, self._config.chain(plan.chain).safe_address)

        def send(**extra: t.Any) -> dict:
            return asyncio.run(
                plan.service.send_request(
                    prompts=(prompt,),
                    tools=(plan.tool,),
                    priority_mech=plan.priced.mech,
                    use_offchain=plan.offchain,
                    auto_deposit=plan.auto_deposit,
                    extra_attributes=plan.extra_attributes,
                    # a short wait under the queue's lock; _resume_watch
                    # spends the rest
                    timeout=min(timeout, ACK_WAIT_SECONDS),
                    max_price=plan.max_payment,
                    **extra,
                )
            )

        try:
            contract = plan.service.marketplace_contract()
        except Exception as e:
            what = f"could not read the marketplace on {plan.chain}"
            raise MechNotSent(f"could not read the marketplace: {said(e, what)}") from e

        def read_map() -> int:
            try:
                return read_map_nonces(contract, safe)
            except Exception as e:
                what = f"could not read the marketplace nonce on {plan.chain}"
                raise MechNotSent(
                    f"could not read the marketplace nonce: {said(e, what)}"
                ) from e

        if not plan.offchain:  # on-chain takes mapNonces itself: none held
            with self._nonces.exclusive(plan.chain, safe, read_map, timeout=timeout):
                return send()
        chain_id = int(plan.service.mech_config.ledger_config.chain_id)
        armed: dict[int, bytes] = {}
        sent: list[tuple[int, PreSignHook]] = []

        def arm(request_id: bytes, nonce: int) -> None:
            self._allowances.arm(
                chain=plan.chain,
                safe=safe,
                chain_id=chain_id,
                mech=plan.priced.mech,
                request_id=request_id,
                nonce=nonce,
                armed=plan.armed,
            )
            armed[nonce] = bytes(request_id)

        def send_one(nonce: int, hook: PreSignHook) -> dict:
            sent.append((nonce, hook))
            # under the queue's lock: no other request's top-up can spend it
            with self._allowances.auto_deposit_armed(
                plan.chain, plan.priced, auto_deposit=plan.auto_deposit
            ):
                return send(nonces=[nonce], on_request_id=hook)

        try:
            return send_with_nonce(
                self._nonces,
                chain=plan.chain,
                sender=safe,
                mech=plan.priced.mech,
                salt=str((plan.extra_attributes or {})["nonce"]),
                read_map_nonces=read_map,
                send=send_one,
                not_sent=(MechNotSent, SignerError),
                timeout=timeout,
                on_request_id=arm,
            )
        except MechPriceExceeded:
            raise
        except NonceRefused as e:
            if e.rule != RULE_ANSWER_UNKNOWN:
                raise
            raise self._lost(plan, sent, armed, e) from e
        except Exception as e:
            # mech-client frees the nonce of what not_sent names, posting or not
            # (a SignerError after the POST is the 402 top-up's): so does Connect
            if isinstance(e, MechNotSent):  # the mapNonces read: nothing sent
                raise
            if sent and sent[-1][1].posting and not isinstance(e, SignerError):
                raise self._lost(plan, sent, armed, e) from e
            what = request_label(plan.chain, plan.priced.mech, plan.tool, None)
            raise MechNotSent(f"mech request not sent: {said(e, what)}") from e

    def _lost(
        self,
        plan: _RequestPlan,
        sent: list[tuple[int, PreSignHook]],
        armed: dict[int, bytes],
        error: Exception,
    ) -> MechAnswerUnknown:
        """Describe a signed request whose answer was lost, its armed id pending."""
        held = [armed[sent[-1][0]].hex()]
        what = request_label(plan.chain, plan.priced.mech, plan.tool, held[0])
        return MechAnswerUnknown(
            f"rule '{RULE_ANSWER_UNKNOWN}': {said(error, what)}"
            f"{self.queue.note(plan.chain)}; "
            f"pending_request_ids: {held} (mech_result collects it if the mech "
            "delivers it)",
            held,
            getattr(error.__cause__, "deposited", 0),
        )

    def _with_pending(  # pylint: disable=too-many-locals
        self,
        result: dict,
        *,
        chain: str,
        mech: str,
        service_id: int,
        offchain: bool,
    ) -> dict:
        """Record every request id the mech has not answered, and report them.

        A timed-out wait is not a failed request: it was paid for and the mech
        may still answer. Remembering where to look is what lets mech_result
        pick it up instead of the answer being stranded.
        """
        deliveries = result.get("deliveries") or {}
        delivered = {rid: d.data for rid, d in deliveries.items() if d.data is not None}
        urls = {rid: d.url for rid, d in deliveries.items() if d.url is not None}
        ids = list(result.get("request_ids") or [])
        receipt = result.get("receipt")
        block = receipt.get("blockNumber") if isinstance(receipt, Mapping) else None
        pending = PendingDelivery(
            chain=chain,
            mech=mech,
            service_id=service_id,
            offchain=offchain,
            from_block=block,
        )
        waiting = [key for key in ids if key not in delivered]
        with self._lock:
            for key in waiting:
                self._pending[key] = pending
        payload = {"chain": chain, **result}
        payload.pop("deliveries", None)
        if "deliveries" in result:
            payload["delivery_results"] = delivered
        if urls:
            payload["delivery_urls"] = urls
        if waiting:
            payload["pending_request_ids"] = waiting
        return payload

    def result(
        self, request_id: str, *, timeout: float = DEFAULT_RESULT_TIMEOUT
    ) -> dict:
        """Resume watching for one request's delivery, without paying again.

        Only ids this service is still waiting on can be polled: the watchers
        need the flow, the chain and the request's own block to look in the
        right place, and none of that survives a restart.
        """
        timeout = _clamp_timeout(timeout)
        key = request_key(request_id)
        with self._lock:
            pending = self._pending.get(key)
        if pending is None:
            raise MechUnknownRequest(
                f"nothing is awaiting delivery for request {key}; mech_result "
                "polls the ids mech_request reported as pending, and a restart "
                "of this service clears them"
            )
        service = self._service(pending.chain)
        try:
            delivered = asyncio.run(self._watch(service, pending, key, timeout))
        except Exception as e:
            what = f"could not read delivery for request {key}"
            raise MechError(f"{what}: {said(e, f'{what} on {pending.chain}')}") from e
        split = {request_key(k): v for k, v in (delivered or {}).items()}
        data = {k: d.data for k, d in split.items() if d.data is not None}
        report = {
            "request_id": key,
            "chain": pending.chain,
            "mech": pending.mech,
            "delivered": key in data,
        }
        if pending.offchain:
            report.update(self.queue.report(pending.chain))
        if key not in data:
            unreadable = split.get(key)
            if unreadable is None:
                report["note"] = (
                    "no delivery yet — the mech may still answer, or may never; "
                    "poll again or treat the payment as spent"
                )
            else:
                report["note"] = (
                    "delivered, but its result file could not be read yet — "
                    "poll again; the answer is at the url below"
                )
                if unreadable.url:
                    report["url"] = unreadable.url
            return report
        with self._lock:
            self._pending.pop(key, None)
        self._activity.record("mech_result", chain=pending.chain, request_id=key)
        url = split[key].url
        return {**report, "result": data[key], **({"url": url} if url else {})}

    @staticmethod
    async def _watch(
        service: MarketplaceService,
        pending: PendingDelivery,
        key: str,
        timeout: float,
    ) -> dict:
        """Run the watcher for the flow this request was sent through."""
        if pending.offchain:
            url = service.tool_manager.get_offchain_url(pending.service_id)
            return await OffchainDeliveryWatcher(url, timeout).watch([key])
        contract = service.marketplace_contract()
        watcher = OnchainDeliveryWatcher(contract, service.ledger_api, timeout)
        return await watcher.watch([key], from_block=pending.from_block)

    def _refused(self, request_id: str, reason: str, detail: str) -> None:
        """Audit a replay refused on its id, before raising it to the caller."""
        self._activity.record(
            "mech_request_refused",
            request_id=request_id,
            reason=reason,
            detail=detail,
        )

    def _blocked(self, chain: str, tool: str, reason: str, detail: str) -> None:
        """Audit a request refused by policy, before raising it to the caller."""
        self._activity.record(
            "mech_request_blocked",
            chain=chain,
            tool=tool,
            reason=reason,
            detail=detail,
        )

    def _priced_mech(
        self, service: MarketplaceService, chain: str, priority_mech: str | None
    ) -> PricedMech:
        """Resolve the target mech, its service id and per-request price (wei).

        Without an explicit mech, the most active listed mech is used: the
        price cap must bind the mech that is actually paid, so the selection
        happens here instead of inside mech-client's send path. The service id
        comes back with it because every later check — reachability, metadata
        — is keyed by service rather than by mech address.

        Named rather than a bare tuple because two of the three fields are
        ints of wholly different kinds: transposing a service id and a wei
        price would corrupt the `max_payment` cap silently, and no type
        checker would object.
        """
        if priority_mech is None:
            listing = self._list_mechs(chain, limit=1, offset=0)
            if not listing["mechs"]:
                raise MechError(f"no live mechs found for '{chain}'")
            priority_mech = str(listing["mechs"][0]["address"])
        try:
            info = service.mech_info(priority_mech)
        except Exception as e:
            what = f"could not price mech {priority_mech}"
            raise MechError(f"{what}: {said(e, f'{what} on {chain}')}") from e
        return PricedMech(
            mech=priority_mech,
            service_id=int(info.service_id),
            rate=int(info.max_delivery_rate),
            payment_type=str(info.payment_type.value),
        )
