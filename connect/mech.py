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
the off-chain flow needs raw digest signing and therefore unrestricted mode.
"""

import asyncio
import logging
import os
import threading
import typing as t
from collections.abc import Mapping

from mech_client.services.marketplace_service import MarketplaceService

from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.guard import Guard, GuardError
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
DEFAULT_MECH_PAGE_SIZE = 20
MAX_MECH_PAGE_SIZE = 100
# A mech prices its own requests (max_delivery_rate) and the guardrail only
# checks *where* payments go — this cap bounds *how much* a single request may
# cost. 0.1 of the chain's native unit; raising it is an explicit, audited
# per-request choice.
DEFAULT_MAX_PAYMENT = 10**17


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


class PricedMech(t.NamedTuple):
    """The mech a request will pay, with the price the cap must bind."""

    mech: str
    service_id: int
    rate_wei: int


class PendingDelivery(t.NamedTuple):
    """Where to resume looking for a request whose delivery had not arrived.

    `from_block` is the request's own transaction block: the on-chain watcher
    otherwise scans from the head minus a hundred blocks, which finds nothing
    for a request that has been waiting a while — exactly the case this exists
    to serve.
    """

    chain: str
    mech: str
    service_id: int
    offchain: bool
    from_block: int | None


def _request_key(request_id: object) -> str:
    """Normalize a request id: the two flows disagree about the 0x prefix."""
    return str(request_id).lower().removeprefix("0x")


class MetadataRead(t.NamedTuple):
    """A service-metadata read: the document, or why it could not be read.

    The reason travels with the result because the two failure modes it
    separates need opposite responses — a gateway that timed out may well
    answer on the next call, while a mech that never published metadata never
    will — and nothing downstream can tell them apart from a bare ``None``.
    """

    document: dict | None
    error: str | None


def _offchain_blocker(read: MetadataRead) -> str | None:
    """Why this mech cannot serve an off-chain request, or None if it can.

    The off-chain flow resolves the mech's endpoint from the ``url`` field of
    the service metadata, so a document we cannot read and a document without
    a ``url`` both rule the flow out entirely — but they earn different advice,
    which is why each reason carries its own. A mech that published no ``url``
    never will serve off-chain; a fetch that failed may simply succeed next
    time, and sending that one on-chain spends gas to avoid a retry.
    """
    if read.document is None:
        cause = read.error or "no cause reported"
        # "may be" is load-bearing: nothing here distinguishes a mech that
        # never published from a gateway that was briefly slow.
        return (
            f"metadata unreadable ({cause}); may be transient or never "
            "published — retry before paying to send this on-chain"
        )
    url = read.document.get("url")
    if not isinstance(url, str) or not url.strip():
        return "no 'url' in metadata; this mech serves on-chain requests only"
    return None


class MechSigner:
    """mech-client ``Signer`` protocol adapter over our guarded Signer.

    No special privileges: every transaction goes through Signer.send() and
    every digest through Signer.sign_digest(), both guardrail-checked.
    """

    def __init__(self, signer: Signer, chain: str) -> None:
        """Initialize."""
        self._signer = signer
        self._chain = chain

    @property
    def address(self) -> str:
        """The agent EOA address."""
        return self._signer.address

    def send_transaction(self, unsigned_tx: dict) -> str:
        """Fill, sign and broadcast the transaction via the choke point."""
        data = unsigned_tx.get("data") or "0x"
        if isinstance(data, (bytes, bytearray)):
            data = "0x" + bytes(data).hex()
        return self._signer.send(
            chain=self._chain,
            to=unsigned_tx["to"],
            value=int(unsigned_tx.get("value") or 0),
            data=data,
            gas=unsigned_tx.get("gas"),
        )

    def sign_message(self, message: bytes) -> bytes:
        """Sign a raw digest via the choke point (guardrail-checked)."""
        signature = self._signer.sign_digest(bytes(message))
        return bytes.fromhex(signature.removeprefix("0x"))


class MechService:
    """Per-chain mech-client marketplace services over the guarded signer."""

    def __init__(
        self, signer: Signer, config: AppConfig, activity: ActivityLog, guard: Guard
    ) -> None:
        """Initialize."""
        self._signer = signer
        self._config = config
        self._activity = activity
        self._guard = guard
        self._lock = threading.Lock()
        self._services: dict[str, MarketplaceService] = {}
        # requests that returned without a delivery, keyed by request id, so
        # mech_result can resume the watch a paid-for request deserves
        self._pending: dict[str, PendingDelivery] = {}

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

    @staticmethod
    def _service_metadata(service: MarketplaceService, service_id: int) -> MetadataRead:
        """Read the mech's published service metadata, keeping any failure cause.

        One fetch answers both questions a report asks of that document — the
        tool names and the off-chain URL — where mech-client refetches it per
        question, and every miss costs a full gateway timeout. The request
        path still pays twice: the pre-flight reads it here, then
        ``send_request`` resolves the URL from it again inside mech-client.

        mech-client swallows the common transport failures itself and hands
        back a bare ``None``, so a miss here usually arrives with no cause at
        all. Log every miss rather than only the ones that reach the `except`,
        otherwise the frequent case leaves no trace in this service's log.
        """
        try:
            metadata = service.tool_manager.fetch_tools_metadata(service_id)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("metadata fetch failed for service %s: %s", service_id, e)
            return MetadataRead(None, f"{type(e).__name__}: {e}")
        if isinstance(metadata, dict):
            return MetadataRead(metadata, None)
        logger.warning(
            "metadata for service %s is unusable: expected a document, got %s",
            service_id,
            type(metadata).__name__,
        )
        return MetadataRead(None, None)

    def _service(self, chain: str) -> MarketplaceService:
        """Lazily build the MarketplaceService for a configured chain."""
        # pylint: disable=import-outside-toplevel
        from eth_typing import URI
        from safe_eth.eth import EthereumClient

        chain = chain.lower()
        chain_config = self._config.chain(chain)  # raises ValueError on unknown
        safe = chain_config.safe_address
        if safe is None:
            raise MechError(
                f"no service safe is configured for chain '{chain}'; mech "
                "requests are paid by the safe"
            )
        with self._lock:
            service = self._services.get(chain)
            if service is None:
                # mech-client reads the RPC from this process-global env var at
                # service construction (highest priority, keeps it away from
                # ~/.operate) — hence the construction lock, which must span
                # the constructor itself: built outside it, two chains could
                # race the env var and construct against each other's RPC.
                # First use of one chain therefore stalls the others; the fix
                # is a constructor arg upstream (valory-xyz/mech-client#247).
                # The exact ==0.21.2 pin keeps the construction-time-read
                # behavior from drifting underneath this lock.
                os.environ["MECHX_CHAIN_RPC"] = chain_config.rpc_url
                service = MarketplaceService(
                    chain_config=chain,
                    agent_mode=True,
                    safe_address=safe,
                    ethereum_client=EthereumClient(URI(chain_config.rpc_url)),
                    signer=MechSigner(self._signer, chain),
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
        # no public single-mech info API in mech-client yet; the protected
        # helper is the same one send_request() uses internally
        fetch_info = service._fetch_mech_info  # pylint: disable=protected-access
        payment_type, service_id, max_delivery_rate = fetch_info(priority_mech)
        info: dict = {
            "chain": chain,
            "mech": priority_mech,
            "payment_type": payment_type.name,
            "service_id": service_id,
            "max_delivery_rate": str(max_delivery_rate),
        }
        read = self._service_metadata(service, service_id)
        # The document is published by the mech operator, so neither its shape
        # nor its contents are ours to assume. A `tools` that is not a list
        # must not be iterated (a bare string yields one "tool" per character),
        # and an entry that is not a name must not be stringified into one:
        # both invent plausible-looking tools that no mech serves.
        raw_tools = (read.document or {}).get("tools")
        tool_names = (
            [n for n in raw_tools if isinstance(n, str) and n.strip()]
            if isinstance(raw_tools, list)
            else []
        )
        if tool_names:
            info["tools"] = tool_names
        elif read.document is None:
            # the two causes stay distinct: one may clear on retry, one will not
            info["tools_note"] = "tool metadata unreadable; a known tool still works"
        else:
            info["tools_note"] = "metadata lists no tools; a known tool still works"
        blocker = _offchain_blocker(read)
        info["offchain_capable"] = blocker is None
        if blocker is not None:
            info["offchain_note"] = blocker
        return info

    def _list_mechs(self, chain: str, *, limit: int, offset: int) -> dict:
        """Return a page of live marketplace mechs, most active first.

        The subgraph query is not paginated upstream (it returns the filtered
        list in one response), so pages are sliced here; `total` lets the
        caller know whether another page exists.
        """
        # pylint: disable=import-outside-toplevel
        from mech_client.infrastructure.subgraph.queries import query_mm_mechs_info

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
            raise MechError(f"could not list mechs for '{chain}': {e}") from e
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

    def request(  # pylint: disable=too-many-arguments
        self,
        prompt: str,
        tool: str,
        *,
        chain: str | None = None,
        legacy_on_chain: bool = False,
        priority_mech: str | None = None,
        auto_deposit: bool = True,
        timeout: float = DEFAULT_DELIVERY_TIMEOUT,
        max_payment: int = DEFAULT_MAX_PAYMENT,
    ) -> dict:
        """Send one mech request and wait for its delivery.

        ``legacy_on_chain=False`` (default) uses the off-chain prepaid flow;
        ``True`` sends the request on-chain through the marketplace. The
        mech's per-request price must not exceed ``max_payment`` (wei).

        Each refusal below is audited before it raises: the activity log is
        what an operator reconstructs an incident from, and a request blocked
        by policy must not look identical there to one never attempted.
        """
        timeout = min(max(float(timeout), 1.0), MAX_DELIVERY_TIMEOUT)
        chain = self._resolve_chain(chain)
        if not legacy_on_chain:
            # Same rule the signer enforces, surfaced before any work happens
            # (the off-chain flow raw-signs the request-id digest).
            try:
                self._guard.check_sign_digest()
            except GuardError as e:
                self._blocked(chain, tool, "restricted-mode", str(e))
                raise MechError(
                    f"off-chain mech requests are restricted: {e}; retry it on-chain"
                ) from e
        service = self._service(chain)
        priority_mech, service_id, rate = self._priced_mech(
            service, chain, priority_mech
        )
        if rate > max_payment:
            self._blocked(
                chain, tool, "over-max-payment", f"{rate} wei > {max_payment} wei"
            )
            raise MechError(
                f"mech {priority_mech} charges {rate} wei per request, above "
                f"max_payment={max_payment}; pass a higher max_payment to "
                "accept that price"
            )
        if not legacy_on_chain:
            # mech-client discovers the endpoint mid-flow and fails there with
            # a message about metadata, which reads as a transient gateway
            # problem. Most listed mechs publish no endpoint at all, so decide
            # it here, before any payment, and name the flow that does work.
            blocker = _offchain_blocker(self._service_metadata(service, service_id))
            if blocker is not None:
                self._blocked(chain, tool, "offchain-unreachable", blocker)
                raise MechError(
                    f"mech {priority_mech} (service {service_id}) cannot serve "
                    f"off-chain requests: {blocker}"
                )
        try:
            result = asyncio.run(
                service.send_request(
                    prompts=(prompt,),
                    tools=(tool,),
                    priority_mech=priority_mech,
                    use_offchain=not legacy_on_chain,
                    auto_deposit=auto_deposit,
                    timeout=timeout,
                )
            )
        except (MechError, SignerError):
            raise
        except Exception as e:
            self._activity.record(
                "mech_request_failed", chain=chain, tool=tool, error=str(e)
            )
            raise MechError(f"mech request failed: {e}") from e
        self._activity.record(
            "mech_request",
            chain=chain,
            tool=tool,
            offchain=not legacy_on_chain,
            request_ids=[_request_key(r) for r in result.get("request_ids") or []],
        )
        return self._with_pending(
            dict(result),
            chain=chain,
            mech=priority_mech,
            service_id=service_id,
            offchain=not legacy_on_chain,
        )

    def _with_pending(
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
        delivered = {
            _request_key(rid): answer
            for rid, answer in (result.get("delivery_results") or {}).items()
        }
        ids = [_request_key(rid) for rid in result.get("request_ids") or []]
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
        # Re-key the ids mech-client returned: the on-chain flow 0x-prefixes
        # request_ids but not the delivery_results keys, so a caller handed
        # both raw sees one id spelled two ways and cannot match them up.
        payload = {"chain": chain, **result}
        if "request_ids" in result:
            payload["request_ids"] = ids
        if "delivery_results" in result:
            payload["delivery_results"] = delivered
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
        timeout = min(max(float(timeout), 1.0), MAX_DELIVERY_TIMEOUT)
        key = _request_key(request_id)
        with self._lock:
            pending = self._pending.get(key)
        if pending is None:
            raise MechError(
                f"nothing is awaiting delivery for request {key}; mech_result "
                "polls the ids mech_request reported as pending, and a restart "
                "of this service clears them"
            )
        service = self._service(pending.chain)
        try:
            delivered = asyncio.run(self._watch(service, pending, key, timeout))
        except Exception as e:
            raise MechError(f"could not read delivery for request {key}: {e}") from e
        data = {_request_key(k): v for k, v in (delivered or {}).items()}
        report = {
            "request_id": key,
            "chain": pending.chain,
            "mech": pending.mech,
            "delivered": key in data,
        }
        if key not in data:
            report["note"] = (
                "no delivery yet — the mech may still answer, or may never; "
                "poll again or treat the payment as spent"
            )
            return report
        with self._lock:
            self._pending.pop(key, None)
        self._activity.record("mech_result", chain=pending.chain, request_id=key)
        return {**report, "result": data[key]}

    @staticmethod
    async def _watch(
        service: MarketplaceService,
        pending: PendingDelivery,
        key: str,
        timeout: float,
    ) -> dict:
        """Run the watcher for the flow this request was sent through."""
        # pylint: disable=import-outside-toplevel, protected-access
        from mech_client.domain.delivery import (
            OffchainDeliveryWatcher,
            OnchainDeliveryWatcher,
        )

        if pending.offchain:
            url = service.tool_manager.get_offchain_url(pending.service_id)
            return await OffchainDeliveryWatcher(url, timeout).watch([key])
        contract = service._get_marketplace_contract()
        watcher = OnchainDeliveryWatcher(contract, service.ledger_api, timeout)
        return await watcher.watch([key], from_block=pending.from_block)

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
        fetch_info = service._fetch_mech_info  # pylint: disable=protected-access
        try:
            _, service_id, max_delivery_rate = fetch_info(priority_mech)
        except Exception as e:
            raise MechError(f"could not price mech {priority_mech}: {e}") from e
        return PricedMech(
            mech=priority_mech,
            service_id=int(service_id),
            rate_wei=int(max_delivery_rate),
        )
