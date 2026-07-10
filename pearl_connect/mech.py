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

from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig
from pearl_connect.guard import Guard, GuardError
from pearl_connect.signer import Signer, SignerError

logger = logging.getLogger("agent")

DEFAULT_MECH_CHAIN = "gnosis"
DEFAULT_DELIVERY_TIMEOUT = 300.0
MAX_DELIVERY_TIMEOUT = 3600.0  # a tool call must not pin its worker forever
DEFAULT_MECH_PAGE_SIZE = 20
MAX_MECH_PAGE_SIZE = 100


class MechError(Exception):
    """A mech request failure with an agent-facing message."""


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
        self._services: dict[str, t.Any] = {}

    def _service(self, chain: str) -> t.Any:
        """Lazily build the MarketplaceService for a configured chain."""
        # pylint: disable=import-outside-toplevel
        from eth_typing import URI
        from mech_client.services.marketplace_service import MarketplaceService
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
                # ~/.operate) — hence the construction lock.
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
        chain: str = DEFAULT_MECH_CHAIN,
        priority_mech: str | None = None,
        limit: int = DEFAULT_MECH_PAGE_SIZE,
        offset: int = 0,
    ) -> dict:
        """Discover live mechs (paginated), or the tool list of one mech.

        The tool list comes from the mech's on-chain metadata via the IPFS
        gateway, which can be slow — a failed fetch degrades to a note instead
        of an error, mirroring mech-client's own best-effort tool validation.
        """
        if priority_mech is None:
            self._config.chain(chain.lower())
            return self._list_mechs(chain.lower(), limit=limit, offset=offset)
        service = self._service(chain)
        # no public single-mech info API in mech-client yet; the protected
        # helper is the same one send_request() uses internally
        fetch_info = service._fetch_mech_info  # pylint: disable=protected-access
        payment_type, service_id, max_delivery_rate = fetch_info(priority_mech)
        info: dict = {
            "mech": priority_mech,
            "payment_type": payment_type.name,
            "service_id": service_id,
            "max_delivery_rate": str(max_delivery_rate),
        }
        try:
            tools_info = service.tool_manager.get_tools(service_id)
        except Exception as e:  # pylint: disable=broad-exception-caught
            tools_info = None
            logger.warning("tool metadata fetch failed for %s: %s", priority_mech, e)
        if tools_info and tools_info.tools:
            info["tools"] = [t.tool_name for t in tools_info.tools]
        else:
            info["tools_note"] = (
                "tool metadata is unavailable (IPFS gateway slow or none "
                "published); mech_request validates tools best-effort, so a "
                "known tool name can still be used"
            )
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
        except Exception as e:
            raise MechError(f"could not list mechs for '{chain}': {e}") from e
        return {
            "mechs": [
                {
                    "address": m["address"],
                    "service_id": m.get("service", {}).get("id"),
                    "total_deliveries": int(m["totalDeliveriesTransactions"]),
                    "mech_type": m.get("mech_type"),
                }
                for m in mechs[offset : offset + limit]
            ],
            "total": len(mechs),
            "offset": offset,
            "limit": limit,
            "note": (
                "call mech_tools with priority_mech=<address> for a mech's "
                "payment type and tool list; page with limit/offset"
            ),
        }

    def request(  # pylint: disable=too-many-arguments
        self,
        prompt: str,
        tool: str,
        *,
        chain: str = DEFAULT_MECH_CHAIN,
        legacy_on_chain: bool = False,
        priority_mech: str | None = None,
        auto_deposit: bool = True,
        timeout: float = DEFAULT_DELIVERY_TIMEOUT,
    ) -> dict:
        """Send one mech request and wait for its delivery.

        ``legacy_on_chain=False`` (default) uses the off-chain prepaid flow;
        ``True`` sends the request on-chain through the marketplace.
        """
        timeout = min(max(float(timeout), 1.0), MAX_DELIVERY_TIMEOUT)
        if not legacy_on_chain:
            # Same rule the signer enforces, surfaced before any work happens
            # (the off-chain flow raw-signs the request-id digest).
            try:
                self._guard.check_sign_digest()
            except GuardError as e:
                raise MechError(
                    f"off-chain mech requests are restricted: {e}; retry with "
                    "legacy_on_chain=true to send the request on-chain"
                ) from e
        service = self._service(chain)
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
        )
        return dict(result)
