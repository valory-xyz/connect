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

"""Can this machine reach Polymarket? Answer it by trying, not by guessing.

    python netcheck.py

An earlier version compared the three API hosts' resolved addresses and
called it interception when they matched. They always match — Cloudflare
fronts all three from one anycast address — so it reported a network fault on
every healthy machine.

Resolved addresses cannot tell you whether a name was hijacked, so this does
not try to infer it: it resolves each host (information, never a verdict) and
then actually completes an HTTPS request, reporting which layer failed.
"""

import argparse
import json
import socket

import requests

HOSTS = (
    "clob.polymarket.com",
    "gamma-api.polymarket.com",
    "data-api.polymarket.com",
)

TIMEOUT = 15

# Only used to explain a shared address in the output, never to fail a host.
CLOUDFLARE_PREFIXES = ("172.64.", "104.16.", "104.17.", "104.18.", "2606:4700")

ESCALATE_TO_OPERATOR = (
    "report it to the operator; it is theirs to fix, and nothing in this "
    "skill can route around it"
)


def _resolve(host: str) -> dict:
    """Every address a host resolves to, or the resolver's error."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return {"addresses": [], "error": f"{type(e).__name__}: {e}"}
    return {"addresses": sorted({info[4][0] for info in infos}), "error": None}


def _probe(host: str) -> dict:
    """Complete a real HTTPS request and name the layer that failed, if any.

    Any HTTP status counts as reachable: a 403 proves TLS completed and the
    venue answered. Geoblocking surfaces as 403 too — the venue's policy, not
    a network fault, so it is deliberately reported as reachable.
    """
    try:
        response = requests.get(f"https://{host}/", timeout=TIMEOUT)
    except requests.exceptions.SSLError as e:
        return {"state": "tls_failed", "detail": str(e)}
    except requests.exceptions.Timeout as e:
        return {"state": "timeout", "detail": str(e)}
    except requests.exceptions.ConnectionError as e:
        return {"state": "unreachable", "detail": str(e)}
    except requests.exceptions.RequestException as e:
        return {"state": "error", "detail": f"{type(e).__name__}: {e}"}
    return {"state": "reachable", "status_code": response.status_code}


def _verdict(results: list) -> dict:
    """Turn the per-host outcomes into one conclusion and a next step."""
    states = {result["probe"]["state"] for result in results}
    if states == {"reachable"}:
        return {
            "ok": True,
            "conclusion": "Polymarket is reachable from this machine",
            "next_step": None,
        }
    if "tls_failed" in states:
        return {
            "ok": False,
            "conclusion": (
                "TLS did not complete. Far more often a missing local trust "
                "store than interception: a pyenv or source-built Python "
                "ships without CA certificates"
            ),
            "next_step": (
                'set the venv up through `eval "$(bash '
                'scripts/bootstrap_env.sh)"`, which exports SSL_CERT_FILE '
                "from certifi, before reporting a network problem"
            ),
        }
    if any(result["dns"]["error"] for result in results):
        return {
            "ok": False,
            "conclusion": "the hosts do not resolve — DNS is failing or filtered",
            "next_step": ESCALATE_TO_OPERATOR,
        }
    return {
        "ok": False,
        "conclusion": (
            "the hosts resolve but the connection never completes — the "
            "network is dropping or blocking traffic to Polymarket"
        ),
        "next_step": ESCALATE_TO_OPERATOR,
    }


def _shared_addresses(results: list) -> list:
    """Addresses more than one host resolves to."""
    counts: dict = {}
    for result in results:
        for address in result["dns"]["addresses"]:
            counts[address] = counts.get(address, 0) + 1
    return sorted(address for address, count in counts.items() if count > 1)


def check(hosts: tuple = HOSTS) -> dict:
    """Resolve and probe every host, then conclude."""
    results = [
        {"host": host, "dns": _resolve(host), "probe": _probe(host)} for host in hosts
    ]
    report: dict = {"hosts": results, **_verdict(results)}
    shared = _shared_addresses(results)
    if shared:
        behind_cdn = any(address.startswith(CLOUDFLARE_PREFIXES) for address in shared)
        report["shared_addresses_note"] = (
            f"these hosts share {', '.join(shared)} — that is normal "
            + (
                "(Cloudflare fronts all three)"
                if behind_cdn
                else "for hosts behind a single CDN"
            )
            + " and is NOT evidence of DNS interception"
        )
    return report


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    report = check()
    print(json.dumps(report, indent=2, default=str))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
