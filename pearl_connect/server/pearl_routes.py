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

"""Pearl SDK endpoints: /healthcheck, /funds-status, and the / HTML page.

These are unauthenticated: the middleware's pollers have no token. They must
never expose the session token.
"""

import html
import logging
import time

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from pearl_connect import wallet, workspace

logger = logging.getLogger("agent")

router = APIRouter()

FUNDS_STATUS_CACHE_SECONDS = 30


@router.get("/healthcheck")
def healthcheck() -> dict:
    """Healthcheck.

    The middleware's HealthChecker reads only is_healthy
    """
    return {"is_healthy": True}


@router.get("/funds-status")
def funds_status(request: Request) -> dict:
    """Funds status."""
    cache = request.app.state.funds_cache  # per-app, created by create_app
    now = time.monotonic()
    with cache["lock"]:
        if now - cache["at"] < FUNDS_STATUS_CACHE_SECONDS:
            return cache["value"]
    try:
        value = wallet.funds_status(request.app.state.config, request.app.state.signer)
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("funds-status computation failed")
        return {}
    with cache["lock"]:
        cache["at"] = now
        cache["value"] = value
    return value


@router.get("/", response_class=HTMLResponse)
def index(request: Request) -> str:
    """Index."""
    state = request.app.state
    chains = state.config.chains
    safes_rows = "".join(
        f"<tr><td>{html.escape(name)}</td>"
        f"<td><code>{html.escape(c.safe_address or '—')}</code></td></tr>"
        for name, c in sorted(chains.items())
    )
    open_link = workspace.launch_order(state.config.store_path)[0]
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Pearl Connect</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 640px; color: #222; }}
 table {{ border-collapse: collapse; width: 100%; }}
 td, th {{ text-align: left; padding: .3rem .6rem; border-bottom: 1px solid #eee; }}
 code {{ font-size: .85em; }}
 .btn {{ display: inline-block; margin-top: 1rem; padding: .6rem 1.2rem; background: #111;
        color: #fff; border-radius: 8px; text-decoration: none; border: 0; cursor: pointer; }}
</style></head>
<body>
<h1>Pearl Connect</h1>
<p>BYOA agent powered by a Claude Code session. This server signs on the agent's
behalf; the Claude session never sees key material.</p>
<table>
<tr><th>Agent EOA</th><td><code>{html.escape(state.signer.address)}</code></td></tr>
<tr><th>Signer actions</th><td>{state.activity.count} this run</td></tr>
</table>
<h2>Service safes</h2>
<table>{safes_rows or "<tr><td>none configured</td></tr>"}</table>
<a class="btn" href="{html.escape(open_link)}">Open Claude Code</a>
</body></html>"""
