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
    settings = state.settings_store.load()
    safes_rows = "".join(
        f"<tr><td>{html.escape(name)}</td>"
        f"<td><code>{html.escape(c.safe_address or '—')}</code></td></tr>"
        for name, c in sorted(chains.items())
    )
    whitelist_lines = (
        "\n".join(
            f"{html.escape(chain)}:{html.escape(address)}"
            for chain, addresses in sorted(settings.protected.whitelist.items())
            for address in addresses
        )
        or "none"
    )
    checked = {True: "checked", False: ""}
    restricted = settings.protected.mode == "restricted"
    desktop = settings.harness == "claude_code_desktop"
    open_link = workspace.launch_order(state.config.store_path, settings.harness)[0]
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
 .mode {{ font-weight: 600; text-transform: capitalize; }}
 pre {{ background: #f6f6f6; padding: .6rem; border-radius: 6px; font-size: .85em;
       overflow-x: auto; }}
 input[type=password] {{ width: 100%; }}
 #settings-result {{ margin-top: .5rem; }}
</style></head>
<body>
<h1>Pearl Connect</h1>
<p>BYOA agent powered by a Claude Code session. This server signs on the agent's
behalf; the Claude session never sees key material.</p>
<table>
<tr><th>Agent EOA</th><td><code>{html.escape(state.signer.address)}</code></td></tr>
<tr><th>Guardrail mode</th><td class="mode">{html.escape(settings.protected.mode)}</td></tr>
<tr><th>Harness</th><td><code>{html.escape(settings.harness)}</code></td></tr>
<tr><th>Signer actions</th><td>{state.activity.count} this run</td></tr>
</table>
<h2>Service safes</h2>
<table>{safes_rows or "<tr><td>none configured</td></tr>"}</table>
<h2>Guardrail settings</h2>
<p>In <em>restricted</em> mode the agent can only sweep funds into its safes and
have a safe call whitelisted addresses; raw digest signing is off. Changing
settings requires the keystore password — the agent session does not have it.</p>
<form id="settings-form">
<p><label><input type="radio" name="mode" value="restricted" {checked[restricted]}>
Restricted</label>
   <label><input type="radio" name="mode" value="unrestricted" {checked[not restricted]}>
Unrestricted</label></p>
<p>Whitelisted targets (not editable yet):</p>
<pre>{whitelist_lines}</pre>
<p><label>Keystore password<br><input type="password" name="password" autocomplete="off"></label></p>
<button class="btn" type="submit">Apply</button>
<div id="settings-result"></div>
</form>
<h2>Harness</h2>
<p>Which Claude Code the workspace session opens in — a preference, saved
without the password.</p>
<form id="harness-form">
<p><label><input type="radio" name="harness" value="claude_code_desktop" {checked[desktop]}>
Claude Code desktop</label>
   <label><input type="radio" name="harness" value="claude_code_cli" {checked[not desktop]}>
Claude Code CLI</label></p>
<button class="btn" type="submit">Apply</button>
<div id="harness-result"></div>
</form>
<script>
async function applySettingsPatch(resultId, payload) {{
  const result = document.getElementById(resultId);
  result.textContent = "applying…";
  try {{
    const response = await fetch("/settings", {{
      method: "PATCH",
      headers: {{"Content-Type": "application/json"}},
      body: JSON.stringify(payload),
    }});
    if (response.ok) {{
      result.textContent = "saved";
      location.reload();
    }} else {{
      const body = await response.json().catch(() => ({{}}));
      result.textContent = "error: " + (body.detail || response.status);
    }}
  }} catch (err) {{
    result.textContent = "error: " + err;
  }}
}}
document.getElementById("settings-form").addEventListener("submit", async (e) => {{
  e.preventDefault();
  const form = e.target;
  await applySettingsPatch("settings-result", {{
    password: form.password.value,
    protected: {{mode: form.mode.value}},
  }});
}});
document.getElementById("harness-form").addEventListener("submit", async (e) => {{
  e.preventDefault();
  await applySettingsPatch("harness-result", {{harness: e.target.harness.value}});
}});
</script>
<a class="btn" href="{html.escape(open_link)}">Open Claude Code</a>
</body></html>"""
