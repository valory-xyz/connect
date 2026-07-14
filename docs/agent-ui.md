# Agent UI

The server serves `pearl_connect/assets/ui/` at `/`. The `index.html` there is a
**stand-in** — a plain page that drives the endpoints below — and it keeps the
agent usable until the real UI is ready.

This document lives outside that directory on purpose: the integration is to
*replace the directory*, and a contract stored inside it would be deleted by the
first person who followed it.

## Integrating the real UI

**Replace the contents of `pearl_connect/assets/ui/`** with the build, exactly as
it is published (the layout Pearl's other agents use, e.g.
[trader's `ui-build/polystrat`](https://github.com/valory-xyz/trader/tree/main/packages/valory/skills/trader_abci/ui-build/polystrat)):

```
pearl_connect/assets/ui/
├── index.html          <- required: what the server serves at /
├── assets/             <- JS/CSS the build references
├── images/
└── favicon.ico
```

That is the whole integration — no code, packaging, or route changes:

- **Serving.** The directory is read into memory once at boot and served from
  there. Two consequences worth knowing:
  - **Every file in the directory is published**, at its path under `/`. A build
    that ships sourcemaps or a config file ships them to the operator too.
  - **There is no SPA history fallback.** `/` serves `index.html`; any other
    unknown path is a 404, *not* `index.html`. A build that uses browser-history
    routing will 404 on refresh and on deep links — use hash routing. (A client
    route named `/settings` would in any case be answered by the API, which
    keeps precedence.)
- **Packaging.** The PyInstaller spec bundles all of `pearl_connect/assets`, so
  whatever lands here ships inside the binary.
- **Endpoints.** The API routes are registered before the UI, which is a
  catch-all registered last, so the UI can never shadow them.

If the directory exists but has no `index.html`, the server logs a warning and
serves the API alone — in a packaged build that is a packaging bug, not a
configuration.

## What the UI can call

Same-origin `fetch` from this page, no token needed — the endpoints below are
open or origin-gated. The bearer token belongs to the Claude session and must
never be embedded in the UI.

| Endpoint | Purpose |
| --- | --- |
| `GET /settings` | current settings: `{"protected": {"mode", "whitelist"}, "harness"}` |
| `PATCH /settings` | merge-patch. The keystore password is required **only** when the body touches `protected`; a `harness`-only change needs none. **The whitelist is frozen:** a `whitelist` key in the patch is refused with a 422, password or not — send `protected: {mode}` alone |
| `POST /session` | open a Claude Code session → `{launched, harness, error?}`. An optional `{"harness": …}` overrides the saved preference for that launch alone |
| `GET /healthcheck` | `{"is_healthy": bool}` — false until the workspace is provisioned |
| `GET /funds-status` | balances against the funding requirements |

`GET /wallet` and the signing routes require the bearer token and are **not**
for the UI.

**Wallet addresses are Pearl's job, not this UI's.** The agent EOA and the
per-chain safes are shown by Pearl's own agent-wallet section, which is also
where funding happens. This page does not display them, and no endpoint it is
allowed to call exposes them.

### Error shapes

Both are `{"detail": …}`, but `detail` is not always a string:

- **4xx we raise** (401, 403, 503, and a 400 for an unknown mode) — `detail` is a
  plain string, safe to show.
- **422 from request validation** (a frozen `whitelist`, an unknown field) —
  `detail` is a *list* of pydantic error objects. Rendering it directly gives
  the operator `[object Object]`; read `msg` off each entry.

## Conventions worth keeping

- Ask for the keystore password only when changing `protected`, and never store
  it. It is the one secret the agent session does not have, and it is what stops
  the agent from lifting its own guardrail.
- Show a failed `POST /session` (`launched: false`) as a dismissable error: a
  deep link that will not open is the operator's environment, not a server
  fault.
- Wait for `GET /healthcheck` to report healthy before offering to start a
  session — the server refuses with 503 until the workspace is ready.
- Do not offer controls over state you have not read. If `GET /settings` fails,
  disable the forms rather than leaving a guardrail toggle live over nothing.
