# Agent UI

The server mounts this directory at `/`. The `index.html` here is a **stand-in**
— a plain page that drives the endpoints below — and it keeps the agent usable
until the real UI is ready.

To integrate that UI: **replace the contents of this directory** with the build,
exactly as it is published (the layout Pearl's other agents use, e.g.
[trader's `ui-build/polystrat`](https://github.com/valory-xyz/trader/tree/main/packages/valory/skills/trader_abci/ui-build/polystrat)):

```
pearl_connect/assets/ui/
├── index.html          <- required: what the server serves at /
├── assets/             <- JS/CSS the build references
├── images/
└── favicon.ico
```

That is the whole integration. No code, packaging, or route changes:

- **Serving.** The directory is mounted at `/` and served as static files, so
  the build's own `index.html` and assets are what the operator gets.
- **Packaging.** The PyInstaller spec bundles all of `pearl_connect/assets`,
  so whatever lands here ships inside the binary.
- **Endpoints.** The API routes are registered before this mount and keep
  precedence, so the UI can never shadow them.

## What the UI can call

Same-origin `fetch` from this page, no token needed — the endpoints below are
open or origin-gated. The bearer token belongs to the Claude session and must
never be embedded in the UI.

| Endpoint | Purpose |
| --- | --- |
| `GET /settings` | current settings: `{"protected": {"mode", "whitelist"}, "harness"}` |
| `PATCH /settings` | merge-patch. The keystore password is required **only** when the body touches `protected` (mode/whitelist); a `harness`-only change needs none |
| `POST /session` | open a Claude Code session → `{launched, harness, error?}`. An optional `{"harness": …}` overrides the saved preference for that launch alone |
| `GET /healthcheck` | `{"is_healthy": bool}` — false until the workspace is provisioned |
| `GET /funds-status` | balances against the funding requirements |

`GET /wallet` and the signing routes require the bearer token and are **not**
for the UI.

## Conventions worth keeping

- Ask for the keystore password only when changing `protected`, and never
  store it. It is the one secret the agent session does not have, and it is
  what stops the agent from lifting its own guardrail.
- Show a failed `POST /session` (`launched: false`) as a dismissable error: a
  deep link that will not open is the operator's environment, not a server
  fault.
- Wait for `GET /healthcheck` to report healthy before offering to start a
  session — the server refuses with 503 until the workspace is ready.
