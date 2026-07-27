# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pearl BYOA agent server: a localhost FastAPI binary (`127.0.0.1:8716`) that the Pearl middleware runs so a Claude Code session can act as an Olas Pearl agent — signing and broadcasting on-chain actions as the service safe — without ever touching key material. The Claude session names actions (via MCP tools or HTTP endpoints); this server signs and broadcasts them through a single guarded choke point.

Note: `connect/assets/CLAUDE.md` is a **shipped asset** — the context brief written into the agent's workspace (STORE_PATH) at runtime. It is not instructions for this repo.

## Keep docs in sync

CLAUDE.md and README.md must be kept updated with any change in the repo — they must not drift in any commit. If a change alters behavior, commands, architecture, endpoints, guardrail semantics, or dependencies described in either file, update that file in the same commit.

## Commands

```bash
uv sync                                     # install deps (uv-managed venv)
uv run pytest -m "not integration"          # unit tests
uv run pytest tests/test_endpoints.py -k <name>   # single test
tox -e unit-tests-coverage                  # unit tests, enforces 100% coverage
GNOSIS_TESTNET_RPC=<tenderly-fork-url> tox -e integration-tests
```

Lint suite (tomte toolchain, mirrors olas-operate-middleware; install once with `uv pip install "tomte[tox,cli]==0.7.0" tox-uv`):

```bash
tox -p -e flake8 -e pylint -e black-check -e isort-check -e bandit -e safety -e mypy -e check-copyright
tox -e black -e isort                       # auto-format
tox -e fix-copyright                        # fix copyright headers (CI checks them)
```

If you change anything under `packages/`: `autonomy packages lock` (CI verifies the pinned hashes in `packages/packages.json`).

Run standalone (mimicking the Pearl runner) — see README "Development" for the required `CONNECTION_*` env vars; cwd must contain `ethereum_private_key.txt`, then `uv run python -m connect --password <password>`.

## Constraints CI enforces

- **100% test coverage** on `connect/` (bundled skills under `connect/assets/skills/` are omitted — they run in the agent's environment, not the server's, and have their own tests).
- mypy with `--disallow-untyped-defs`; `connect/assets/skills/connect-polymarket/` is excluded (depends on `py_clob_client_v2`, not a repo dep).
- flake8 includes docstring rules (D) and pytest style (PT); every module/function needs a docstring.
- Copyright headers (Valory AG, Apache 2.0) on every source file — `tox -e fix-copyright` adds them.
- `packages/valory/connections/`, `packages/valory/protocols/`, `packages/open_aea/` are vendored third-party code, excluded from all linters — don't edit or reformat them.

## Architecture

The security architecture is the thing to understand first: **every signing path funnels through one gate with no bypass.** MCP tools, HTTP signing endpoints, and the mech request flow all reduce to `Signer.send()` / `Signer.sign_digest()` (`connect/signer.py`), and every request passes the guardrail in `connect/guard.py` before signing. Two invariants hold in every mode and no setting lifts them: the safe may not `delegatecall`, and the safe may not call itself. On that floor sit two persistent modes: **unrestricted** (default) and **restricted** (operator opt-in via the UI: only safe `execTransaction` CALLs to whitelisted addresses, gas-refund fields zeroed, no raw digest signing — except single-use allowances the mech flow registers for the safe's ERC-1271 wrap of off-chain request ids it derived locally and for the one capped safe→tracker deposit a 402 top-up would send). The modes are an operator concept only — agent-facing surfaces (MCP tools, `/wallet`, the workspace brief and skills, guard refusal messages) deliberately never mention that modes exist; `EXPOSE_MODE_TO_AGENT` in `connect/settings.py` is the one switch that turns the agent-visible mode readouts back on. The reasoning is documented at the top of `guard.py`.

Core modules:

- `connect/__main__.py` — entrypoint; decrypts the keystore (`connect/keystore.py`) in memory, provisions the workspace, starts the server.
- `connect/workspace.py` — provisions STORE_PATH (the Claude session's cwd): writes `.mcp.json` with a fresh per-run bearer token, the `CLAUDE.md` brief, and copies the bundled skills from `connect/assets/skills/`.
- `connect/signer.py` — the single signing choke point.
- `connect/guard.py` — the guardrail; one gate for every signing path.
- `connect/safe.py` — the only place that knows what an `execTransaction` looks like. The agent names an inner call (target, value, calldata); the server wraps it in the safe's `execTransaction` with a threshold-1 pre-validated signature.
- `connect/settings.py` — tamper-evident settings persisted in STORE_PATH. Security-critical fields (mode, whitelist) are HMAC'd with a key derived from the agent private key; a failed verification resets them to the (unrestricted) defaults — deliberate and audited, see the module docstring for the reasoning. The last-written MAC is also pinned in memory to defeat replay of old settings files. The `harness` preference sits outside the MAC deliberately (it can't move funds).
- `connect/mech.py` — mech marketplace requests via mech-client's `Signer` protocol, so every transaction/digest still passes the choke point.
- `connect/config.py` — the only module that reads env vars (`CONNECTION_*`, injected by Pearl from the service template).
- `connect/activity.py` — audit trail of every signer action + `agent_performance.json` (Pearl SDK contract file).
- `connect/wallet.py` — balance queries shared by `/funds-status`, `/wallet`, and the `wallet_info` MCP tool.

Server (`connect/server/`):

- `app.py` — FastAPI application factory; also serves the bundled UI from `connect/assets/ui` (read into memory at boot).
- `auth.py` — bearer-token auth, Origin/Host validation, auth-failure rate limiting. The localhost bind is *not* trusted: any browser page can hit localhost, so every fund-moving or guardrail-changing route needs the bearer token (or the keystore password for protected settings). Only `POST /session` and the harness half of `PATCH /settings` are origin-gated without a token — deliberately, because they can't move funds.
- `pearl_routes.py` — Pearl SDK contracts (`/healthcheck`, `/funds-status`); `is_healthy` flips true only once the workspace is populated.
- `signer_routes.py` / `settings_routes.py` — HTTP signing surface and settings.
- `mcp_tools.py` — MCP (streamable HTTP) at `/mcp`; thin adapters over signer/wallet. The MCP SDK calls sync tools inline on the event loop, so blocking bodies are pushed to worker threads.

Other trees:

- `connect/assets/skills/` — skills bundled into the agent workspace (`pearl-connect`, `connect-polymarket`). These run in the agent's environment, not the server process: excluded from coverage and (for connect-polymarket) mypy; tested by `tests/test_connect_polymarket_skill.py` and `tests/test_connect_polymarket_sdk.py`.
- `packages/` — Olas SDK package tree (agent blueprint + service package defining the env-var overrides). After changing: `autonomy packages sync && autonomy packages lock && autonomy push-all`.
- `packaging/pyinstaller.spec` — release binaries are built by `.github/workflows/release.yml` on a GitHub release.

## Dependency quirks

- `[tool.uv] override-dependencies` pins fastapi past mech-client's transitive `fastapi<0.118` pin (operate paths in mech-client never run here). This is why the pylint/test tox envs use `uv sync` in `commands_pre` instead of a normal package install — pip can't honor the override.
- pytest runs with `-p no:anchorpy` (a transitive plugin whose own deps aren't installed).
