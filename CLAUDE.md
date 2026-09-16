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

Run standalone (mimicking the Pearl runner) — see README "Development" for the required `CONNECTION_*` env vars; cwd must contain `ethereum_private_key.txt`, then `uv run python -m connect --password-stdin` (password on stdin until EOF, docker-style, one trailing newline stripped; legacy `--password <password>` still works but leaks into `/proc/<pid>/cmdline`).

## Constraints CI enforces

- **100% test coverage** on `connect/`, including the shared agent-runtime modules under `connect/assets/lib/`. Only the bundled skills under `connect/assets/skills/` are omitted: they run in the agent's environment, not the server's, and have their own tests.
- mypy with `--disallow-untyped-defs`; `connect/assets/skills/connect-polymarket/` is excluded (depends on `py_clob_client_v2`, not a repo dep). `connect/assets/lib/` is excluded from the *scan* but sits on `mypy_path` and is still fully checked as an import of the skill scripts — without the exclude mypy resolves it under two module names and halts.
- flake8 includes docstring rules (D) and pytest style (PT); every module/function needs a docstring.
- Copyright headers (Valory AG, Apache 2.0) on every source file — `tox -e fix-copyright` adds them.
- `packages/valory/connections/`, `packages/valory/protocols/`, `packages/open_aea/` are vendored third-party code, excluded from all linters — don't edit or reformat them.

## Architecture

The security architecture is the thing to understand first: **every signing path funnels through one gate with no bypass.** MCP tools, HTTP signing endpoints, and the mech request flow all reduce to `Signer.send()` / `Signer.sign_digest()` (`connect/signer.py`), and every request passes the guardrail in `connect/guard.py` before signing. Two invariants hold in every mode and no setting lifts them: the safe may not `delegatecall`, and the safe may not call itself. On that floor sit two persistent modes: **unrestricted** (default) and **restricted** (operator opt-in via the UI: only safe `execTransaction` CALLs to whitelisted addresses, gas-refund fields zeroed, no raw digest signing — except single-use allowances the mech flow registers for the safe's ERC-1271 wrap of off-chain request ids it derived locally and for the one capped safe→tracker deposit a 402 top-up would send). The modes are an operator concept only — agent-facing surfaces (MCP tools, `/wallet`, the workspace brief and skills, guard refusal messages) deliberately never mention that modes exist; `EXPOSE_MODE_TO_AGENT` in `connect/settings.py` is the one switch that turns the agent-visible mode readouts back on. The reasoning is documented at the top of `guard.py`.

Core modules:

- `connect/__main__.py` — entrypoint; decrypts the keystore (`connect/keystore.py`) in memory, provisions the workspace, starts the server.
- `connect/workspace.py` — provisions STORE_PATH (the Claude session's cwd): writes `.mcp.json` with a fresh per-run bearer token, the `CLAUDE.md` brief, copies the bundled skills from `connect/assets/skills/` and the shared modules they import from `connect/assets/lib/` into `.claude/lib/`. A bundle missing either is a broken bundle: provisioning fails and the server reports itself unhealthy. It also opens the session, and does so through `harness_env()`, which strips the dynamic-loader variables our PyInstaller packaging leaks (`LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH` + their `_ORIG` twins, `_PYI_*`) — left in, our bundled OpenSSL shadows the system one and every node-based hook and MCP server in the session fails, the MCP servers silently. See the `LOADER_ENV_VARS` comment.
- `connect/signer.py` — the single signing choke point. Its per-chain Web3 clients sit on `RotatingHTTPProvider` (the `open-aea-ledger-ethereum` plugin), built without a `chain_id` so chainlist.org enrichment stays off — `test_rpc_pool_is_built_without_a_chain_id` in `tests/test_extras.py` carries the reasoning and enforces it. What it buys is retry for the methods web3 does not already cover: a bare `HTTPProvider` retries the 43 in `REQUEST_RETRY_ALLOWLIST`, so the gain is the rest — `eth_feeHistory`, on the EIP-1559 fee path of every send. It buys nothing for writes. `eth_sendRawTransaction` is on web3's allowlist, so the pooled inner provider re-broadcasts before the outer write rule is ever reached (measured: one 503, two sends, on a bare and a rotating provider alike), and a post-send read timeout classifies as `connection` in `CONNECTION_SIGNALS` — so "retried only on clear pre-send failures" is not true of the stack as shipped. The bytes are identical, so a re-broadcast cannot double-spend; what it can do is surface a transaction that landed as failed, via "already known" or "nonce too low". That covers this pool only: mech-client builds its own `EthereumApi`, which always passes a `chain_id`, so the mech flow does reach chainlist. `parse_rpc_urls` means a comma-separated address would rotate here, but `mech.py` and `wallet.py` hand the same string to single-URL consumers — so that form is unsupported until they agree.
- `connect/guard.py` — the guardrail; one gate for every signing path. `check_transaction` takes `consume=False` so a dry run can ask without spending an allowance (README, "Guardrail").
- `connect/safe.py` — the only place that knows what an `execTransaction` looks like. The agent names an inner call (target, value, calldata); the server wraps it in the safe's `execTransaction` with a threshold-1 pre-validated signature.
- `connect/settings.py` — tamper-evident settings persisted in STORE_PATH. Security-critical fields (mode, whitelist) are HMAC'd with a key derived from the agent private key; a failed verification resets them to the (unrestricted) defaults — deliberate and audited, see the module docstring for the reasoning. The last-written MAC is also pinned in memory to defeat replay of old settings files. The `harness` preference sits outside the MAC deliberately (it can't move funds).
- `connect/mech.py` — mech marketplace requests via mech-client's `Signer` protocol, so every transaction/digest still passes the choke point. An optional caller-chosen `request_id` makes a request replayable, and an optional `request_context` dict rides along in the request metadata for the tool (README, "Mech requests"). `_metadata_extras` builds those extras once so the off-chain digest and mech-client hash the same bytes; `_request_stamp` covers the context too, since the same prompt with a different market price is a different question.
- `connect/mech_allowances.py` — the single-use grants that flow registers with the guard before it signs or spends: the safe's ERC-1271 wrap of a request id it derived locally (trusting no RPC for anything signed) and the one capped safe→tracker deposit a 402 top-up would send. Split out of `mech.py`, which was over pylint's 1000-line limit; the seam is real, and `MechService` no longer holds the guard at all — this is its whole relationship with it.
- `connect/mech_budget.py` — the default `max_payment` per mech-client `PaymentType` (0.1 of the payment asset) and the token each type is paid in on a chain, which `mech_tools` reports as `payment_token`. Split out of `mech.py` for the same line limit.
- `connect/mech_rpc.py` — mech-client reads the RPC from the process-global `MECHX_CHAIN_RPC` (valory-xyz/mech-client#247), so `RPC_LOCK` serialises the places that must set it: building a chain's service, and just before a request is sent, because an auto-deposit rebuilds a mech-client service mid-send. Listing never sets it or takes the lock — a subgraph query can run for minutes — and only reads it for a chain-id check, so `listing_mechs()` drops the stale-RPC warning that check raises, for that thread only.
- `connect/mech_types.py` — the error and shapes `mech.py` and `mech_allowances.py` share, in neither of them so the pair does not import in a circle. `from connect.mech import MechError` still resolves.
- `connect/idempotency.py` — at-most-once execution keyed by caller-chosen request ids, for actions paid for before they are answered; `mech.py` is the only user, and `signer.py` keeps its own simpler cache mapping ids to tx hashes. Its entries hold a whole report plus a stamp of what was asked, because a replay has to resume a watch rather than repeat a value, and a reused id must not answer a different question.
- `connect/config.py` — the only module that reads env vars *as configuration* (`CONNECTION_*`, injected by Pearl from the service template); `workspace.harness_env()` touches the environment only to scrub it on the way out.
- `connect/activity.py` — audit trail of every signer action + `agent_performance.json` (Pearl SDK contract file).
- `connect/wallet.py` — balance queries shared by `/funds-status`, `/wallet`, and the `wallet_info` MCP tool.

Server (`connect/server/`):

- `app.py` — FastAPI application factory; also serves the bundled UI from `connect/assets/ui` (read into memory at boot).
- `auth.py` — bearer-token auth, Origin/Host validation, auth-failure rate limiting. The localhost bind is *not* trusted: any browser page can hit localhost, so every fund-moving or guardrail-changing route needs the bearer token (or the keystore password for protected settings). Only `POST /session` and the harness half of `PATCH /settings` are origin-gated without a token — deliberately, because they can't move funds.
- `pearl_routes.py` — Pearl SDK contracts (`/healthcheck`, `/funds-status`); `is_healthy` flips true only once the workspace is populated.
- `signer_routes.py` / `settings_routes.py` — HTTP signing surface and settings.
- `mcp_tools.py` — MCP (streamable HTTP) at `/mcp`; thin adapters over signer/wallet. The MCP SDK calls sync tools inline on the event loop, so blocking bodies are pushed to worker threads.

Other trees:

- `connect/assets/skills/` — skills bundled into the agent workspace (`pearl-connect`, `connect-polymarket`, `connect-stocktokens`). These run in the agent's environment, not the server process: excluded from coverage and (for connect-polymarket) mypy; tested by `tests/test_connect_polymarket_skill.py`, `tests/test_connect_polymarket_sdk.py` and `tests/test_connect_stocktokens_skill.py`. `connect-stocktokens` trades Robinhood Chain Stock Tokens by quoting every Uniswap v2/v3/v4 pool it can discover from the factories and encoding the Universal Router call itself — no routing API, no API key. The chain- and venue-generic half lives in `connect/assets/lib/` (`evm.py`, `uniswap.py` with addresses and CREATE2 init-code hashes in `DEPLOYMENTS` keyed by chain id, `permit.py`, and `bootstrap_env.sh`, the workspace-venv builder both trading skills wrap with their own package list), which `workspace.py` installs to `.claude/lib/` next to the skills; the skill keeps only what is Robinhood — the registry, the reference price and the multiplier that reconciles them, read from the token contract's `uiMultiplier()` at trade time rather than from the REST registry. Skill modules reach the library through `sys.path`, the same way they reach `pearl-connect`. Its swap inputs carry an undocumented `uint256[] minHopPriceX36` the deployed router expects; without it the call reverts with `SliceOutOfBounds()`. Parity against Uniswap's own Trading API is pinned by golden calldata fixtures in the tests. Hook-less pools are the only v4 pools enumerable without an indexer, so `swap.py` also checks its best quote against Robinhood's own REST price and refuses past 150 bps — the floor alone cannot catch a dislocated pool, because the floor is derived from the same quote. A buy is two safe calls, not three: the router's Permit2 allowance rides inside the swap as an ERC-1271 permit the safe signs (`permit.py` wraps the Permit2 digest in the safe's own `SafeMessage`, which is what its fallback handler verifies), and `--separate-approvals` falls back to an on-chain approval when digest signing is refused. Both the swap calldata and the signed permit are decoded and checked against the plan before either reaches the signer, each call is confirmed before the next is sent, and a quote only scores zero when the pool itself reverts — a timeout, an empty read or a missing deployment address propagates, because an empty market and a broken endpoint must not look alike. The slippage floor is a fraction of the quote, never of Robinhood's reference: the reference drives the two-sided gap refusal instead, so a reference that breaks downward cannot quietly remove the protection. MultiSend is not an option for batching — the guard floor refuses delegatecall.
- `packages/` — Olas SDK package tree (agent blueprint + service package defining the env-var overrides). After changing: `autonomy packages sync && autonomy packages lock && autonomy push-all`.
- `packaging/pyinstaller.spec` — release binaries are built by `.github/workflows/release.yml` on a GitHub release.

## Dependency quirks

- `open-aea-ledger-ethereum` is pinned direct, though mech-client already resolved it at the same version. Importing mech-client already loads the `aea` core and this plugin, so the pin costs no modules in the process or the bundle; it only stops a transitive bump from moving it. The mypy env silences the import rather than installing it: the package ships `py.typed`, but installing it drags in a real `web3` too, which un-silences `[mypy-web3.*]` across the whole tree.
- `mech-client` is pinned at `0.23.0`, the first release that lists Robinhood Chain's mechs (its marketplace indexer is a squid, which 0.22.x could not query). `0.22.0` was the first carrying the `deliveries`/`DeliveryResult` shape `connect/mech.py` reads. `mech_request`'s default `max_payment` is 0.1 of the mech's payment asset, keyed by mech-client's `PaymentType` (`DEFAULT_MAX_PAYMENT` in `connect/mech_budget.py`), so a payment type added upstream is refused until it gets a default.
- `[tool.uv] override-dependencies` pins fastapi past mech-client's transitive `fastapi<0.118` pin (operate paths in mech-client never run here). This is why the pylint/test tox envs use `uv sync` in `commands_pre` instead of a normal package install — pip can't honor the override.
- pytest runs with `-p no:anchorpy` (a transitive plugin whose own deps aren't installed).
