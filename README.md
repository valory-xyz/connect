# pearl-connect

Pearl Connect agent. When a user starts the BYOA agent in
[Pearl](https://olas.network/pearl), the middleware runs this binary like any
other non-aea agent. It:

1. decrypts the agent EOA keystore (`./ethereum_private_key.txt`) in memory
   using the `--password` argument — key material never leaves the process;
2. populates the service's persistent workspace (`STORE_PATH`) with a
   `.mcp.json` (fresh bearer token every run), a `CLAUDE.md` context brief for
   the agent session, and the bundled `pearl-connect` skill;
3. serves on `127.0.0.1:8716`:
   - Pearl SDK contracts: `GET /healthcheck`, `GET /funds-status`, `GET /`
   - Settings: `GET /settings` (open) and `POST /settings`
     (keystore-password-authed, used by the `/` UI)
   - a bearer-authed signing surface: `POST /sign-and-send`,
     `POST /sign-message`, `GET /wallet`
   - MCP (streamable HTTP) at `/mcp` with tools `wallet_info`,
     `send_transaction`, `transaction_status`, `sign_message`,
     `mech_tools`, `mech_request`, `settings`;
4. opens a Claude Code session at the workspace via deep link — the
   `harness` setting picks which one to try first (`claude_code_desktop`
   → `claude://code/new?folder=…`, `claude_code_cli` →
   `claude-cli://open?cwd=…`; the other stays the fallback).

The agent-harness session composes on-chain actions (including service-safe
`execTransaction` calls via the threshold-1 pre-validated signature) and the
server signs and broadcasts them — a single audited choke point, no plaintext
secrets on disk.

## Guardrail

The signer enforces one of two persistent modes:

- **unrestricted** — any well-formed request is signed;
- **restricted** (default) — raw digest signing is off, and the only allowed
  transactions are EOA→safe native sweeps and safe `execTransaction` CALLs to
  whitelisted addresses with the gas-refund fields zeroed (a non-zero SafeTx
  `gasPrice` would pay a refund out of the safe past the whitelist). The
  MechMarketplace contract per chain (imported from
  the pinned mech-client) is whitelisted by default — the only contract the
  safe calls in the on-chain mech flow — so mech requests work out of the box.
  Balance trackers and payment tokens are deliberately not whitelisted: the
  whitelist is address-level (any calldata), so a token entry would permit
  arbitrary transfers, and the safe only calls trackers for prepaid deposits,
  an off-chain-flow (unrestricted-mode) concern.

There is a single gate with no bypass: the MCP tools, the HTTP signing
endpoints and the mech request flow all pass the same check. State persists in
`pearl-connect.settings.json` at STORE_PATH, HMAC'd with a key derived from
the agent private key and verified on every read — an edit by the agent (or
anything else without the key) fails verification and resets the file to the
restricted defaults. The MAC of the last file the server wrote is also pinned
in memory, so replaying an *old* validly-MAC'd settings file (say, captured
while the mode was unrestricted) fails the same way; only a replay staged
while the server is stopped escapes the pin. Operators change mode/whitelist in the agent UI at
`http://127.0.0.1:8716/`; the change is authenticated by re-decrypting the
keystore with the submitted password, not by the session's bearer token.

## Mech requests

The `mech_request` MCP tool drives [mech](https://olas.network/services/ai-mechs)
requests through mech-client's `Signer` protocol, so every transaction and
digest passes the guarded choke point. `legacy_on_chain=false` (default) uses
the off-chain prepaid flow (needs unrestricted mode; `auto_deposit` tops up
the prepaid balance from the safe on HTTP 402); `legacy_on_chain=true` sends
the request on-chain through the MechMarketplace via the service safe.

## Development

```bash
uv sync
uv run pytest -m "not integration"
```

Linting and CI checks mirror olas-operate-middleware (tomte toolchain via tox):

```bash
uv pip install "tomte[tox,cli]==0.7.0" tox-uv
tox -p -e flake8 -e pylint
tox -p -e black-check -e isort-check -e bandit -e safety -e mypy
tox -e unit-tests-coverage        # enforces 100% coverage
GNOSIS_TESTNET_RPC=<tenderly-fork-url> tox -e integration-tests
```

Run standalone (mimicking the Pearl runner):

```bash
export CONNECTION_LEDGER_CONFIG_LEDGER_APIS_GNOSIS_ADDRESS=<rpc-url>
export CONNECTION_CONFIGS_CONFIG_STORE_PATH=/path/to/persistent_data
export CONNECTION_CONFIGS_CONFIG_SAFE_CONTRACT_ADDRESSES='{"gnosis":"0x..."}'
export CONNECTION_CONFIGS_CONFIG_FUND_REQUIREMENTS='{"gnosis":{"agent":{"0x0000000000000000000000000000000000000000":"1000000000000000000"}}}'
# cwd must contain ethereum_private_key.txt (encrypted web3 keystore JSON)
uv run python -m pearl_connect --password <password>
```

## Olas packages

`packages/` holds the [Olas SDK](https://stack.olas.network/olas-sdk/) package
tree (mirroring `valory-xyz/olas-sdk-starter`):

- `packages/valory/agents/pearl_connect` — the agent blueprint (metadata; the
  runtime is the released binary)
- `packages/valory/services/pearl_connect` — the service package whose
  connection overrides define the env vars the binary consumes
  (`CONNECTION_LEDGER_CONFIG_LEDGER_APIS_<CHAIN>_ADDRESS`,
  `CONNECTION_CONFIGS_CONFIG_{SAFE_CONTRACT_ADDRESSES,STORE_PATH,FUND_REQUIREMENTS,LOG_LEVEL}`)
- `packages/packages.json` — pinned hashes (`dev` = ours, `third_party` =
  vendorable dependencies, synced on demand)

After changing a package: `autonomy packages sync && autonomy packages lock && autonomy push-all`
(requires `open-autonomy` + `open-aea-cli-ipfs`). Publishing to IPFS and
minting the agent blueprint/service on the Olas Registry follow the
[Pearl integration checklist](https://stack.olas.network/pearl/agent-integration-checklist/).

## Release

Publishing a GitHub release triggers `.github/workflows/release.yml`, which:

- verifies the package hashes (`autonomy packages lock --check`) and pushes
  `packages/` to the Olas IPFS registry (`autonomy push-all`), and
- builds PyInstaller binaries named `agent_runner_{linux,macos,windows}_{x64,arm64}`
  — the asset names Pearl's middleware downloads and sha256-verifies.
