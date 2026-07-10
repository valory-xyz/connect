# pearl-connect

Pearl Connect agent. When a user starts the BYOA agent in
[Pearl](https://olas.network/pearl), the middleware runs this binary like any
other non-aea agent. It:

1. decrypts the agent EOA keystore (`./ethereum_private_key.txt`) in memory
   using the `--password` argument — key material never leaves the process;
2. serves on `127.0.0.1:8716`:
   - Pearl SDK contracts: `GET /healthcheck`, `GET /funds-status`, `GET /`
   - a bearer-authed signing surface: `POST /sign-and-send`,
     `POST /sign-message`, `GET /wallet`

The agent-harness session composes on-chain actions (including service-safe
`execTransaction` calls via the threshold-1 pre-validated signature) and the
server signs and broadcasts them — a single audited choke point, no plaintext
secrets on disk. The MCP surface, workspace provisioning, guardrail and mech
integration land in the stacked follow-up PRs.

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
