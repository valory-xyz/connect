# connect

Pearl Connect agent. When a user starts the BYOA agent in
[Pearl](https://olas.network/pearl), the middleware runs this binary like any
other non-aea agent. It:

1. decrypts the agent EOA keystore (`./ethereum_private_key.txt`) in memory
   using the keystore password — read from stdin until EOF with
   `--password-stdin` (docker-style, one trailing newline stripped;
   preferred: argv is world-readable via `/proc/<pid>/cmdline` on Linux) or
   from the legacy `--password` argument — key material never leaves the
   process;
2. populates the service's persistent workspace (`STORE_PATH`) with a
   `.mcp.json` (fresh bearer token every run), a `CLAUDE.md` context brief for
   the agent session, and the bundled `connect` skill;
3. serves on `127.0.0.1:8716`:
   - Pearl SDK contracts: `GET /healthcheck` and `GET /funds-status`.
     `is_healthy` turns true only once the workspace is populated — Pearl
     opens the session the moment it does, so health is a promise the server
     has to be able to keep
   - the agent UI at `GET /`: the bundled build in `connect/assets/ui`,
     read into memory at boot and served from there. It ships a stand-in page
     (settings, harness, open a session — everything it shows comes from
     `GET /settings`); see [docs/agent-ui.md](docs/agent-ui.md)
   - Settings: `GET /settings` (open) and `PATCH /settings` (merge-patch of
     the canonical shape; the keystore password gates the `protected`
     object — currently the mode; the whitelist is read-only until its
     editing semantics are specced — while the `harness` preference needs none)
   - `POST /session` (origin-gated, no token): opens a Claude Code session in
     the configured harness (`claude_code_desktop` →
     `claude://code/new?folder=…`, `claude_code_cli` →
     `claude-cli://open?cwd=…`) and answers
     `{launched, harness, requested, error?}` — `harness` is the one that
     opened, `requested` the one it aimed for. An optional `{"harness": …}`
     body overrides the saved preference for that launch alone, without
     rewriting what the operator chose
   - a bearer-authed signing surface: `POST /safe-transaction`,
     `POST /sign-and-send`, `POST /sign-message`, `GET /wallet`
   - MCP (streamable HTTP) at `/mcp` with tools `wallet_info`,
     `safe_transaction`, `send_transaction`, `preflight_transaction`,
     `transaction_status`,
     `sign_message`, `mech_tools`, `mech_request`, `mech_result` (plus a
     read-only `settings` tool when `EXPOSE_MODE_TO_AGENT` is on).

The binary opens no session itself: Pearl waits for `is_healthy`, then calls
`POST /session`. A launch failure (harness not installed, deep link unhandled)
then reaches the operator's UI as a dismissable error instead of dying in this
process's log. Neither Pearl nor the UI names a harness, so those launches
start at the saved preference — until an operator changes it, only our default
guess — and fall back to the other Claude Code rather than leave them with no
session at all. A launch that *does* name one opens there or not at all:
naming a harness is a choice.

What the session must *not* inherit is our own packaging. We ship as a
PyInstaller one-file binary, whose bootloader puts its extraction directory at
the front of `LD_LIBRARY_PATH` — and that directory carries our
`libcrypto.so.3`, built against an older OpenSSL than a modern distro's. A
session started with it cannot run the system `node`, so every node-based hook
and MCP server dies: the hooks noisily, the MCP servers by silently never
appearing in the tool list. So the deep link is handed off with
`LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, their `_ORIG` twins and the `_PYI_*`
variables stripped. Restoring `LD_LIBRARY_PATH_ORIG`, PyInstaller's usual
advice, is wrong here: under Pearl that variable names the middleware's private
lib dir, carrying the same old libcrypto — the child needs these gone, not
restored. An operator who genuinely needs one of them can set it back for the
session in the workspace's `.claude/settings.json`, which we merge into rather
than own.

The agent-harness session names the actions; the server signs and broadcasts
them — a single audited choke point, no plaintext secrets on disk. The agent
acts *as the service safe*: it is the `msg.sender` contracts see, and approvals,
swaps, stakes, transfers, etc. are all calls it makes. The session never composes
one, though — it names the inner call (`safe_transaction`, `POST
/safe-transaction`) and the server wraps it in the safe's `execTransaction`,
threshold-1 pre-validated signature and all. Nothing about the safe — its
address, its ABI, its signature convention — is the session's problem.

## Guardrail

Two rules hold in **every** mode, and no setting lifts them: the safe may not
`delegatecall`, and the safe may not call itself (`enableModule`,
`addOwnerWithThreshold`, `setGuard` — the ways a Safe changes what it *is*).
Both would outlive a switch back to restricted mode, so the guardrail refuses
them regardless of mode; the reasoning lives at the top of `connect/guard.py`.

On that floor, the signer enforces one of two persistent modes. The modes are
an operator concept only: agent-facing surfaces (the MCP tools, `GET /wallet`,
the workspace brief and bundled skills, and every guard refusal message)
deliberately never say a mode system exists — a blocked request names only the
rule it violated and that the operator's guardrail settings are where to
change it. Flipping `EXPOSE_MODE_TO_AGENT` in `connect/settings.py` restores
the agent-visible mode readouts (`mode` in `wallet_info`/`GET /wallet` and the
`settings` MCP tool).

- **unrestricted** (default) — any other well-formed request is signed;
- **restricted** (operator opt-in) — raw digest signing is off, with one
  carve-out: the mech flow recomputes the off-chain request id *locally* from
  inputs it already validated, wraps it into the safe's ERC-1271 SafeMessage
  hash (the safe is the off-chain requester of record), and registers exactly
  that digest with the guard as a single-use, short-lived allowance before
  mech-client asks for the signature (nothing the agent session names can
  register one, and a digest the server did not derive — say, from a lying
  RPC answering `getRequestId` — mismatches and is refused). The only allowed
  transaction is a safe `execTransaction` CALL to a whitelisted address with
  the gas-refund fields zeroed (a non-zero SafeTx `gasPrice` would pay a refund
  out of the safe past the whitelist) — plus one analogous carve-out: before
  an off-chain request that may auto-deposit, the mech flow pre-authorizes
  the one safe→balance-tracker payment a 402 top-up would send, single-use,
  shape-checked (bare native transfer or `deposit(uint256)` with no inner
  value) and capped at the same bound mech-client itself enforces on the
  shortfall (10× the mech's per-request rate). The MechMarketplace contract per chain
  (imported from the pinned mech-client) is whitelisted by default — the only
  contract the safe calls in the on-chain mech flow — so mech requests work out
  of the box. Balance trackers and payment tokens are deliberately not
  whitelisted: the whitelist is address-level (any calldata), so a token entry
  would permit arbitrary transfers, and the safe only calls trackers for prepaid
  deposits, which restricted mode admits only through the one-shot capped
  deposit allowance described above.

The agent can ask before it spends: `preflight_transaction` composes the same
bytes the send would and runs them past the same gate, answering `{allowed}`
plus the refusal the real call would have raised. Nothing is signed or
broadcast, and no single-use allowance is spent — the reasoning for that is at
the top of `connect/guard.py`.

Asking is not a new capability: a refused send never reached the chain either,
because the gate runs before signing. What asking avoids is the audit entry, so
a dry run is recorded as `checked` rather than `blocked` — an operator can
still see a session probing for what it can get away with, without a request
that was never sent being logged as one the guardrail stopped. The entry
carries the call as it was *asked about* (`probed_target`, `probed_value`,
`via_safe`) beside the composed transaction it would have become, since on the
safe path the composed target is the safe itself and an allowed probe would
otherwise record nothing about what was probed.

Funding the safe is the operator's job, through Pearl — the agent has no
EOA→safe sweep, because it never needed one.

There is a single gate with no bypass: the MCP tools, the HTTP signing
endpoints and the mech request flow all pass the same check. State persists in
`pearl-connect.settings.json` at STORE_PATH; the security-critical fields
(mode, whitelist) are HMAC'd with a key derived from the agent private key
and verified on every read — an edit by the agent (or anything else without
the key) fails verification and resets them to the defaults — deliberate,
and audited; the reasoning lives in `connect/settings.py`'s module
docstring. The
`harness` preference is stored alongside without integrity checks and survives
a guardrail reset. It is outside the MAC because it cannot move funds or widen
the guardrail — both harnesses are only ways to open Claude Code on the
operator's own machine, and editing the field just reorders which one is tried
first. What a tamper can still do is mislead: leave the UI showing a preference
the operator's sessions are not opening in.
The MAC of the last file the server wrote is also pinned
in memory, so replaying an *old* validly-MAC'd settings file (say, captured
while the mode was unrestricted) fails the same way; only a replay staged
while the server is stopped escapes the pin. Operators change the mode in the agent UI at
`http://127.0.0.1:8716/`; the change is authenticated by re-decrypting the
keystore with the submitted password, not by the session's bearer token. The
whitelist is not editable through the API yet — a patch replaces it wholesale
across all chains and only its address *format* can be validated here, so it
stays frozen at the defaults (a `whitelist` in a patch is a 422) until those
semantics are designed.

## Threat-model notes

Binding to `127.0.0.1` does **not** make the server unreachable from the web:
any page the user's browser visits can fire requests at localhost, and DNS
rebinding defeats some browser-side protections. Hence: every route that moves
funds or changes the guardrail requires the bearer token (or the keystore
password for the `protected` settings), Origin headers are validated, only
loopback Host headers are accepted, and no CORS is enabled. Two state-changing
routes are gated on **origin locality alone**, because the FE that calls them
holds no token: `POST /session` (spawns a Claude Code session on the operator's
machine) and the harness half of `PATCH /settings`. Neither can move funds or
widen the guardrail; the deliberate trade is that any local process — including
the agent's own session — can open a session window or change which Claude Code
it opens in. Repeated auth failures are audited to the activity log and
rate-limited (429) so a probed token is loud, not silent. The token itself is
header-only, rotated per run, dies with the process, and the provisioned
workspace ships a `.gitignore` and a Claude Code `Read` deny rule so it is
neither committed nor read into session transcripts.

Out of scope for v1: SSH port forwarding or running on a shared/remote
machine voids the loopback assumption entirely, and same-user local malware
can read `.mcp.json` directly — the guardrail (not the token) is the defense
that survives those.

## Mech requests

The `mech_request` MCP tool drives [mech](https://olas.network/services/ai-mechs)
requests through mech-client's `Signer` protocol, so every transaction and
digest passes the guarded choke point. The default off-chain prepaid flow
works in both modes: it signs the request-id digest, which restricted mode
allows through the server-derived single-use allowance described above, and
its `auto_deposit` top-up (paying the balance tracker from the safe on HTTP
402) is pre-authorized the same way — capped, single-use, armed only for the
request being sent. The flow also needs a mech whose operator published an
endpoint in its on-chain metadata — few have, so `mech_tools` reports
`offchain_capable` per mech and a request to one that cannot serve it is
refused before any payment. The on-chain path sends through the
MechMarketplace via the service safe and works for any listed mech.

### Replaying a mech request

A mech request is paid for before it is answered, so a caller whose response
was lost cannot tell a spent request from an unsent one — and the only way to
find out costs another payment. `mech_request` therefore takes an optional
caller-chosen `request_id`; repeating it never sends again, and the report
comes back marked `replayed`.

What the id covers depends on where the first attempt stopped, because the
server can only promise what it can actually know:

- **It returned.** The replay resumes each watch still outstanding and picks
  up whatever landed since — the usual case, since a caller retries precisely
  because the first call returned before the mech answered. Ids that resolve
  move into `delivery_results`; ids whose read failed stay in
  `pending_request_ids` with the cause in `replay_errors`; ids a direct
  `mech_result` call already collected come back as
  `unrecoverable_request_ids`, because that answer was handed to another
  caller and this server keeps no copy.
- **It failed before the paying call.** The id is released, so a retry is an
  ordinary first attempt.
- **It failed after the paying call was entered.** mech-client pays before it
  watches, so the spend is genuinely unknown. The id is kept and every replay
  refuses it: sending again is a decision to risk a second payment, and it
  takes a new id to say so.

Two bounds worth knowing: the ledger is in memory, so a restart clears it,
exactly as it clears `mech_result`'s pending ids; and it keeps the last 1024
ids, so an id replayed long after that many others pays again. An id is also
bound to what it asked — reusing one for a different prompt, tool, chain, mech
or flow is refused rather than answering the wrong question.

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
uv run python -m connect --password-stdin   # prompts "Enter password:" on a TTY
# legacy (password lands in /proc/<pid>/cmdline, readable by any local user):
uv run python -m connect --password <password>
```

## Olas packages

`packages/` holds the [Olas SDK](https://stack.olas.network/olas-sdk/) package
tree (mirroring `valory-xyz/olas-sdk-starter`):

- `packages/valory/agents/connect` — the agent blueprint (metadata; the
  runtime is the released binary)
- `packages/valory/services/connect` — the service package whose
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

## Further reading

- Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- Security policy: [`SECURITY.md`](./SECURITY.md).
- Agent UI integration: [`docs/agent-ui.md`](./docs/agent-ui.md).
- [Open Autonomy framework](https://stack.olas.network/open-autonomy/) and the
  [Pearl integration checklist](https://stack.olas.network/pearl/agent-integration-checklist/).
