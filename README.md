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
2. populates the service's persistent workspace (`STORE_PATH`) for either
   harness: the MCP entry with a fresh bearer token every run (`.mcp.json` for
   Claude Code, `.codex/config.toml` for Codex), the context brief (`CLAUDE.md`,
   copied to `AGENTS.md`), the bundled skills (`pearl-connect` for signing,
   `connect-polymarket` for prediction markets, `connect-stocktokens` for
   Robinhood Chain Stock Tokens, `connect-pons` for the Pons memecoin
   launchpad on Robinhood Chain) and the shared modules they import, installed
   as `skills/` and `lib/` under both `.claude/` and `.agents/`;
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
   - `POST /session` (origin-gated, no token): opens an agent session in the
     configured harness (`claude_code_cli` →
     `claude-cli://open?cwd=…`, `codex_desktop` →
     `codex://threads/new?path=…`, `claude_code_desktop` →
     `claude://code/new?folder=…`, see [Codex](#codex)) and answers
     `{launched, harness, requested, error?}` — `harness` is the one that
     opened, `requested` the one it aimed for. An optional `{"harness": …}`
     body overrides the saved preference for that launch alone, without
     rewriting what the operator chose
   - a bearer-authed signing surface: `POST /safe-transaction` (the safe's call:
     `target`, `value`, `data`), `POST /sign-and-send` (the EOA's: `to`,
     `value`, `data`), `POST /sign-message`, `GET /wallet`. Every body and
     every MCP tool refuses a parameter it does not take, with an error naming
     the ones it does (`to` on the safe path is pointed at `target`); read-only
     tools carry `readOnlyHint`
   - MCP (streamable HTTP) at `/mcp` with tools `wallet_info`,
     `safe_transaction`, `send_transaction`, `preflight_transaction`,
     `simulate_transaction`, `transaction_status`, `chain_call`, `get_abi`,
     `decode_calldata`,
     `sign_message`, `mech_tools`, `mech_request`, `mech_result` (plus a
     read-only `settings` tool when `EXPOSE_MODE_TO_AGENT` is on).

The binary opens no session itself: Pearl waits for `is_healthy`, then calls
`POST /session`. A launch failure (harness not installed, deep link unhandled)
then reaches the operator's UI as a dismissable error instead of dying in this
process's log. Neither Pearl nor the UI names a harness, so those launches
start at the saved preference — until an operator changes it, only our default
guess, the Claude Code CLI — and fall back through the other harnesses in
the order `DEEP_LINKS` then `TERMINAL_COMMANDS` declare them
(`claude_code_cli`, `codex_desktop`, `claude_code_desktop`, `codex_cli`),
rather than leave them with no session at all. A launch that *does* name one
opens there or not at all: naming a harness is a choice.

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
session in the workspace's `.claude/settings.json` or `.codex/config.toml`,
which we merge into rather than own.

The agent-harness session names the actions; the server signs and broadcasts
them — a single audited choke point, no plaintext secrets on disk. The agent
acts *as the service safe*: it is the `msg.sender` contracts see, and approvals,
swaps, stakes, transfers, etc. are all calls it makes. The session never composes
one, though — it names the inner call (`safe_transaction`, `POST
/safe-transaction`) and the server wraps it in the safe's `execTransaction`,
threshold-1 pre-validated signature and all. Nothing about the safe — its
address, its ABI, its signature convention — is the session's problem.

## Run window

Connect has no staking epoch, so its activity goal is **one run window per
process** of N minutes, opened when the process starts and never rolled over.
Every write of `agent_performance.json` carries it as the `activity_goal`
block Pearl reads through the middleware's `agent_performance` endpoint:

```json
{
  "activity_goal": {
    "unit": "minutes",
    "target": 15,
    "progress": 19,
    "is_met": true,
    "period_start": 1791331200,
    "last_met_at": 1791332100,
    "updated_at": 1791332340
  }
}
```

The server rewrites the file every 15 seconds as well as after every recorded
action. `progress` is whole minutes since `period_start`, and `is_met` is
`progress >= target`: once met, it stays met for the rest of the process
unless the target is raised.
`last_met_at` is stamped once, the first time a write sees the goal met. A
target of `0` is met at once. Connect never stops itself; Pearl's Auto-run
reads `is_met` and decides when to hand the turn to another agent. Window
state does not survive a restart: a new process opens a fresh window with
`is_met: false` (unless the target is 0) and `last_met_at: null`.

`activity_goal.target` is the one field the session may write. Each server
write reads it back first: a whole number >= 0 becomes the target of the
current window (raising it above `progress` makes the goal unmet again,
lowering it to or below `progress` meets it) and is audited as
`minutes_per_run_changed`;
anything else is logged and overwritten with the current target. The file
sits in `STORE_PATH`, so the user's value survives restarts. The first read of
a process that finds a value other than the configured one is audited as
`minutes_per_run_restored`: it may be the value from before the restart, or
an edit the session made while Connect was stopped. When the session may
change it is the brief's to say
([`connect/assets/CLAUDE.md`](connect/assets/CLAUDE.md), "Minutes per run");
that is instruction, not enforcement, which is why every change is audited.
The target starts as `CONNECTION_CONFIGS_CONFIG_MINUTES_PER_RUN` (default
15). The first write stores it in the file, and the file's value wins from
then on, so a later change to the env var doesn't reach an existing install.
A value that is not a whole number >= 0 is a configuration error.

## Codex

Two harnesses open Codex. `codex_desktop` uses the desktop app's
`codex://threads/new` link, with `mode=codex` so an app sitting on its chat
tab switches to Codex rather than opening the thread there; the parameter is
read from the app's code, not documented, so it may change under us. The Codex
CLI registers no URL handler, so `codex_cli` does what Claude Code's
`claude-cli://` handler does for itself: it opens a terminal running `codex`
in STORE_PATH. On Linux that is `$TERMINAL` when it names a terminal Connect
knows how to drive, then `x-terminal-emulator`, then the first known emulator
installed, and `codex` runs through the operator's login shell when it is a
POSIX one, else bash. On macOS, Terminal.app opens a self-deleting `.command`
file, which needs no Automation permission. On Windows, Windows Terminal, then
`cmd.exe`. The CLI cannot pre-fill a prompt, so that session opens empty. A
terminal only opens once `codex` resolves in that shell (`shutil.which` on
Windows); otherwise the launch fails as not installed, and a fallback moves
on, instead of flashing a window that cannot find it.

Codex loads a project's `.codex/config.toml` — our MCP entry with it — only
once the operator trusts the folder, and asks them to the first time a session
opens there. Connect never answers for them and never touches the user's own
Codex config; a session in an untrusted folder has no signer tools, and the
brief tells the agent to say so.

The workspace config turns on `sandbox_workspace_write.network_access`, unless
the file already sets it: Codex's `workspace-write` sandbox otherwise blocks
every socket, the signer on localhost included, and the skills' scripts need
the network. It is all or nothing on purpose: Codex's permission profiles can
narrow network access to a domain allowlist, but its private-network guard
blocks loopback, where the signer is, unless `allow_local_binding` is also set,
and the skills reach operator-configured RPCs and several venue APIs, so the
list would differ per operator. Two differences from Claude Code remain. Every MCP tool call asks
for approval, as Claude Code's do without an allow rule. And there is no
equivalent of the `Read` deny rule: the token in `.codex/config.toml` is
gitignored, not kept out of transcripts.

## Intent gate

After the guardrail, every agent-originated value-moving send (`safe_transaction`
and `send_transaction`, MCP and HTTP alike) must carry an **intent** — spend
caps per token, minimum receive, allowed recipients, approvals — and is
simulated at head over the chain's RPC with `eth_simulateV1`
(`traceTransfers: true`, `validation: false`) before it is signed. The asset
diff comes from the simulated logs (`connect/intent.py`): no fork, no trace, so
`called` lists the target plus every contract that emitted a log. Native value
comes from the synthetic `0xeeee…eeee` logs plus, on Celo, the `0x471E…` CELO
face's `Transfer` logs, summed: a native send logs only the synthetic one and a
`transfer` on the face logs only its own, so neither is counted twice
(`chains.NATIVE_ERC20_FACES`). Polygon's own `LogTransfer` is a different event
and never counted. A WETH `Deposit`/`Withdrawal` is counted only when the same
token logged no `Transfer` mint to (or burn from) the sender, since
Solmate- and OpenZeppelin-style wrappers log both for one wrap. The rules, each named in
the refusal and recorded as an activity `refusal` entry: `reverts`,
`bad-intent`, `missing-intent`, `overspend`, `receive-min`,
`undeclared-recipient` (EOAs only, an EIP-7702 delegated EOA counted as one;
burns to the zero address skipped) and
`undeclared-approval` (a 0 approval is not checked; `setApprovalForAll` counts
as a maximum, even when revoking). Only the CELO face's `Transfer` is native:
its `Approval` is an approval like any other, and an intent naming the face in
`spend` or `receive_min` means `"native"` (naming both is `bad-intent`). Under a
value-capped token the gate also refuses any ERC-721/1155 position leaving the
sender (`token-cap-positions`; README, "Scoped tokens"). A `send_transaction`
to the configured safe whose calldata is `execTransaction` is gated as the
safe's inner call (to any other address the EOA's own call is what runs, and
what is simulated), and refused before simulating as `bad-exec-transaction` if
it also carries value from the EOA, is not a CALL, or pays a gas refund (any of
`gasPrice`, `gasToken`, `refundReceiver` set), which the inner call's
simulation would not show. The safe's `approveHash` is refused outright
(`approve-hash`): it pre-approves a safe transaction by hash, which anyone may
then execute, so no intent could hold it. These refusals are audited like the
rest, after the guard has answered. An amount in an intent is a whole number
of base units: a float or a bool is `bad-intent`, never truncated. An ERC-20
`Approval` whose amount is no higher than the spender's allowance before the
call (read at head; OpenZeppelin 4.x tokens emit one from `transferFrom` as
they spend an allowance down) is no new grant and needs no declaring; a read
that fails keeps it. A call that sends native value but whose simulation logs
no native transfer of it fails closed as `simulation-unavailable`: the RPC
ignored `traceTransfers`. Permit2's own grants (its `Approval` from
`approve()` and its `Permit` from a signed permit, from the canonical Permit2
address) are approvals of the token to their spender, declared and capped like
an ERC-20 approval, and always declared: the allowance exemption above reads
the token's own `allowance()`, which says nothing about a Permit2 grant. An RPC that cannot simulate refuses the send
as `simulation-unavailable`, so Pearl must give Connect, on every chain, an RPC
that serves `eth_simulateV1` (Celo's `forno.celo.org` does not). The
transactions the server builds itself — the mech flow (`MechSigner`) and the
agent top-up — pass the private `SERVER_BUILT` marker and skip the gate; they
are bounded by `max_payment` and the top-up plan, and while restricted by their
single-use allowances. The diff names each token's `symbol()` for the reader
(display only: nothing is checked against it, and a token without one reads
as `""`). `preflight_transaction` and `simulate_transaction` take
the same `intent` and report the gate's `problems` without signing.

The gate holds **transactions**. `sign_message` signs a raw digest for the
uncapped workspace token in the default mode, and a digest can be a safe
transaction hash: that is the guardrail's restricted mode to turn off, not
the gate's to check (a value-capped token cannot sign one at all).

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
  shortfall (10× the mech's per-request rate). The
  [agent top-up](#agent-top-up) arms the same bare native shape for the agent
  EOA. The MechMarketplace contract per chain
  (imported from the pinned mech-client) is whitelisted by default — the only
  contract the safe calls in the on-chain mech flow — so mech requests work out
  of the box. Balance trackers and payment tokens are deliberately not
  whitelisted: the whitelist is address-level (any calldata), so a token entry
  would permit arbitrary transfers, and the safe only calls trackers for prepaid
  deposits, which restricted mode admits only through the one-shot capped
  deposit allowance described above.

The agent can ask before it spends: `preflight_transaction` composes the same
bytes the send would and runs them past the same gate, answering `{allowed}`
plus the refusal the real call would have raised — the calling token's caps
included, checked first as the MCP mount checks the send, without drawing on its
session budget. Nothing is signed or broadcast, and no single-use allowance is
spent — the reasoning for that is at the top of `connect/guard.py`.

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
the guardrail — every harness is only a way to open a coding agent on the
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

## Agent top-up

`CONNECTION_CONFIGS_CONFIG_FUND_REQUIREMENTS` is
`{chain: {"agent" | "safe": {asset: {"threshold", "topup"}}}}`, amounts in wei
as decimal strings or integers.

At start and then every `AGENT_TOPUP_INTERVAL_SECONDS`, on every chain with a
safe and a native requirement for the agent, the server checks the agent
EOA's native balance. Below its `threshold`, the EOA needs `topup - balance`,
and the safe sends it that much native token, or all it holds when that is
less, in one plain `execTransaction` CALL (no calldata, no MultiSend). Tokens
never move. An EOA that cannot pay the gas fails the send at estimation, which
costs nothing. A top-up that is mined successfully is audited as
`agent_topup`; one that is refused, fails to send, reverts or is not mined in
time, as `agent_topup_failed`. Those two entries are the top-up's whole audit:
it is not a `transaction`, `send_failed` or `blocked` entry, it does not count
towards the `transactions` metric in `agent_performance.json`, and it never
becomes its `last_activity`. In restricted mode the send passes through a
one-shot allowance for exactly that transfer, capped at the amount sent.

`GET /funds-status` reports each entry's deficit as funds-manager does:
`topup - balance` once the balance is below `threshold`, else 0. The
exception is the native pair on a chain whose last top-up succeeded. There,
an agent EOA below its `threshold` reports 0, since the next top-up covers
it, and the safe is judged on what it keeps after sending the EOA's need:
`remaining = safe balance - need`, and the safe's deficit is
`topup - remaining` when `remaining` is below its `threshold`, else 0. When
the safe holds less than the need, `remaining` is negative, so the shortfall
is added to the safe's `topup`.

## Threat-model notes

Binding to `127.0.0.1` does **not** make the server unreachable from the web:
any page the user's browser visits can fire requests at localhost, and DNS
rebinding defeats some browser-side protections. Hence: every route that moves
funds or changes the guardrail requires the bearer token (or the keystore
password for the `protected` settings), Origin headers are validated, only
loopback Host headers are accepted, and no CORS is enabled. Two state-changing
routes are gated on **origin locality alone**, because the FE that calls them
holds no token: `POST /session` (spawns an agent session on the operator's
machine) and the harness half of `PATCH /settings`. Neither can move funds or
widen the guardrail; the deliberate trade is that any local process — including
the agent's own session — can open a session window or change which harness
it opens in. Repeated auth failures are audited to the activity log and
rate-limited (429) so a probed token is loud, not silent. The
token itself is header-only, rotated per run, dies with the process, and the
provisioned workspace ships a `.gitignore` so it is never committed and, for
Claude Code, `Read` deny rules on `.mcp.json*` and `.codex/config.toml*` so it is
not read into session transcripts.

### Scoped tokens

The token in the workspace is a **scoped** token: `read` + `mech` + `tx`, with no
caps of its own, so a session can do what it always could, and it is the root
every other token is minted from. Any token can mint a narrower one with `POST /tokens` (`{scopes, max_value_per_tx,
max_value_per_session, max_mech_payment, expires_at}`), for the scripts a
harness runs: fewer scopes, value caps per transaction and per session (per
token, `"native"` or an address in any case, in base units; Celo's CELO face
counts as `"native"`), a mech payment cap, an expiry. A grant wider than the
presenting token's is refused (`token-scope`), and unknown fields are refused by
name like every other body. The bundled `signer_client` mints one with
`SignerClient.mint_token(grant)`, and every bundled reader of `.mcp.json`
(`signer_client.load_mcp_config_dir`, so `connect(chain, token=None)` and
connect-polymarket's `ConnectSigner.from_workspace` alike) signs with
`$PEARL_CONNECT_TOKEN` when it is set, so a launcher can hand a script a
narrower token without the session ever reading `.mcp.json`. A blank value is
an error, never a fall-back to the workspace token. The cap bounds a script's
mistakes, not a hostile script, which can still read `.mcp.json` itself.

| Scope | Allows |
|---|---|
| `read` | `wallet_info`, `mech_tools`, `mech_result`, `transaction_status`, `preflight_transaction`, `simulate_transaction`, `chain_call`, `get_abi`, `decode_calldata`, `settings`, `GET /wallet` |
| `mech` | `mech_request` |
| `tx` | `safe_transaction`, `send_transaction`, `sign_message`, `POST /safe-transaction`, `POST /sign-and-send`, `POST /sign-message` |

Value caps are checked against the spend the call's intent declares (and its
native `value`), which the intent gate then holds the transaction to; a capped
`mech` token must pass a `max_payment` within `max_mech_payment`. A per-session
budget is drawn down when a call is authorized, whether or not the send then
succeeds, so it can be spent early but never exceeded; a retry naming a
`request_id` the signer already sent is not drawn again, since it is answered
with the sent transaction's hash and sends nothing; a child's spend is drawn
on every capped token it was minted from as well, so minting more children
never multiplies a budget. A declared approval draws on the session budget as
its spend does, since its spender can take that much later. That includes an
ERC-20 approval of Permit2, which also honours Permit2 grants made before this
token (by the workspace token, or outside Connect). An approval to a Uniswap
Universal Router that Connect ships for the call's `chain` is the exception: the
router pulls only from its own caller, so only the safe's own swaps can use it,
and what they move is drawn as spend. A Uniswap swap therefore draws its amount
twice (the approval of Permit2 and the spend), not three times. What a cap cannot bound, a value-capped token may not
do: approve more of a token than its caps allow (an approval is spend the
spender takes later; refused under the rule of the cap it exceeds), sign a raw digest (`sign_message`: a digest can authorize
any safe transaction), or move an ERC-721/1155 position out of the safe (the
gate's `token-cap-positions`). Refusals name their rule (`token-scope`,
`token-expired`, `token-cap-per-tx`, `token-cap-per-session`,
`token-mech-payment-cap`, and `bad-intent` or `bad-value` for an amount that is
not a whole number >= 0), come back as the HTTP 403/401 detail or the MCP tool
error, and are recorded as activity `refusal` entries. MCP calls are authorized
in the mount's middleware, which reads each JSON-RPC `tools/call` before the
MCP server does, and stamps the token on the request; whether its intent is
held as capped is decided from the token in one place (`GrantStore.intent_for`)
for both surfaces, and a call with no known token is treated as capped. A mech
payment (`mech_request`) is held to `max_mech_payment` per request and draws
nothing from a session cap.

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

### One payer per safe: nonces

Connect, not mech-client, allocates off-chain marketplace nonces
(`connect/mech_nonces.py`), so concurrent requests from one safe never share
one. It follows the deployed sequential marketplace: the mech admits only
`mapNonces + accepted + settling` for a sender, so one mech is in flight per
safe and chain (a request to another mech waits for the first one's slots to
settle, and is refused as `mech-in-flight` when its wait runs out), the lock is
held from reservation until the mech answers, and a slot is held until
`mapNonces > n`. mech-client signs the nonce it is given (`send_request(...,
nonces=[n], on_request_id=...)`, mech-client 0.25.0) and reports the
request id just before signing. Connect still recomputes that id itself from
what it assembled and the nonce it allocated: mech-client asks the contract
for it over `eth_call`, and an id signed on faith would let a lying RPC
collect the safe's ERC-1271 signature on any 32 bytes, so a mismatch is
refused before anything is signed. The mech's answer decides the slot: 200
holds it; 503 (a gap) resends the same nonce and id up to
`CONNECTION_CONFIGS_CONFIG_MECH_GAP_RETRIES` times (default 3), then refuses as
`mech-nonce-gap`; a 401 whose reason is exactly
`wire nonce below sender's next expected slot` means the nonce is taken
(`mech-nonce-taken`: our own unknown slot is then accepted, otherwise the queue
stalls); any other 4xx, a 402 after the top-up retry included, frees it
(`mech-request-rejected`), as does mech-client's auto top-up failing on the
safe's side (`OffchainTopUpFailed`: a cap, a balance, a reverted deposit). When
that top-up landed and the mech still answered 402, the amount it deposited
into the balance tracker is audited as `mech_deposit`; any other 5xx or a transport error holds it, since
the mech may have stored the request. A failure before mech-client's pre-sign
hook (an RPC or gateway error assembling the request) never reached the mech,
so it frees the nonce too. A held slot's settle clock starts when its delivery
arrives, or when the request's own response timeout (300 s, which mech-client
writes into every request) runs out if no delivery was seen first; a queue
with a slot that `mapNonces` has not passed within the settle timeout after
that (`CONNECTION_CONFIGS_CONFIG_MECH_SETTLE_TIMEOUT`, default 1800 s), or
whose nonce another signer took, stalls: only a probe at `mapNonces` is sent
until one is accepted again, and refusals and `mech_result` say
`mech_queue_stalled`. A slot whose answer was lost (unknown) is resolved
through that stall and probe; it is not resent by its salt. An on-chain request takes
`mapNonces` itself, so it waits until no off-chain slot is held. Held slots,
their metadata salt and the stall are persisted in `mech_nonces.json` under
STORE_PATH, and a slot is written there as unknown before its request is
POSTed, so a restart or a crash mid-send never reissues a held nonce. An
unreadable file refuses every request (`mech-queue-unreadable`) rather than
guess, and a file that cannot be written refuses new ones
(`mech-queue-unwritable`), the request whose own slot could not be written
included. Every refusal above is recorded as an activity `refusal` with its
`rule`, and leaves a caller's `request_id` free to send again, since nothing
reached the mech; only `mech-answer-unknown` is recorded as possibly paid for —
a 5xx, or a transport error after the pre-sign hook, when the request was
already signed. Its request id, derived from the nonce as the pre-sign hook checked it, is
named in the error and the `mech_request_failed` entry as `pending_request_ids`
and registered for `mech_result`, since the mech may still deliver it.
On both paths the lock is held only `ACK_WAIT_SECONDS` (1 s) of the delivery
wait: the rest runs after it is released, up to the request's `timeout`, so
other requests from the safe are not held behind a delivery. A read that fails
during that wait keeps the request pending, with its cause in
`watch_errors`, and never loses the report of a request already paid for; a
delivery collected there reports its url in `delivery_urls`, as one collected
under the lock does, also while its file cannot be read yet.

**Validity.** An off-chain request carries no deadline (mech-client sends
none), so it can settle whenever the mech delivers it, also after the
requester stopped waiting: `mech_request` reports `"expires": null`.

**Chat tools.** A prompt that is an OpenAI-style `messages` list as JSON gets
the shared chat contract: the report adds `completion` (text) and `usage`
(`prompt_tokens`, `completion_tokens`), read from the delivery in pmini's
`MechModel` order (the delivery, then `response`/`result`, then
`content`/`text`/`completion`, or `choices[0].message`); a native tool call the
model returned unrequested comes back as a fenced bash block in `completion`
(`connect/mech_chat.py`). Until the mechs team's chat mechs and the
facilitator's standard request path exist, do not use the facilitator's
`/mech/chat` route and `mech_request` from one safe at once: the facilitator
signs its own marketplace nonces for the safe, and two payers on one safe
collide.

Each request carries a spending budget, `max_payment`, checked against the
mech's price before anything is paid. It is denominated in the mech's payment
asset, so its default is 0.1 of that asset — 10^17 base units for native and
OLAS mechs, 10^5 for USDC ones, including Robinhood Chain, where that payment
type is USDG. `mech_tools` reports the asset as `payment_token`.

Each Mech is run by its own operator. `mech_tools` reports `valory_operated`
per mech: it resolves the mech's own name under `mech.valory.xyz`, built from
the mech address without `0x`, a hyphen, then the chain id. Valory creates
one DNS record for each mech it operates and for no other, so a name that
resolves in the public DNS means Valory operates that mech and Valory AG's
Mech Terms apply, which the report states in `terms`. The answer does not
depend on the mech being up. The lookup is not DNSSEC-validated, so it trusts
the resolver to return the public answer. The check fails closed: a name that
does not resolve, a failed or timed-out lookup, or a zone that answers every
name all read as not identified, and a check that could not complete says so
in `identification_note`. Whatever terms link an operator published in its
metadata is passed through as `terms_url`, reported as found rather than
endorsed.

The same report says who runs the mech and how it has behaved, from
mech-client's `ToolManager.mech_report_or_terms`. In `operator` the domain is
the identity: `domain_verified` is true only when
`https://<domain>/.well-known/agent-registration.json` lists the mech's
ERC-8004 agent id for the chain's identity registry (the agent id is read from
the service registry indexer; it is not the Olas service id except by
coincidence). Otherwise `verification_note` says why, including a domain that
redirects instead of serving the proof itself, and the proof is fetched again
next time rather than remembered as a no. The name is `claimed_name`, the
operator's own text, never checked, which `name_note` says: a verified domain
proves the domain, not the name. `benchmarks` maps each tool to the link the
operator publishes, as a claim and never as a figure, which `benchmark_note`
says. `delivery` is the
on-chain record from the marketplace indexer: requests received,
self-delivered and delivered by others, the creation time in ISO 8601 UTC and
`age_days`; its `note` says the counters cover on-chain requests and off-chain
requests the mech settled on-chain, so an off-chain request that was never
delivered appears nowhere. `payment` names the method with no price, since the
contract quotes the charge at request time. The record is only an aid to
choosing: when the manifest or the indexer cannot be read, mech-client reports
the terms alone and says so in `report_note`.

`mech_request` reports the same fields, decided before anything is paid or any
allowance is armed, so a session that skips `mech_tools` still learns whose
mech it pays and whose terms apply: `valory_operated` and `terms` or
`identification_note` on both flows, plus `operator`, `benchmarks`,
`delivery`, `payment` and `terms_url` on the off-chain flow, which is the one
that reads the manifest. Each report is its own check, resolver, indexer and
proof fetch alike, so two reports in one flow can disagree after a DNS blip
or an indexer hiccup; `mech_request`'s is the one that governs the request it
sent. mech-client's warnings, including a check that could not complete, are
routed into `log.txt`. Every check and label comes from mech-client, so the
rules live in one place; this server recomputes none of the domain check, the
id resolution or the labels.

An optional `request_context` dict is passed through unmodified as a
top-level key of the request metadata, for the tool to read; the bundled skill
documents the keys the predict tools look for. Off-chain it is part of the
document the request-id digest commits to, so that digest is derived over the
very bytes mech-client will hash. On-chain the document goes to IPFS with its
CID in the request event, making the context as public and permanent as the
prompt beside it.

### Replaying a mech request

A mech request is paid for before it is answered, so a caller whose response
was lost cannot tell a spent request from an unsent one — and the only way to
find out costs another payment. `mech_request` therefore takes an optional
caller-chosen `request_id`; repeating it never sends again, and the report
comes back marked `replayed`.

A request that returned before its delivery reports the ids still awaited in
`pending_request_ids`; one whose delivery could not be read in that wait
carries the cause in `watch_errors`, keyed by id; a chat delivery that cannot
be read leaves the cause in `chat_error` instead of losing the report. The
request was paid for, so the report is never lost to a failed read:
`mech_result` picks it up.

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
bound to what it asked — reusing one for a different prompt, tool, chain, mech,
flow or `request_context` is refused rather than answering the wrong question.

## Development

```bash
uv sync
uv run pytest -m "not integration"
# the connect-polymarket skill tests run the real SDK, kept out of uv.lock:
uv run --with polymarket-client==0.13.0 pytest tests/test_connect_polymarket_skill.py tests/test_connect_polymarket_trade_guard.py
```

Linting and CI checks mirror olas-operate-middleware (tomte toolchain via tox):

```bash
uv pip install "tomte[tox,cli]==0.7.0" tox-uv
tox -p -e flake8 -e pylint
tox -p -e black-check -e isort-check -e bandit -e safety -e mypy
tox -e unit-tests-coverage        # enforces 100% coverage
GNOSIS_RPC=<gnosis-rpc-url> tox -e integration-tests
tox -e launch-tests               # opens a real terminal for codex_cli (stand-in codex)
```

Run standalone (mimicking the Pearl runner):

```bash
export CONNECTION_LEDGER_CONFIG_LEDGER_APIS_GNOSIS_ADDRESS=<rpc-url>
export CONNECTION_CONFIGS_CONFIG_STORE_PATH=/path/to/persistent_data
export CONNECTION_CONFIGS_CONFIG_SAFE_CONTRACT_ADDRESSES='{"gnosis":"0x..."}'
export CONNECTION_CONFIGS_CONFIG_FUND_REQUIREMENTS='{"gnosis":{"agent":{"0x0000000000000000000000000000000000000000":{"threshold":"10000000000000000","topup":"50000000000000000"}},"safe":{"0x0000000000000000000000000000000000000000":{"threshold":"1000000000000000000","topup":"5000000000000000000"}}}}'
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
  `CONNECTION_CONFIGS_CONFIG_{SAFE_CONTRACT_ADDRESSES,STORE_PATH,FUND_REQUIREMENTS,LOG_LEVEL,MINUTES_PER_RUN,MECH_SETTLE_TIMEOUT,MECH_GAP_RETRIES}`)
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
