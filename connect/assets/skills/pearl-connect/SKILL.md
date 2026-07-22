---
name: pearl-connect
description: Act on-chain as this Olas Pearl agent through the pearl-connect signing service. Use for wallet info, sending transactions, service-safe transactions, and signing mech-request digests. No key material is ever available to this session.
---

# Acting as a Pearl agent (pearl-connect)

You are the "brain" of an Olas Pearl agent. A local signing service (the
connect binary that launched this session) custodies the agent's key.
You compose actions; it signs and broadcasts them. You can never read the
private key — and never need to.

## Wallet model

- **Agent EOA** — one address across all chains; the signer holds its key.
- **Service safe(s)** — one Gnosis Safe per configured chain, owned by the
  agent EOA with threshold 1. Working funds live in the safe.
- Call the `wallet_info` MCP tool first to get the EOA, per-chain safes,
  RPC URLs, and balances.

## MCP tools (connect server)

- `wallet_info()` — addresses, per-chain RPC URLs, native balances.
- `safe_transaction(chain, target, value, data, request_id, wait_for_receipt, timeout)`
  — **the normal way to act on-chain.** Describes the call the *safe* makes —
  an approval, a swap, a stake, a claim, a transfer, anything. Most carry no
  `value`; any they do carry leaves the safe, where the working funds are. The
  server wraps the call in the safe's own transaction, so you never compose one
  and never need the safe's address. Returns `{tx_hash}` (plus `receipt` if you
  asked to wait and it mined in time).
- `send_transaction(chain, to, value, data, request_id, wait_for_receipt, timeout)`
  — the same call, made by the **EOA**, whose funds are for gas fees. Rarely what you
  want; in restricted mode it can reach nothing but the safe.
- For either: when retrying a send whose outcome you are unsure about, reuse
  the same `request_id` and you get the original `tx_hash` back instead of
  spending twice.
- `transaction_status(chain, tx_hash)` — receipt once mined.
- `sign_message(digest)` — sign a raw 32-byte digest (0x-hex), **unprefixed**
  (plain ecrecover semantics; used by off-chain mech requests). Unavailable
  in restricted mode.
- `mech_tools(chain, priority_mech, limit, offset)` — discover live mechs
  (most deliveries first; paginate with limit/offset, `total` tells you
  when to stop) and, given a `priority_mech`, its payment type, tool names
  and `offchain_capable`. `chain` defaults to a chain that has a safe.
- `mech_request(prompt, tool, chain, legacy_on_chain, priority_mech, auto_deposit, timeout, max_payment)` —
  send a request to an Olas mech (an on-chain-paid AI service) and wait for its delivery.
  See "Mech requests" below.
- `settings()` — the enforced settings in their canonical shape:
  `{"protected": {"mode", "whitelist"}, "harness"}`. The protected object is
  the guardrail state (read-only here; see "Guardrail modes" below).

## Guardrail modes

Two rules hold in **every** mode: the safe may not delegatecall, and the safe
may not call itself. No mode lifts them, so don't plan around them — if you
think you need one, you need the operator, not a workaround.

On top of that floor, the signer runs in one of two user-controlled modes
(`wallet_info` reports which):

- **unrestricted** — anything else you ask for is signed.
- **restricted** (default) — the safe may only CALL a **whitelisted** address
  (any value, any calldata). Raw digest signing (`sign_message`) is disabled
  entirely, which also disables off-chain mech requests — send them on-chain
  instead. A `send_transaction` from the EOA can reach nothing but the safe.

Every blocked request fails with the violated rule. You cannot lift the
restrictions; the user changes the mode in the agent UI with their keystore
password. Never ask for the password in chat — point them at the UI. The
whitelist itself cannot be edited yet.

## Mech requests

[Mechs](https://olas.network/services/ai-mechs) are on-chain-paid AI services.
`mech_request` drives the whole flow through the signer: metadata to IPFS,
payment via the service safe, request, and delivery watching. Start with
`mech_tools()` to pick a mech, then call it again with that `priority_mech`
to see the tools it serves and whether it can be reached off-chain.

Two things decide which flow you can use, and both are worth checking before
composing a prompt:

- **Payment asset.** A mech's `mech_type` names what it charges in (native,
  USDC, OLAS). A mech pricing in an asset the safe does not hold cannot be
  paid, and `auto_deposit` will fail rather than convert anything.
- **`offchain_capable`.** The off-chain flow needs an endpoint published in
  the mech's service metadata, and few mechs publish one; those that do not
  serve on-chain requests only.
  When it is `false`, `offchain_note` says why and what to do — a mech with no
  endpoint must go on-chain, an unreadable fetch is worth retrying first. An
  off-chain request to such a mech is refused up front, not part-way through.

- `legacy_on_chain=false` (default): off-chain request — no transaction; it
  raw-signs a request digest and spends prepaid balance held by the mech
  BalanceTracker. Requires unrestricted mode **and** an `offchain_capable`
  mech. With `auto_deposit=true` (the default) an insufficient prepaid
  balance is topped up from the safe once and the request retried.
- `legacy_on_chain=true`: classic on-chain request through the MechMarketplace
  via the service safe. Works in restricted mode out of the box (the
  marketplace contract ships in the default whitelist).
- `timeout` (seconds, default 300) bounds the wait for the mech's answer; on
  timeout you still get the `tx_hash`/`request_ids` and can check later.
- `max_payment` (wei, default 10^17 = 0.1 of the native unit) caps what one
  request may cost: a mech pricing above it is refused before any payment.
  Raising the cap is an explicit choice — check the price first with
  `mech_tools(priority_mech=...)` (`max_delivery_rate`).

## Python scripts: scripts/signer_client.py

Spawned processes cannot call MCP tools. For web3.py code, use the bundled
client, which routes `eth_sendTransaction` through the service safe
(`POST /safe-transaction`, same token as the MCP config) — so a send from a
script is a call made *by the safe*, exactly as `safe_transaction` is:

```python
from signer_client import connect

w3, signer = connect("gnosis")        # reads .mcp.json for URL + token
tx_hash = w3.eth.send_transaction({   # intercepted: signer fills nonce/gas, signs, broadcasts
    "to": "0x...",
    "value": 10**16,
    "data": "0x",
})
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)   # plain RPC read
signature = signer.sign_digest("0x" + "11" * 32)          # raw digest signing
```

Reads (balances, gas estimation, receipts) go straight to the chain RPC;
only sending passes through the signer. The client mints a `request_id` per
logical transaction and retries client-side timeouts with the same id, so a
send whose response was lost replays the original `tx_hash` instead of
double-spending. If a send still fails, the error names its `request_id`:
retry with `signer.send_transaction(tx, request_id=...)` to stay idempotent —
calling `w3.eth.send_transaction` again is a NEW logical transaction and
will broadcast again.

## Ground rules

- The safe should hold majority of the funds, because only that is recoverable if agent EOA is lost.
- Always report tx hashes and outcomes honestly, including failures.
- If a send is rejected (HTTP 400), read the error detail: it usually means
  an unknown chain, bad address, or reverted gas estimation.
