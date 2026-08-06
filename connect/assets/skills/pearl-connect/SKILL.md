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
- **Service safe** — a Gnosis Safe owned by the EOA (threshold 1) on each
  chain you were deployed to, usually one. Working funds live there; the
  EOA pays gas.
- Call `wallet_info` first: **act only on `actionable_chains`** — usually a
  single chain. The launcher configures an RPC for every chain it supports,
  so the rest are listed with no safe or no gas. That is the normal shape,
  not something to fix; `not_actionable_because` says which state each is in.

## MCP tools (connect server)

Each tool's own description carries its parameters and returns. What those
cannot tell you is which to reach for:

- `wallet_info` — start every on-chain task here.
- `safe_transaction` — **the normal way to act on-chain.** It describes the
  call the *safe* makes: an approval, a swap, a stake, a claim, a transfer,
  anything. You never compose the safe's own transaction, and never need its
  address.
- `send_transaction` — the same call made by the **EOA**, whose funds are for
  gas. Rarely what you want.
- For either: if you are unsure whether a send landed, retry with the same
  `request_id` rather than issuing a new one.
- `transaction_status` — settle a hash you already hold.
- `sign_message` — raw digests, **unprefixed** (plain ecrecover semantics).
- `mech_tools`, `mech_request`, `mech_result` — see "Mech requests" below.

## The guardrail

Every signing request passes a guardrail. Two of its rules never move: the
safe may not delegatecall, and the safe may not call itself. Don't plan
around them — if you think you need one, you need the operator, not a
workaround.

The operator controls what else the guardrail allows. Any blocked request
fails with the violated rule named; you cannot lift a restriction yourself —
the operator manages the guardrail in the agent UI with their keystore
password. Never ask for the password in chat — point them at the UI.

## Mech requests

[Mechs](https://olas.network/services/ai-mechs) are on-chain-paid AI services.
`mech_request` drives the whole flow through the signer: metadata to IPFS,
payment via the service safe, request, and delivery watching. Start with
`mech_tools()` to pick a mech, then call it again with that `priority_mech`
to see the tools it serves and whether it can be reached off-chain.

`chain` is optional throughout: it defaults to a configured chain, preferring
one with a safe.

Two things decide which flow you can use, and both are worth checking before
composing a prompt:

- **Payment asset.** A mech's `mech_type` names what it charges in (native,
  USDC, OLAS). A mech pricing in an asset the safe does not hold cannot be
  paid, and `auto_deposit` will fail rather than convert anything.
- **`offchain_capable`.** The off-chain flow needs an endpoint published in
  the mech's service metadata, and few mechs publish one; the rest serve
  on-chain requests only. When it is `false`, `offchain_note` says why — a
  mech with no endpoint must go on-chain, an unreadable fetch is worth
  retrying first. Such a request is refused up front, not part-way through.

- `legacy_on_chain=false` (default): no transaction; it signs a request
  digest and spends prepaid balance held by the mech BalanceTracker. With
  `auto_deposit=true` (the default) an insufficient balance is topped up from
  the safe once and the request retried.
- `legacy_on_chain=true`: classic on-chain request through the MechMarketplace
  via the service safe.
- `timeout` (seconds, default 300, max 900) bounds each phase of the wait —
  the marketplace naming a delivering mech, then reading that mech's logs —
  so the call itself can take up to twice it. A timeout does not lose the
  request — it is paid for, and the ids come back as `pending_request_ids`.
  Poll them with `mech_result(request_id)`, which resumes the watch and never
  resends.
- `max_payment` (base units of the mech's payment asset — wei for native
  mechs; default 10^17 = 0.1 native) caps what one
  request may cost: a mech pricing above it is refused before any payment.
  Raising the cap is an explicit choice — check the price first with
  `mech_tools(priority_mech=...)` (`max_delivery_rate`).

## Python scripts: scripts/signer_client.py

Spawned processes cannot call MCP tools. For web3.py code, use the bundled
client, which routes `eth_sendTransaction` through the service safe
(`POST /safe-transaction`, same token as the MCP config) — so a send from a
script is a call made *by the safe*, exactly as `safe_transaction` is.

The client needs **`web3>=7.15,<8`**; install that into whatever venv runs
your script. On web3 6 it fails at import (the middleware moved in 7), so an
`ImportError` from `signer_client` is the venv's version, not a missing file:

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

Contract calls go the same way, through a normal web3 contract object —
`connect()` points `w3.eth.default_account` at the safe, so a simulation sees
the sender the send will really have:

```python
token = w3.eth.contract(address=usdc, abi=ERC20_ABI)
token.functions.balanceOf(w3.eth.default_account).call()        # read
tx_hash = token.functions.approve(spender, amount).transact()   # sent by the safe
```

`signer.send_transaction({...})` is the same send one layer down, and the one
to reach for when you need to pass a `request_id` (below).

Two things `connect()` handles that hand-rolled web3 code gets wrong: PoA
chains (Polygon above all) pad `extraData` past 32 bytes and break every block
read unless the PoA middleware is injected, and web3's own gas estimator would
otherwise simulate the call with `from` unset — i.e. from the zero address —
so a contract call reverts (`ERC20: approve from the zero address`) before
anything is sent. Build the web3 with `connect()`, not `Web3(...)`, and
neither happens.

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
