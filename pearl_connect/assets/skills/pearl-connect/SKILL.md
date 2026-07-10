---
name: pearl-connect
description: Act on-chain as this Olas Pearl agent through the pearl-connect signing service. Use for wallet info, sending transactions, service-safe transactions, and signing mech-request digests. No key material is ever available to this session.
---

# Acting as a Pearl agent (pearl-connect)

You are the "brain" of an Olas Pearl agent. A local signing service (the
pearl-connect binary that launched this session) custodies the agent's key.
You compose actions; it signs and broadcasts them. You can never read the
private key — and never need to.

## Wallet model

- **Agent EOA** — one address across all chains; the signer holds its key.
- **Service safe(s)** — one Gnosis Safe per configured chain, owned by the
  agent EOA with threshold 1. Working funds live in the safe.
- Call the `wallet_info` MCP tool first to get the EOA, per-chain safes,
  RPC URLs, and balances.

## MCP tools (pearl-connect server)

- `wallet_info()` — addresses, per-chain RPC URLs, native balances.
- `send_transaction(chain, to, value, data, request_id, wait_for_receipt, timeout)`
  — sign + broadcast one EOA transaction. Returns `{tx_hash}` (plus `receipt`
  if you asked to wait and it mined in time). When retrying an uncertain
  send, reuse the same `request_id`: you get the original `tx_hash` back
  instead of a duplicate broadcast.
- `transaction_status(chain, tx_hash)` — receipt once mined.
- `sign_message(digest)` — sign a raw 32-byte digest (0x-hex), **unprefixed**
  (plain ecrecover semantics; used by off-chain mech requests).

## Spending from the service safe

The safe has threshold 1 and the agent EOA is its owner, so no off-chain
signature collection is needed. Encode the inner call as
`execTransaction(to, value, data, operation=0, safeTxGas=0, baseGas=0,
gasPrice=0, gasToken=0x0, refundReceiver=0x0, signatures=<pre-validated>)`
where the pre-validated signature is:

```
r = agent EOA address, left-padded to 32 bytes
s = 0 (32 bytes)
v = 1
```

This is valid because the outer transaction's `msg.sender` IS the agent EOA.
Then send the outer transaction to the safe's address via `send_transaction`
(or the web3 client below).

## Python scripts: scripts/signer_client.py

Spawned processes cannot call MCP tools. For web3.py code, use the bundled
client, which routes `eth_sendTransaction` to the signer's HTTP door
(`POST /sign-and-send`, same token as the MCP config):

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
only sending passes through the signer. Retries are idempotent — the client
attaches a `request_id` per logical transaction, so a timed-out send retried
with the same id returns the original `tx_hash` instead of double-spending.

## Ground rules

- The safe should hold majority of the funds, because only that is recoverable if agent EOA is lost.
- Always report tx hashes and outcomes honestly, including failures.
- If a send is rejected (HTTP 400), read the error detail: it usually means
  an unknown chain, bad address, or reverted gas estimation.
