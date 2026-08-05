---
name: connect-polymarket
description: Trade on Polymarket as this Olas Pearl agent — discover markets, manage the deposit wallet, place and sell bets, sweep funds back to the service safe, and redeem winnings. All signing goes through the pearl-connect signing service; no key material ever enters this session.
---

# Trading on Polymarket (connect-polymarket)

Polymarket's CLOB v2 accepts orders funded by a **DepositWallet (DW)** — a
per-owner smart wallet deployed by Polymarket's factory — signed with
signature type 3 (`POLY_1271`). For this agent, the DW is owned by the agent
EOA and every signature (CLOB auth, orders, DW batches, relayer challenges,
safe transactions) is produced by the connect signer. You compose; it signs.

## The funds flow — follow it exactly

This mirrors the Olas Polystrat agent, and it exists for one
reason: **the service safe is the only wallet recoverable if the agent EOA
is lost.** The DW is owned by the bare EOA, so money must never sit there
longer than a trade needs.

```
USDC.e in safe --wrap--> pUSD in safe --top-up--> DW --buy--> position in DW
                                                                   |
     pUSD in safe <--redeem-- position in safe <------sweep--------+
```

1. `funds.py wrap` — the safe wraps its USDC.e into pUSD (the v2 collateral).
2. `funds.py top-up --amount X` — the safe sends the DW exactly what the
   next buy spends.
3. `trade.py buy/sell/limit` — trade on the CLOB, funded by the DW.
4. `funds.py sweep` — **always, after trading**: returns the DW's pUSD *and*
   bought positions to the safe. Cancel any resting limit orders first —
   sweep refuses while orders are open (their collateral/shares must stay in
   the DW to settle), unless you pass `--force`. Selling happens before
   sweeping (the shares must be in the DW when a sell matches).
5. `redeem.py all` — after market resolution, the safe redeems its winning
   positions for pUSD.

Re-running after a failure is **not** uniformly a no-op — check what a step
actually did before repeating it:

- **Safe to re-run:** `deposit_wallet.py ensure` (deploy is detected,
  approvals are checked on-chain) and `funds.py sweep` (moves whatever is
  there). These converge.
- **NOT idempotent — a re-run repeats the action:** `funds.py wrap` /
  `top-up` / `return-position` and `redeem.py` each send a fresh transaction
  every run, and `trade.py buy` / `sell` / `limit` place a *new* order each
  run. Every fund-moving command fails loudly (non-zero exit) if its
  transaction does not confirm on-chain, so a failure is visible — inspect
  the reported tx before re-running, or you may double-spend / double-order.

## Scripts (`scripts/`)

Run them from anywhere in the workspace (they locate `.mcp.json` upwards).

| Script | What it does |
|---|---|
| `deposit_wallet.py status\|ensure` | Deploy the DW via the relayer proxy and grant its trading approvals (idempotent one-time setup) |
| `funds.py balances\|wrap\|top-up\|sweep\|return-position` | Treasury flows between safe and DW; `return-position` stages an already-swept position back in the DW for selling |
| `markets.py list\|market\|book\|price` | Market discovery and prices (public reads); `list --ends-within 48h\|7d\|2w` filters by resolution date |
| `trade.py buy\|sell\|limit\|order\|cancel` | CLOB orders (POLY_1271, DW-funded); market orders take `--order-type fok\|fak`, limit orders `gtc\|gtd --expires-in` |
| `positions.py positions\|trades` | Portfolio reads (public) |
| `redeem.py list\|approve\|redeem\|all` | Redeem resolved positions from the safe |
| `pm_common.py` | Print every contract and API host this skill uses, named (reference only, no network) |

### Python environment — use a virtualenv, don't touch system Python

The scripts need a few third-party packages (the Polymarket SDK, web3,
requests). Run everything from a **persistent virtualenv**: create it if it doesn't
exist already, and reuse the same one on every run afterwards — don't
reinstall each time, and never install into the system Python. Keep the
venv **outside** `.claude/skills/` (the server overwrites that directory on
every boot, which would wipe a venv placed inside it).

```bash
# Create-if-missing, reuse-if-present. Kept in a home cache dir (outside the
# workspace), so it survives both restarts and skill refreshes. Override the
# location with CONNECT_POLYMARKET_VENV if you prefer somewhere else.
VENV="${CONNECT_POLYMARKET_VENV:-$HOME/.cache/connect-polymarket/venv}"
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q "py-clob-client-v2==1.0.2" "web3>=7.15,<8" requests
fi
PY="$VENV/bin/python"   # run every script below with "$PY", not plain python
# Point TLS at certifi's CA bundle, on every run — not only at creation. A
# pyenv/source-built Python often carries no trust store, and every Polymarket
# HTTPS call then dies with CERTIFICATE_VERIFY_FAILED, which reads as a venue
# outage rather than a local gap.
SSL_CERT_FILE="$("$PY" -c 'import certifi; print(certifi.where())')"
export SSL_CERT_FILE
export REQUESTS_CA_BUNDLE="$SSL_CERT_FILE"
```

A typical first session (once the venv is set up as above):

```bash
"$PY" scripts/deposit_wallet.py ensure     # once: DW + approvals
"$PY" scripts/funds.py wrap                # USDC.e → pUSD in the safe
"$PY" scripts/markets.py list --query "bitcoin"
"$PY" scripts/funds.py top-up --amount 10
"$PY" scripts/trade.py buy --token-id <id> --usd 10
"$PY" scripts/funds.py sweep               # position → safe
# ...after resolution:
"$PY" scripts/redeem.py all
```

## Prerequisites — check before starting, report blocks honestly

- **Signing allowed by the guardrail.** Order signing, CLOB auth, DW batches
  and relayer challenges are all raw-digest signatures, and the safe legs
  (wrap, top-up, redeem) are safe calls — any of them may be refused by the
  operator's guardrail settings, with the violated rule named. You cannot
  lift a restriction — the operator changes it in the agent UI with their
  keystore password; never ask for the password in chat.
- **Polygon configured.** `wallet_info` must list a `polygon` RPC and safe,
  and the EOA needs POL for the safe legs' gas. If missing, tell the
  operator — nothing here can add a chain.
- **Funding.** The operator funds the safe (USDC.e or pUSD) through Pearl.
- **Relayer proxy reachable.** DW operations go through Valory's predict-api
  proxy (Polymarket's DW relayer needs a Builder key that can't ship in a
  desktop app). Override with `POLYMARKET_RELAYER_PROXY_URL` if instructed.
- **Network reachable.** Some ISPs block Polymarket at the DNS level, which
  looks nothing like the venue's 403 — connections hang or fail TLS, and
  every host resolves to one address the ISP owns. Check before blaming the
  venue or the code:

  ```bash
  "$PY" -c "import socket
  for h in ('clob.polymarket.com','gamma-api.polymarket.com','data-api.polymarket.com'):
      print(h, socket.gethostbyname(h))"
  ```

  Three distinct addresses is healthy; one address for all three means the
  network is intercepting the lookup. Report that to the operator — it is
  theirs to fix, and nothing here can route around it.
- **Geoblocking.** Polymarket rejects order placement from the US, UK and
  ~30 other jurisdictions by IP (close-only). A `403`/geoblock error on
  order posting is the venue's policy, not a bug — report it to the operator
  and do not attempt to circumvent it.

## Ground rules

- The safe holds the funds; the DW is a per-trade buffer. **Never leave
  balances or positions in the DW after trading — sweep.**
- `polymarket/state.json` caches the DW address and CLOB API creds
  (revocable API credentials, never key material). Don't commit it; don't
  hand-edit it.
- Amount semantics: buys spend pUSD (`--usd`), sells move shares
  (`--shares`) — same as the Polystrat agent.
- Taker fees are per-market: `fee = shares × rate × (p·(1-p))^exponent`,
  where the rate is 0.07 for crypto, 0.05 for sports/culture, 0.04 for
  politics/finance, 0 for geopolitics (makers pay nothing). The CLOB's
  marketable-order minimum is $1 **after** the fee reserve, so when the DW
  balance equals the bet, a $1 bet shrinks below the minimum and is
  rejected — `trade.py buy` preflights this with the SDK's exact per-market
  sizing and tells you the precise top-up. Resting limit orders reserve the
  same per-market fee on top of `price × size`. In short: **never buy with
  the DW's full balance** — leave the fee room above the bet.
- pUSD has **no unwrap**: the onramp is wrap-only. The exit back to USDC is
  a DEX swap (Uniswap v3 pUSD/USDC pools) or selling positions and
  withdrawing pUSD as-is.
- Report every order response, tx hash and failure honestly. A guardrail
  refusal names the violated rule — relay it to the user rather than
  retrying around it.
- For everything else on-chain (balances via MCP, mech requests, other
  chains), use the pearl-connect skill; this one is Polymarket only.
