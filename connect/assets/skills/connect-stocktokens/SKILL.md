---
name: connect-stocktokens
description: Trade Robinhood Chain Stock Tokens as this Olas Pearl agent — discover pools, quote against Robinhood's own prices, and swap USDG for tokenized equities through the Uniswap Universal Router. All signing goes through the pearl-connect signing service.
---

# Trading Stock Tokens

Robinhood Chain (chain id 4663) carries many **Stock Tokens**: ERC-20s, 18
decimals, issued by Robinhood Assets (Jersey) Ltd, each tracking one US
equity or ETF. They trade 24/7 against **USDG** (Paxos, **6 decimals**) in
ordinary Uniswap pools. No account, no API key, no order book — a swap is
two contract calls the service safe makes.

## Step zero — before researching anything

Call `wallet_info` and confirm `robinhood` is in `actionable_chains`. Do this
before looking at a single ticker: the answer costs one call, and if it is no,
every bit of research after it is wasted.

The safe needs **USDG to trade with and ETH for gas**, both on chain 4663. Read
`not_actionable_because` rather than guessing: no safe and no ETH are the
operator's to fix, so report them and stop.

**Before the first trade, ask once.** Robinhood does not offer Stock Tokens
to US, UK, Canadian or Swiss persons; it enforces that in its own app, not in
the token contracts. Ask the operator whether they are one, and record the
answer in `stocktokens.eligibility.json` in the workspace so you never ask
again. If they are, say that Stock Tokens are not offered to them and do not
trade. Quotes and pool lookups need no answer; only `buy` and `sell` do.

## Python environment

The scripts import `web3`, which the system Python usually lacks. Build the
environment once per shell, then run every script with `$PY`:

```bash
eval "$(bash scripts/bootstrap_env.sh)"   # sets $PY and the TLS trust store
"$PY" scripts/pools.py list --symbol NVDA
```

It creates or reuses `.venv` at the workspace root — the same venv
connect-polymarket uses, so the two skills share it. `CONNECT_STOCKTOKENS_VENV` moves it.
Never install into the system Python. A `ModuleNotFoundError` from these scripts
means this step was skipped, not that a file is missing.

## The flow

```
USDG in safe --approve--> Permit2 --approve--> UniversalRouter --execute--> Stock Token in safe
```

1. `"$PY" scripts/pools.py list --symbol NVDA` — what pools exist for this
   ticker.
2. `"$PY" scripts/swap.py quote --symbol NVDA --usdg 1000` — what they would
   fill at, next to Robinhood's own price.
3. `"$PY" scripts/swap.py buy --symbol NVDA --usdg 1000` — two safe calls:
   ERC-20 approve to Permit2, then the swap. The router's Permit2 allowance
   rides inside the swap as a signed permit rather than costing its own
   transaction.
4. `"$PY" scripts/swap.py sell --symbol NVDA --shares 4.7` — the same in
   reverse.

`"$PY" scripts/pools.py census [--limit 25]` walks the listed tickers and
ranks them by pool depth — the way to answer "where is the liquidity?". Both
`pools.py` commands take `--quote USDG|WETH` (default USDG).

Add `--dry-run` to `buy` or `sell` to print the calls without sending them.
It never asks the signer for anything: the permit carries a placeholder
signature, and the real signature is made only when the trade is sent, so
the printed calls match a real run except for those bytes. `quote` never
sends anything and does not take the flag. Every command takes `--refresh`
to bypass the hour-long pool cache.

**If the signer refuses to sign the permit**, rerun with
`--separate-approvals`: the allowance then goes on-chain as its own
transaction and nothing needs signing. Three calls instead of two. The refusal message says this too; do not try to work around it any other way.

**Re-running is not a no-op.** `buy` and `sell` send fresh transactions every
time: a repeat places another trade. `pools.py` is safe to re-run — it only
reads.

## What the numbers mean

Two prices, and they do not agree:

- **The pool quote** — what a pool would actually fill, read from the deployed
  quoters for the exact size you asked for.
- **Robinhood's REST price** — `GET api.robinhood.com/rhj/prices/{symbol}`,
  the underlying equity's bid/ask, keyless and unauthenticated.

They are in different units. REST quotes the **equity**; one Stock Token is
some number of *shares* of it, read from the token contract's `uiMultiplier()`
at trade time, and that multiplier is not always 1. `swap.py` multiplies REST
prices by it before comparing, and every plan reports it as `multiplier`. If
you mix the two yourself, apply it the same way or your numbers are silently
wrong.

The minimum output is a fraction of **the quote you were shown**, less
slippage — never of the reference, which would hand back the difference
whenever the pool prices better. The reference's job is the gap check, and
the gap is reported as `price_gap_bps` on every plan:

- **over 50 bps** — `price_warning` is set. Tell the operator before trading
  size; it is not a reason to stop.
- **over 150 bps either way** — refused. A pool far *better* than the
  underlying is a broken reading, not a bargain.
- **no usable price at all** — refused. A missing bid, ask, multiplier or
  halt flag is not a gap of zero; a ticker without a reference does not trade.

`--max-gap-bps` moves that limit (up to 1000) and `--slippage` (capped at 5%)
moves the floor. Both are the operator's call, not yours: if a trade is refused, report
the refusal rather than widening the guard that produced it. Every plan records
the values it ran under.

A halted ticker (`isTradingHalt`) is refused outright, and so is a quote
whose halt flag is missing or not a plain true/false. So is a ticker Robinhood
no longer lists as active, lists twice, or lists malformed — that one ticker
is refused with the reason, and every other ticker still trades. An
unreachable or reshaped Robinhood feed is a refusal too.

## Routing, and what it does not do

Every candidate pool is quoted for the real size and the best one wins — v2
pairs, v3 across four fee tiers, and hook-less v4 pools, all discovered from
the factories at call time so a ticker listed an hour ago is tradable.

Two gaps worth knowing before quoting a price to the operator:

- **Hooked v4 pools are invisible here.** They cannot be enumerated without
  an indexer, and few tickers' deepest liquidity lives in them.
- **No splitting.** The whole size goes through one pool; an aggregator would
  spread a large order across several.

The price-gap refusal above is what stops bad priced trades from filling silently.

## Where the code is

`pools.py` and `swap.py` are the commands, and `stocktokens.py` next to them
holds the registry, the reference price and the multiplier — everything that
is Robinhood.

The rest is in `.claude/lib/`: `uniswap.py` (discovery, quoting, router calldata),
`permit.py` (Permit2 and the safe's ERC-1271 wrapper),
`router.py` (the approvals, permit and checked swap call),
`evm.py` (the signer's web3, calls, decimals, ERC-20),
`state.py` (the atomic pool cache write) and `cli.py` (the printed plan).

## Money safety

Approvals are for **this trade's exact amount**. The Permit2 allowance
expires with the swap's own deadline, so it cannot lapse while the swap is
still sendable; the ERC-20 approval to Permit2 that precedes it does not
expire, so a swap that fails after it lands leaves that allowance standing —
say so when you report a failure. Never widen either.
The amount is known before the call is built, so there is no reason to ask for more.

The signed permit is an EIP-712 message the safe authorises through ERC-1271.
The safe's handler expects its own `SafeMessage` wrapper around the Permit2
digest, not the digest itself — `permit.py` derives both.

The swap calldata is decoded and re-checked before it is handed to the signer:
token in, token out, recipient, amount, floor, deadline, the pool it routes
through and that it is a single hop must all match what was planned. The
signed permit is re-read from the same calldata and checked the same way —
token, spender, amount and both time bounds — because the action that
authorises moving funds should not be the one nobody re-reads. A mismatch
raises rather than signs.

Everything goes through the pearl-connect signer — `send_transaction` makes
the **safe** the caller, so the tokens land in the safe.

## Chain notes

- Gas is ETH; blocks are ~100ms.
- The sequencer screens destinations. A screened target is rejected at
  broadcast with "Transaction rejected by chain policy" — no hash, nonce
  untouched. Report it; there is nothing to retry.
- The public RPC rate-limits aggressively. Pool discovery is cached for an
  hour in `stocktokens.pools.json`; do not loop `--refresh`.
