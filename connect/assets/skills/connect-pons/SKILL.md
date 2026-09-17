---
name: connect-pons
description: Discover, trade and launch memecoins on Pons (ponsfamily.com), the Robinhood Chain launchpad, as this Olas Pearl agent — bonding-curve and Uniswap trades in ETH or USDG, token launches, and creator-fee claims. All signing goes through the pearl-connect signing service.
---

# Trading and launching on Pons

Pons is a memecoin launchpad on Robinhood Chain (chain id 4663). Anyone can
launch a fixed-supply token; the safe can buy, sell and launch with ordinary
contract calls. Memecoins are extremely volatile and most go to zero — say so
when the operator is sizing a position.

Two generations are live, and `tokens.py show` tells you which one a token is:

| | V1 | V2 |
|---|---|---|
| Trades on | a locked Uniswap v3 pool against WETH, from launch | a bonding curve until it sells out, then a locked Uniswap v4 pool |
| Paid in | ETH (wrapped to WETH for you) | the launch's pair asset — ETH, USDG, or another token Pons approved (some launches pair with stock tokens); new launches here use ETH or USDG |
| Launching | closed | open (`launch.py options` says whether the safe may) |
| Audit | — | **none published yet** |

## Step zero — before researching anything

Call `wallet_info` and confirm `robinhood` is in `actionable_chains`. The safe
needs ETH for gas and for ETH-paired trades, and the pair asset for anything
else. Read `not_actionable_because` rather than guessing; no safe or no ETH is
the operator's to fix, so report it and stop.

**Before the first V2 trade or launch, ask once.** Pons's own docs say V2 has
no completed audit. Tell the operator that, ask whether they want to trade it
anyway. Only if they agree, record their answer:

```bash
"$PY" scripts/tokens.py acknowledge-v2 --answer "<their words>"
```

It is stored in `pons.audit.json` and never asked again. If they decline,
record nothing and do not trade or launch V2. Every V2 plan still re-reads the docs and
reports the live audit status under `audit`, so if the reports publish, or the
page cannot be read, you will see it: pass that on. `tokens.py audit` shows the
status and whether the answer is on file. Quotes and lookups need no answer.

## Python environment

```bash
eval "$(bash scripts/bootstrap_env.sh)"   # sets $PY and the TLS trust store
"$PY" scripts/tokens.py search --query pepe
```

It creates or reuses `.venv` at the workspace root, shared with the other
skills; `CONNECT_PONS_VENV` moves it. Never install into the system Python.

## Finding tokens

- `tokens.py search [--query Q] [--sort relevance|marketCap|volume|newest|oldest] [--quote ETH|USDG] [--page N] [--limit N]`
- `tokens.py show --token ADDR` — generation, phase, where it trades, pair
  asset, fees, curve progress towards graduation, the snipe tax right now, and
  Pons's market data.

Discovery asks Pons's website API, then **checks every result on-chain**
before listing it; an item the chain disagrees with is dropped with a note.
The API's prices and market caps are labelled unverified — use them to
orient, never to size a trade; `trade.py quote` prices from the chain.

**If the API is down or changes shape**, the commands say so on stderr, report
`"source": "onchain"`, and fall back to scanning launch events. Tell the
operator. That fallback only covers graduated V2 tokens and recent launches,
and can take a while on the rate-limited public RPC; any other token is still
reachable with `show --token ADDR`.

## Trading

```bash
"$PY" scripts/trade.py quote --token ADDR --spend 0.05      # buy, in the pair asset
"$PY" scripts/trade.py quote --token ADDR --tokens 1000000  # sell
"$PY" scripts/trade.py buy   --token ADDR --spend 0.05 [--dry-run]
"$PY" scripts/trade.py sell  --token ADDR --tokens 1000000 [--dry-run]
```

`--spend` is in the launch's own pair asset — ETH for an ETH launch, USDG for
a USDG launch — never assume. The venue follows the token's phase:

- **curve** (V2, not graduated) — the curve contract directly.
- **v4** (V2, graduated) — its Uniswap v4 pool through the Universal Router;
  the pool charges no fee itself, Pons's hook does.
- **v3** (V1) — its Uniswap v3 pool. A buy wraps ETH first; a sell unwraps
  exactly the WETH it received.
- **none** — graduating right now, or rescued by Pons. Refused, with the reason.

Guards, all of which refuse rather than trade:

- **Snipe tax** — the first seconds of a V2 launch tax buys up to 99%, falling
  to zero. A curve buy is refused while it is above zero; wait and retry.
- **Price impact** over `--max-impact-bps` (default 500, at most 2000).
- **Slippage** — `--slippage` (default 0.5%, at most 5%) sets the floor from
  the quote you were shown.
- A balance that does not cover the trade.

Widening a guard is the operator's call, not yours: report the refusal.
`quote` reports the same numbers without refusing and needs no safe.
Pons fees are on the pair-asset side: a base fee plus any creator tax
(`fee_bps`, `creator_tax_bps` in `show`). The base fee is the curve's before
graduation and the pool hook's after; both are fixed at launch but can differ.

A buy that reaches the end of the curve fills only what is left and refunds
the rest; the curve is then ready to graduate and nothing trades until the
pool opens.

`buy` and `sell` send fresh transactions every time — a rerun trades again.
`--dry-run` prints the calls instead and never asks the signer: the permit
carries a placeholder signature, made for real only when the trade is sent,
so the calls match a real run except for those bytes. `--separate-approvals`
sends the router's Permit2 allowance as its own transaction when the signer
refuses to sign one.

## Launching a token

Launching spends real ETH and cannot be undone. **Never launch on your own
initiative, and never without the operator approving the exact parameters**:
show them the `--dry-run` output — name, symbol, description, socials, pair,
creator tax, buyback, opening buy and slippage — and launch only after a yes.

1. `launch.py options` — whether the safe may launch now (Pons can restrict it
   to a whitelist), the fee (0.0005 ETH today), the pair assets and what each
   graduates at, and the creator-tax cap.
2. **The logo.** Ask the operator for the image: PNG, JPEG or WebP, under
   5 MB, square (existing launches use 512×512). Ask where they want it
   hosted:
   - on Pons — they upload it themselves on ponsfamily.com's create page; Pons
     accepts uploads only from its own site, so you cannot do it for them; or
   - on any IPFS pinning service (Pinata, Filebase, …).

   Either way you need an `ipfs://CID` URI, never an http(s) link. Check it
   with `launch.py check-logo --logo ipfs://CID`; a CID that was only just
   pinned can take a couple of minutes to resolve.
3. `launch.py launch --name N --symbol S --logo ipfs://CID --description D --pair ETH|USDG [--buy X] [--slippage 0.5] [--creator-tax-bps N] [--no-buyback] [--config-id 0] [--twitter … --telegram … --discord … --website … --farcaster …] --dry-run`,
   then, once approved, the same command with `--salt <the salt it printed>`
   in place of `--dry-run`. The salt fixes the addresses: with it the launch
   lands at the token and curve the dry run predicted; without it a fresh
   salt is drawn and they differ. It prints the new token and curve.

Rules the contract enforces, in UTF-8 bytes: name 1–64, symbol 1–16, logo URI
≤ 512, description ≤ 2048, each social ≤ 256.

- **Supply** is always 1 billion tokens, all on the curve; the creator gets no
  allocation except by buying.
- **`--buy X`** launches and buys in one transaction, so nobody trades first,
  and the safe is exempt from the snipe tax. A buy that would take the whole
  curve is refused.
- **Creator tax** is an optional extra fee on every trade, paid to the safe,
  up to the cap `options` shows; it is fixed forever at launch.
- **Buyback** (on unless `--no-buyback`) spends part of the fees buying the
  token back into a 5-year vest.
- The terms `options` showed are pinned: if Pons changes them before the
  transaction lands, the launch reverts instead of settling on terms nobody
  approved. Rerun `options` and ask again.

## Creator fees

- `launch.py fees --token ADDR` — what the fee escrow holds for the safe, and
  what is still waiting on the curve or pool to be swept into it.
- `launch.py claim [--asset ETH|USDG] [--sweep --token ADDR] [--dry-run]` —
  sweep what the safe may, then withdraw.

While buyback or conversion fees are pending, only Pons's own operator can
sweep, so fees on a buyback launch may wait for Pons; `fees` says when.
`creator_claimable` is what the safe receives from sweeping what is pending:
Pons keeps its protocol share of the swept fees, the creator tax is paid in full.

## Money safety

Every approval is for the trade's exact amount, to the one contract that will
spend it. Every call is decoded and checked against the plan before it is
signed, and each is confirmed before the next is sent; a failure names what
already landed — check it before resending. A V1 sell that lands but whose
unwrap fails leaves WETH in the safe; say so.

Everything goes through the pearl-connect signer, so the **safe** is the
caller and receives the tokens.

## Where the code is

`tokens.py`, `trade.py` and `launch.py` are the commands. `pons.py` holds the
addresses, the on-chain launch record, the API client and the audit check;
`discovery.py` the search, with its on-chain fallback index; `curve.py` the bonding-curve maths and calls.
Uniswap routing and constant-product maths, Permit2, chain access, log scans,
the IPFS image check, HTTP and the JSON state files come from `.claude/lib/`
(`uniswap.py`, `router.py`, `permit.py`, `evm.py`, `ipfs.py`, `web.py`,
`state.py`, `cli.py`).

## Chain notes

- Gas is ETH; blocks are ~100 ms.
- The sequencer screens destinations; "Transaction rejected by chain policy"
  means no hash and nothing to retry — report it.
- The public RPC rate-limits hard. Do not loop searches.
