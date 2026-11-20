#!/usr/bin/env bash
# Boot the built binary as Pearl would and wait for it to report itself healthy.
# Usage: packaging/boot_check.sh <binary>
set -euo pipefail

binary=$(realpath "$1")
repo=$PWD
work=$(mktemp -d)
cd "$work"
mkdir store

uv run --project "$repo" --locked python -c "
import json
from eth_account import Account
key = Account.create().key
open('ethereum_private_key.txt', 'w').write(json.dumps(Account.encrypt(key, 'boot-check')))
"

export CONNECTION_LEDGER_CONFIG_LEDGER_APIS_GNOSIS_ADDRESS=http://127.0.0.1:9
export CONNECTION_CONFIGS_CONFIG_STORE_PATH="$work/store"
export CONNECTION_CONFIGS_CONFIG_SAFE_CONTRACT_ADDRESSES='{"gnosis":"0x0000000000000000000000000000000000000001"}'

printf boot-check | "$binary" --password-stdin >boot.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT

for _ in $(seq 60); do
  if [ "$(curl -sf http://127.0.0.1:8716/healthcheck || true)" = '{"is_healthy":true}' ]; then
    echo "healthy"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    break
  fi
  sleep 1
done
cat boot.log
echo "the binary never reported itself healthy" >&2
exit 1
