#!/usr/bin/env bash
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------
#
# Create-if-missing / reuse-if-present virtualenv for the connect-polymarket
# scripts, plus the TLS trust store they need.
#
#   eval "$(bash scripts/bootstrap_env.sh)"
#   "$PY" scripts/markets.py list
#
# Everything human-readable goes to stderr; stdout carries only shell
# assignments, so the eval above is safe and the script can still be run on
# its own to see what it would do.
#
# The venv is `.venv` at the workspace ROOT — not `.claude/skills/`, which the
# server overwrites on every boot. See SKILL.md for the rest; the one thing
# not written there is why certifi is exported on every run and not only at
# creation: a reused venv needs it just as much.

set -euo pipefail

# `eval "$(...)"` throws the exit status away — it only sees stdout, and
# `eval ""` succeeds — so a failed install would leave $PY unset while the
# caller carried on. Emitting a failing command makes that eval fail loudly.
trap 'echo "echo \"connect-polymarket: bootstrap FAILED, see errors above\" >&2; false"' ERR

# Walk up from a directory looking for the workspace marker.
find_workspace() {
  local dir
  dir="$(cd "$1" 2>/dev/null && pwd)" || return 1
  while :; do
    if [ -f "$dir/.mcp.json" ]; then
      printf '%s\n' "$dir"
      return 0
    fi
    [ "$dir" = "/" ] && return 1
    dir="$(dirname "$dir")"
  done
}

if [ -n "${CONNECT_POLYMARKET_VENV:-}" ]; then
  VENV="$CONNECT_POLYMARKET_VENV"
else
  # cwd first, matching the Python client's search; then the script's own
  # location, so invoking it by absolute path from elsewhere still works.
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  WORKSPACE="$(find_workspace "$PWD" || find_workspace "$SCRIPT_DIR" || true)"
  if [ -z "$WORKSPACE" ]; then
    echo "connect-polymarket: no .mcp.json in the current directory or any" \
      "parent, so the agent workspace could not be located — run this from" \
      "inside the workspace, or set CONNECT_POLYMARKET_VENV to choose the" \
      "venv location yourself" >&2
    false  # not `exit 1`: an explicit exit does NOT fire the ERR trap
  fi
  VENV="$WORKSPACE/.venv"
fi
PY="$VENV/bin/python"
# `python3 -m venv` creates bin/python BEFORE the packages go in, so the
# interpreter proves nothing about whether the venv is usable. This sentinel
# lands only once the installs succeed, so a half-built venv retries (pip is
# idempotent) instead of being reused forever with missing imports.
READY="$VENV/.bootstrap-complete"

# Gate on pip, not just the interpreter. A `python3 -m venv` that dies at the
# ensurepip step (Debian/Ubuntu ship it as a separate python3-venv package)
# still leaves an executable bin/python behind, so checking the interpreter
# alone skips this branch forever after, and every later run reports only
# "bin/pip: No such file or directory" — burying the actionable error the
# first attempt printed. Re-running the create is what keeps that message.
if [ ! -x "$PY" ] || [ ! -x "$VENV/bin/pip" ]; then
  echo "connect-polymarket: creating venv at $VENV" >&2
  python3 -m venv "$VENV" >&2
fi
if [ ! -f "$READY" ]; then
  echo "connect-polymarket: installing dependencies into $VENV" >&2
  "$VENV/bin/pip" install -q --upgrade pip >&2
  "$VENV/bin/pip" install -q \
    "py-clob-client-v2==1.0.2" "web3>=7.15,<8" requests certifi >&2
  touch "$READY"
  echo "connect-polymarket: venv ready" >&2
else
  echo "connect-polymarket: reusing venv at $VENV" >&2
fi

CA_BUNDLE="$("$PY" -c 'import certifi; print(certifi.where())')"

echo "export PY=$(printf '%q' "$PY")"
echo "export SSL_CERT_FILE=$(printf '%q' "$CA_BUNDLE")"
echo "export REQUESTS_CA_BUNDLE=$(printf '%q' "$CA_BUNDLE")"
