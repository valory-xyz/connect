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
#   eval "$(bash scripts/bootstrap_env.sh)"
#   "$PY" scripts/markets.py list

SHARED="$(dirname "${BASH_SOURCE[0]}")/../../../lib/bootstrap_env.sh"
if [ ! -f "$SHARED" ]; then
  echo "echo \"connect-polymarket: shared bootstrap missing at $SHARED\" >&2; false"
  exit 1
fi
# polymarket-client 0.13.0 requires Python 3.11+. The shared bootstrap builds
# the venv with this python3, and on an older one pip only answers "No
# matching distribution found", which reads like a network problem.
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  FOUND="$(python3 --version 2>/dev/null || true)"
  echo "echo \"connect-polymarket: needs Python 3.11+ to build its venv, but python3 is ${FOUND:-missing}\" >&2; false"
  exit 1
fi
exec bash "$SHARED" connect-polymarket CONNECT_POLYMARKET_VENV .bootstrap-complete-polymarket-client-0.13.0 \
  "polymarket-client==0.13.0" "web3>=7.15,<8" requests certifi
