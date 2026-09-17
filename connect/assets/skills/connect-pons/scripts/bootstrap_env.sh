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
#   "$PY" scripts/tokens.py search --query pons

SHARED="$(dirname "${BASH_SOURCE[0]}")/../../../lib/bootstrap_env.sh"
if [ ! -f "$SHARED" ]; then
  echo "echo \"connect-pons: shared bootstrap missing at $SHARED\" >&2; false"
  exit 1
fi
exec bash "$SHARED" connect-pons CONNECT_PONS_VENV .bootstrap-connect-pons \
  "web3>=7.15,<8" certifi
