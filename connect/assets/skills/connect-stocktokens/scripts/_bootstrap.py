# -*- coding: utf-8 -*-
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

"""Put the lib/ beside skills/ on the path; import this before any shared module."""

import importlib.util
import sys
from pathlib import Path

LIB = Path(__file__).resolve().parents[3] / "lib"
if not (LIB / "evm.py").is_file():
    raise ImportError(
        f"connect-stocktokens needs the shared modules the connect server installs "
        f"beside skills/; expected evm.py under {LIB}"
    )
if importlib.util.find_spec("web3") is None:
    raise ImportError(
        "connect-stocktokens needs web3>=7.15,<8 in the interpreter running it; "
        "see the Environment section of SKILL.md"
    )
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))
