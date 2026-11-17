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

"""Write a file only its owner can read, atomically.

Shared by workspace.py (the token-bearing configs) and ocb.py (the install
record), which may not import each other.
"""

from pathlib import Path


def write_private(path: Path, text: str) -> None:
    """Atomically replace a file, readable by its owner alone."""
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.unlink(missing_ok=True)  # a stale tmp may have looser permissions
    tmp.touch(mode=0o600)
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)
