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

"""Decrypt the agent EOA keystore into memory.

The Pearl middleware places the password-encrypted web3 keystore JSON at
./ethereum_private_key.txt in the deployment build dir (the agent's cwd)
and passes the password via --password. The decrypted key exists only inside
the returned LocalAccount.
"""

import json
from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount

from pearl_connect.config import KEYSTORE_FILE


class KeystoreError(Exception):
    """Keystore loading or decryption failure."""


def load_account(password: str, directory: Path | None = None) -> LocalAccount:
    """Load account."""
    directory = directory or Path.cwd()
    path = directory / KEYSTORE_FILE
    if not path.exists():
        raise KeystoreError(f"keystore not found at {path}")
    try:
        keystore = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise KeystoreError(f"keystore at {path} is not valid JSON: {e}") from e
    try:
        private_key = Account.decrypt(keystore, password)
    except (ValueError, KeyError, TypeError) as e:
        # ValueError: wrong password; KeyError/TypeError: not a keystore JSON
        raise KeystoreError(f"failed to decrypt keystore: {e!r}") from e
    return Account.from_key(private_key)  # pylint: disable=no-value-for-parameter
