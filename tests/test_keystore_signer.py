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

"""Test keystore signer module."""

import threading
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.signers.local import LocalAccount
from hexbytes import HexBytes

from pearl_connect.activity import ActivityLog
from pearl_connect.keystore import KeystoreError, load_account
from pearl_connect.signer import Signer, SignerError

from tests.conftest import FakeW3, TEST_PASSWORD, audit_kinds


class TestKeystore:
    """TestKeystore."""

    def test_decrypt(self, keystore_dir: Path, account: LocalAccount) -> None:
        """Test decrypt."""
        loaded = load_account(TEST_PASSWORD, keystore_dir)
        assert loaded.address == account.address

    def test_wrong_password(self, keystore_dir: Path) -> None:
        """Test wrong password."""
        with pytest.raises(KeystoreError, match="decrypt"):
            load_account("wrong", keystore_dir)

    def test_missing_file(self, tmp_path: Path) -> None:
        """Test missing file."""
        with pytest.raises(KeystoreError, match="not found"):
            load_account(TEST_PASSWORD, tmp_path / "nope")


class TestSigner:
    """TestSigner."""

    def test_send_returns_hash_and_logs(
        self,
        store_path: Path,
        test_signer: Signer,
        fake_w3: FakeW3,
        activity: ActivityLog,
    ) -> None:
        """Test send returns hash and logs."""
        tx_hash = test_signer.send("testchain", to="0x" + "aa" * 20, value=1)
        assert tx_hash.startswith("0x")
        assert len(tx_hash) == 66
        assert len(fake_w3.eth.sent) == 1
        kinds = audit_kinds(store_path)
        assert "transaction" in kinds

    def test_request_id_idempotency(self, test_signer: Signer, fake_w3: FakeW3) -> None:
        """Test request id idempotency."""
        first = test_signer.send("testchain", to="0x" + "aa" * 20, request_id="r-1")
        second = test_signer.send("testchain", to="0x" + "aa" * 20, request_id="r-1")
        assert first == second
        assert len(fake_w3.eth.sent) == 1  # broadcast exactly once

    def test_failed_send_resyncs_nonce_from_node(
        self, test_signer: Signer, fake_w3: FakeW3
    ) -> None:
        """A failed send drops the local counter so the next send re-reads pending."""
        test_signer.send("testchain", to="0x" + "aa" * 20)  # local counter -> 6
        fake_w3.eth.fail_broadcast = True
        with pytest.raises(SignerError):
            test_signer.send("testchain", to="0x" + "aa" * 20)
        fake_w3.eth.fail_broadcast = False
        test_signer.send("testchain", to="0x" + "aa" * 20)
        nonces = [_tx_nonce(raw) for raw in fake_w3.eth.sent]
        # the retry resynced from the node's pending count (still 5), instead
        # of continuing from the stale local counter (which would send 6)
        assert nonces == [5, 5]

    def test_nonces_are_sequential_under_concurrency(
        self, test_signer: Signer, fake_w3: FakeW3, account: LocalAccount
    ) -> None:
        """Test nonces are sequential under concurrency."""
        threads = [
            threading.Thread(
                target=test_signer.send,
                args=("testchain",),
                kwargs={"to": "0x" + "aa" * 20},
            )
            for _ in range(8)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        nonces = sorted(_tx_nonce(raw) for raw in fake_w3.eth.sent)
        start = fake_w3.eth.pending_nonce
        assert nonces == list(range(start, start + 8))

    def test_unknown_chain(self, test_signer: Signer) -> None:
        """Test unknown chain."""
        with pytest.raises(ValueError, match="unknown chain"):
            test_signer.send("mystery", to="0x" + "aa" * 20)

    def test_sign_digest_recovers_to_eoa(
        self, test_signer: Signer, account: LocalAccount
    ) -> None:
        """Test sign digest recovers to eoa."""
        digest = bytes(range(32))
        signature = test_signer.sign_digest(digest)
        recovered = Account._recover_hash(digest, signature=HexBytes(signature))
        assert recovered == account.address

    def test_sign_digest_rejects_bad_length(self, test_signer: Signer) -> None:
        """Test sign digest rejects bad length."""
        with pytest.raises(SignerError, match="32 bytes"):
            test_signer.sign_digest(b"short")


def _tx_nonce(raw: bytes) -> int:
    """Extract the nonce from a signed typed (EIP-1559) transaction."""
    import rlp

    assert raw[0] == 2  # typed tx envelope
    fields = rlp.decode(raw[1:])
    return int.from_bytes(fields[1], "big")
