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

"""Test endpoints module."""

import typing as t

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from pearl_connect import wallet as wallet_module
from pearl_connect import workspace
from pearl_connect.activity import ActivityLog
from pearl_connect.config import AppConfig
from pearl_connect.signer import Signer

from tests.conftest import FakeW3

TOKEN = "unit-test-token"  # nosec B105


@pytest.fixture
def client(
    test_signer: Signer,
    app_config: AppConfig,
    activity: ActivityLog,
    make_app: t.Callable,
) -> t.Iterator[TestClient]:
    """Client."""
    app = make_app(test_signer, app_config, activity, token=TOKEN)
    with TestClient(app, base_url="http://127.0.0.1:8716") as client:
        yield client


def auth(extra: dict | None = None) -> dict:
    """Auth."""
    return {"Authorization": f"Bearer {TOKEN}", **(extra or {})}


class TestOpenEndpoints:
    """TestOpenEndpoints."""

    def test_healthcheck(self, client: TestClient) -> None:
        """Test healthcheck."""
        response = client.get("/healthcheck")
        assert response.status_code == 200
        # is_healthy is the only field the middleware's HealthChecker reads;
        # no decorative FSM fields (rounds, transition counters)
        assert response.json() == {"is_healthy": True}

    def test_healthcheck_reports_unready(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Health is the FE's cue to open a session, so it must not lie.

        POST /session lands the moment this turns true; a server whose
        workspace it could not build says so, and refuses the session it could
        not have honored — naming the reason, not an opaque "unhealthy".
        """
        monkeypatch.setattr(
            workspace.Workspace,
            "_provision",
            lambda self: (_ for _ in ()).throw(OSError("store volume not mounted")),
        )
        assert client.get("/healthcheck").json() == {"is_healthy": False}
        session = client.post("/session")
        assert session.status_code == 503
        assert "store volume not mounted" in session.json()["detail"]

    def test_a_transient_workspace_failure_heals_itself(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A boot failure that clears on its own must not need a restart.

        Pearl only calls POST /session once we report healthy, so a server that
        can never become healthy is never asked to heal — the retry has to sit
        on the poller's path, or one unlucky boot bricks the agent until
        somebody restarts it.
        """
        state = client.app.state  # type: ignore[attr-defined]
        attempts: list[int] = []

        def flaky(self: workspace.Workspace) -> None:
            attempts.append(1)
            if len(attempts) == 1:  # the store volume was still mounting
                raise OSError("store volume not mounted")

        monkeypatch.setattr(workspace.Workspace, "_provision", flaky)
        assert client.get("/healthcheck").json() == {"is_healthy": False}
        assert client.get("/healthcheck").json() == {"is_healthy": True}
        assert state.workspace.reason is None
        # and healthy stays healthy: no repopulating on every poll thereafter
        assert client.get("/healthcheck").json() == {"is_healthy": True}
        assert len(attempts) == 2

    def test_funds_status_empty_without_requirements(self, client: TestClient) -> None:
        """Test funds status empty without requirements."""
        response = client.get("/funds-status")
        assert response.status_code == 200
        assert response.json() == {}

    def test_funds_status_shape(
        self, client: TestClient, app_config: AppConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test funds status shape."""
        app_config.fund_requirements = {"testchain": {"agent": {"0x" + "00" * 20: 100}}}
        monkeypatch.setattr(wallet_module, "asset_balance", lambda *a, **k: (40, 18))
        response = client.get("/funds-status")
        assert response.status_code == 200
        body = response.json()
        (chain_entry,) = body.values()
        (asset_entry,) = list(chain_entry.values())[0].values()
        assert asset_entry == {"balance": "40", "deficit": "60", "decimals": 18}

    def test_index_html_has_no_token(self, client: TestClient) -> None:
        """Test index html has no token."""
        response = client.get("/")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/html")
        assert TOKEN not in response.text


class TestAuth:
    """TestAuth."""

    def test_wallet_requires_token(self, client: TestClient) -> None:
        """Test wallet requires token."""
        assert client.get("/wallet").status_code == 401
        assert (
            client.get("/wallet", headers={"Authorization": "Bearer nope"}).status_code
            == 401
        )

    def test_non_ascii_token_is_401_not_500(self, client: TestClient) -> None:
        """A malformed (non-ASCII) bearer header is a clean 401, not a crash.

        hmac.compare_digest raises TypeError on non-ASCII strs; the header is
        sent as latin-1 bytes because that is what the wire allows and how
        Starlette decodes it.
        """
        response = client.get(
            "/wallet", headers={b"Authorization": "Bearer é".encode("latin-1")}
        )
        assert response.status_code == 401

    def test_wallet_with_token(
        self, client: TestClient, test_signer: Signer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test wallet with token."""
        monkeypatch.setattr(
            wallet_module,
            "wallet_overview",
            lambda config, signer: {"agent_eoa": signer.address},
        )
        response = client.get("/wallet", headers=auth())
        assert response.status_code == 200
        assert response.json()["agent_eoa"] == test_signer.address

    def test_cross_origin_rejected_even_with_token(self, client: TestClient) -> None:
        """Test cross origin rejected even with token."""
        response = client.get(
            "/wallet", headers=auth({"Origin": "https://evil.example"})
        )
        assert response.status_code == 403

    def test_local_origin_accepted(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test local origin accepted."""
        monkeypatch.setattr(wallet_module, "wallet_overview", lambda c, s: {})
        response = client.get(
            "/wallet", headers=auth({"Origin": "http://localhost:8716"})
        )
        assert response.status_code == 200

    def test_mcp_mount_requires_token(self, client: TestClient) -> None:
        """Test mcp mount requires token."""
        assert client.post("/mcp/", json={}).status_code == 401

    def test_sign_message_roundtrip(
        self, client: TestClient, account: LocalAccount
    ) -> None:
        """Test sign message roundtrip."""
        digest = "0x" + "ab" * 32
        response = client.post("/sign-message", json={"digest": digest}, headers=auth())
        assert response.status_code == 200
        assert len(bytes.fromhex(response.json()["signature"][2:])) == 65

    def test_sign_and_send(self, client: TestClient, fake_w3: FakeW3) -> None:
        """Test sign and send."""
        response = client.post(
            "/sign-and-send",
            json={"chain": "testchain", "to": "0x" + "aa" * 20, "value": "0x10"},
            headers=auth(),
        )
        assert response.status_code == 200
        assert response.json()["tx_hash"].startswith("0x")
        assert len(fake_w3.eth.sent) == 1

    def test_sign_and_send_unknown_chain_is_400(self, client: TestClient) -> None:
        """Test sign and send unknown chain is 400."""
        response = client.post(
            "/sign-and-send",
            json={"chain": "mystery", "to": "0x" + "aa" * 20},
            headers=auth(),
        )
        assert response.status_code == 400
