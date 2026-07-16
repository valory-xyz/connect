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

import mimetypes
import typing as t
from pathlib import Path

import pytest
from eth_account.signers.local import LocalAccount
from fastapi.testclient import TestClient

from connect import wallet as wallet_module
from connect import workspace
from connect.activity import ActivityLog
from connect.config import AppConfig
from connect.settings import HARNESSES, MODES
from connect.signer import Signer

from tests.conftest import FakeW3

TOKEN = "unit-test-token"  # nosec B105


def stand_in_page() -> str:
    """Return the bundled stand-in page, read as the source artifact it is.

    Not through GET /: that route serves whatever build sits in assets/ui, and
    the documented integration is to replace it. Asserting the stand-in's own
    markup through the server would mean that following our own instructions
    turns the suite red.
    """
    path = workspace.assets_dir() / workspace.UI_SUBDIR / workspace.UI_INDEX
    return path.read_text(encoding="utf-8")


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


def _complete_bundle(assets: Path) -> None:
    """Give a fake bundle what the workspace provisions from.

    A bundle is not only a UI: without CLAUDE.md and the skills the workspace
    cannot be provisioned, and the server would report itself unhealthy — which
    is exactly what these tests must NOT be measuring.
    """
    (assets / "CLAUDE.md").write_text("brief")
    (assets / "skills").mkdir(exist_ok=True)


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

    def test_bundled_ui_is_served_and_shadows_nothing(
        self,
        make_app: t.Callable,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A UI build in assets/ui is served at /, with the API untouched.

        The whole integration contract: replace what is in that directory,
        change nothing else.
        """
        assets = tmp_path / "assets"
        ui = assets / "ui"
        (ui / "assets").mkdir(parents=True)
        (ui / "index.html").write_text("<!doctype html><title>the real ui</title>")
        (ui / "assets" / "app.js").write_text("console.log('hi')")
        (ui / "assets" / "blob.q7x").write_bytes(b"\x00\x01")  # nothing types this
        _complete_bundle(assets)  # the workspace provisions from it too
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)

        app = make_app(test_signer, app_config, activity)
        # the UI is the last route by construction, not by hope: a router
        # appended below this catch-all would be silently swallowed
        assert app.router.routes[-1].path == "/{asset_path:path}"

        with TestClient(app, base_url="http://127.0.0.1:8716") as client:
            page = client.get("/")
            assert page.status_code == 200
            assert "<title>the real ui</title>" in page.text  # not the stand-in
            assert "Pearl Connect" not in page.text
            asset = client.get("/assets/app.js")
            assert asset.status_code == 200
            # a JavaScript type — the spelling moved from application/ to text/
            # in 3.12, and both are executable; what matters is that it is one
            # of them (see test_content_types_never_come_from_the_machine)
            assert "javascript" in asset.headers["content-type"]
            assert client.get("/").headers["content-type"].startswith("text/html")
            # a build can ship anything; what nothing types, we do not guess at
            binary = client.get("/assets/blob.q7x")
            assert binary.headers["content-type"] == "application/octet-stream"
            # no SPA history fallback: an unknown path is a 404, not index.html
            assert client.get("/dashboard").status_code == 404
            # the API keeps precedence: the UI only sees what no route took
            assert client.get("/healthcheck").json() == {"is_healthy": True}
            assert client.get("/settings").status_code == 200

    def test_content_types_never_come_from_the_machine(
        self,
        make_app: t.Callable,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A hostile mimetypes registry cannot reach what we serve.

        On Windows, mimetypes.guess_type() answers from HKEY_CLASSES_ROOT, so
        the type served for .js would be whatever that machine says. A box that
        maps it to text/plain has the browser refuse to execute the script —
        the UI breaks for that operator alone, on a machine we cannot
        reproduce. This is what the private MimeTypes() buys.
        """
        assets = tmp_path / "assets"
        ui = assets / "ui"
        ui.mkdir(parents=True)
        (ui / "index.html").write_text("<!doctype html>")
        (ui / "app.js").write_text("console.log('hi')")
        _complete_bundle(assets)
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)
        # the registry, at its worst
        monkeypatch.setattr(
            mimetypes, "guess_type", lambda *_a, **_kw: ("text/plain", None)
        )

        with TestClient(
            make_app(test_signer, app_config, activity),
            base_url="http://127.0.0.1:8716",
        ) as client:
            assert "javascript" in client.get("/app.js").headers["content-type"]
            assert client.get("/").headers["content-type"].startswith("text/html")

    def test_the_ui_is_read_once_at_boot(
        self,
        make_app: t.Callable,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A rewrite of index.html after boot does not reach the operator.

        The bundle lives in PyInstaller's extraction dir, writable by the same
        user the agent session runs as — and this is the page where the
        operator types the keystore password, the one secret the whole design
        keeps from the agent. Serving from disk would let a compromised session
        swap the page between two visits, with no restart to notice.
        """
        assets = tmp_path / "assets"
        ui = assets / "ui"
        ui.mkdir(parents=True)
        index = ui / "index.html"
        index.write_text("<!doctype html><title>the shipped page</title>")
        _complete_bundle(assets)
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)

        with TestClient(
            make_app(test_signer, app_config, activity),
            base_url="http://127.0.0.1:8716",
        ) as client:
            index.write_text("<!doctype html><title>password harvester</title>")
            page = client.get("/")
            assert "the shipped page" in page.text
            assert "harvester" not in page.text

    def test_a_ui_is_served_at_root(self, client: TestClient) -> None:
        """Whatever build is bundled, / answers with it — and only that.

        Held to what must be true of ANY build, because the real UI replaces
        this directory: pinning the stand-in's markup here is what would make
        the documented integration ("replace the directory, change nothing
        else") turn the suite red. The stand-in's own contract is pinned
        against the file on disk instead.
        """
        page = client.get("/")
        assert page.status_code == 200
        assert page.headers["content-type"].startswith("text/html")
        # the API keeps precedence: the UI only sees what no route took
        assert client.get("/healthcheck").json() == {"is_healthy": True}
        assert client.get("/settings").status_code == 200

    def test_the_stand_in_ui_matches_the_api_it_drives(
        self, client: TestClient
    ) -> None:
        """The page's contract with the server, pinned.

        Nothing in the Python suite executes this page's JavaScript, and it is
        the operator's only way to change the guardrail. So at least hold it to
        the endpoints it calls, the fields its script reads, and — above all —
        the literal values it sends: renaming any of them would otherwise break
        the control surface with every test still green.
        """
        page = stand_in_page()
        for endpoint in ('fetch("/settings")', 'fetch("/settings"', 'fetch("/session"'):
            assert endpoint in page
        # it waits for the workspace before offering a session, as the server
        # 503s until then (and as docs/agent-ui.md tells the real UI to)
        assert 'fetch("/healthcheck")' in page
        # the inputs its script reads by name: renaming one silently breaks it
        for field in ('name="mode"', 'name="password"', 'name="harness"'):
            assert field in page
        # the values it actually submits must be values the API accepts — this
        # is the control surface, and a typo here is invisible to every other
        # test in the suite
        for mode in MODES:
            assert f'name="mode" value="{mode}"' in page
        for harness in HARNESSES:
            assert f'name="harness" value="{harness}"' in page
        # and it must not offer to edit what the API refuses: a whitelist in a
        # patch is a 422, so a whitelist input here would fail every save
        assert 'name="whitelist"' not in page
        # the canonical shape it renders, exactly as GET /settings returns it
        served = client.get("/settings").json()
        assert set(served) == {"protected", "harness"}
        assert set(served["protected"]) == {"mode", "whitelist"}

    def test_the_stand_in_offers_nothing_it_cannot_yet_do(self) -> None:
        """Every control starts disabled, and its button is bindable.

        A radio group nobody has touched reads .value as "", so a form left
        live over a failed GET /settings would either send mode:"" — burning a
        keystore decrypt to earn a 400 — or flip the guardrail from a page that
        never read it. And an element emitted after the inline script is null
        when the handler runs, so the button would look right and do nothing.
        """
        page = stand_in_page()
        for control in ("settings-apply", "harness-apply", "open-session"):
            button = page[page.index(f'id="{control}"') :]
            assert "disabled" in button[: button.index(">")]
        assert 0 < page.index('id="open-session"') < page.index("<script>")

    def test_api_survives_a_bundle_without_a_ui(
        self,
        make_app: t.Callable,
        test_signer: Signer,
        app_config: AppConfig,
        activity: ActivityLog,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bundle with no UI at all still serves the agent, just no page."""
        assets = tmp_path / "assets"
        assets.mkdir()
        _complete_bundle(assets)
        monkeypatch.setattr(workspace, "assets_dir", lambda: assets)
        with TestClient(
            make_app(test_signer, app_config, activity),
            base_url="http://127.0.0.1:8716",
        ) as client:
            assert client.get("/").status_code == 404
            assert client.get("/healthcheck").json() == {"is_healthy": True}

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

    def test_safe_transaction(self, client: TestClient, fake_w3: FakeW3) -> None:
        """The route names the inner call; the server composes the safe's tx."""
        response = client.post(
            "/safe-transaction",
            json={"chain": "testchain", "to": "0x" + "aa" * 20, "value": "0x10"},
            headers=auth(),
        )
        assert response.status_code == 200
        assert response.json()["tx_hash"].startswith("0x")
        assert len(fake_w3.eth.sent) == 1

    def test_safe_transaction_without_a_safe_is_400(
        self, client: TestClient, fake_w3: FakeW3
    ) -> None:
        """A chain we cannot spend from is the caller's problem, not a 500."""
        response = client.post(
            "/safe-transaction",
            json={"chain": "mystery", "to": "0x" + "aa" * 20},
            headers=auth(),
        )
        assert response.status_code == 400
        assert not fake_w3.eth.sent

    def test_safe_transaction_malformed_input_is_400_not_500(
        self, client: TestClient, fake_w3: FakeW3
    ) -> None:
        """Compose-time errors map to 400, like the sibling /sign-and-send path.

        The inner call is ABI-encoded before the send, so a bad target or an
        oversized value must not leak out as an unhandled 500.
        """
        bad_target = client.post(
            "/safe-transaction",
            json={"chain": "testchain", "to": "0x1234"},
            headers=auth(),
        )
        assert bad_target.status_code == 400
        huge_value = client.post(
            "/safe-transaction",
            json={"chain": "testchain", "to": "0x" + "aa" * 20, "value": 2**256},
            headers=auth(),
        )
        assert huge_value.status_code == 400
        assert not fake_w3.eth.sent

    def test_sign_and_send_unknown_chain_is_400(self, client: TestClient) -> None:
        """Test sign and send unknown chain is 400."""
        response = client.post(
            "/sign-and-send",
            json={"chain": "mystery", "to": "0x" + "aa" * 20},
            headers=auth(),
        )
        assert response.status_code == 400
