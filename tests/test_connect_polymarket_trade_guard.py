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

"""Tests that connect-polymarket's trade.py places orders only on v1 markets.

trade.py imports the Polymarket SDK, so these run where tox -e unit-tests
layers it on, and skip elsewhere. The module is loaded under its own name: the
shared conftest puts connect-pons' scripts first on ``sys.path``, where another
``trade`` lives.
"""

# The skill's scripts are imported through sys.path, which mypy cannot follow
# (the skill is excluded from mypy for the same reason), so skip the file.
# mypy: ignore-errors

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

# Without the SDK this file skips, unless CONNECT_REQUIRE_SDK is set: tox's
# SDK run sets it, so a broken overlay fails there. See testenv:unit-tests.
if os.environ.get("CONNECT_REQUIRE_SDK"):
    importlib.import_module("polymarket")
else:
    pytest.importorskip("polymarket")

_SCRIPTS = (
    Path(__file__).resolve().parent.parent
    / "connect"
    / "assets"
    / "skills"
    / "connect-polymarket"
    / "scripts"
)
sys.path.insert(0, str(_SCRIPTS))

import pm_common as pm  # noqa: E402

TOKEN_ID = "12345"  # nosec B105


@pytest.fixture
def trade() -> types.ModuleType:
    """connect-polymarket's trade.py, on the real SDK."""
    spec = importlib.util.spec_from_file_location(
        "connect_polymarket_trade", _SCRIPTS / "trade.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_COMMANDS = {
    "quote": lambda trade: trade.cmd_quote(object(), TOKEN_ID, 1.0, "fok"),
    "buy": lambda trade: trade.cmd_buy(object(), TOKEN_ID, 1.0, "fok"),
    "sell": lambda trade: trade.cmd_sell(object(), TOKEN_ID, 1.0, "fak"),
    "limit-buy": lambda trade: trade.cmd_limit(
        object(), TOKEN_ID, "buy", 0.5, 10.0, "gtc", None
    ),
    "limit-sell": lambda trade: trade.cmd_limit(
        object(), TOKEN_ID, "sell", 0.5, 10.0, "gtc", None
    ),
}


@pytest.mark.parametrize("command", sorted(_COMMANDS))
@pytest.mark.parametrize("listed", [[{"version": "v2"}], [], None])
def test_order_commands_refuse_before_any_client_is_built(
    monkeypatch, trade, command, listed
) -> None:
    """A token no open v1 market lists is refused before the CLOB is touched."""
    runs = []
    monkeypatch.setattr(pm, "http_get_json", lambda url, params=None: listed)
    monkeypatch.setattr(trade, "_run_client", lambda *a, **k: runs.append(a))

    with pytest.raises(SystemExit, match="no open v1 market lists token 12345"):
        _COMMANDS[command](trade)
    assert runs == []


@pytest.mark.parametrize("command", sorted(_COMMANDS))
def test_order_commands_proceed_on_a_v1_market(monkeypatch, trade, command) -> None:
    """A token an open v1 market lists goes on to the CLOB."""
    lookups = []
    runs = []

    def fake_get(url, params=None):
        lookups.append(params)
        return [{"version": "v1"}]

    monkeypatch.setattr(pm, "http_get_json", fake_get)
    monkeypatch.setattr(trade, "_run_client", lambda *a, **k: runs.append(k))

    _COMMANDS[command](trade)
    assert lookups == [{"clob_token_ids": TOKEN_ID}]
    assert len(runs) == 1
    # only the quote, which places nothing, may retry after an auth failure
    assert runs[0].get("retry_auth", True) is (command == "quote")
