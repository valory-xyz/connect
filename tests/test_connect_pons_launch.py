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

"""Unit tests for the connect-pons skill's launch and creator-fee script."""

import argparse
import json
import sys
import typing as t

import pytest
from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address
from web3 import Web3

from tests.conftest import (
    _v2_record,
    curve,
    evm,
    ipfs,
    launch,
    pons,
)

SAFE = to_checksum_address("0x" + "5a" * 20)
OTHER = to_checksum_address("0x" + "0b" * 20)
TOKEN = to_checksum_address("0x" + "7c" * 20)
CURVE = to_checksum_address("0x" + "c0" * 20)
POOL_ID = "0x" + "ab" * 32
FEE = 5 * 10**14
SUPPLY = 10**27
PHANTOM = 168 * 10**16
THRESHOLD = 42 * 10**17
ECONOMICS = b"\xee" * 32
LOGO = "ipfs://bafkreiar3qgowwjij2a2cccofut7lxba6r55tzrz7oaawcizngeuct55je"
TX_HASH = "0x" + "12" * 32
DOCS_LAUNCH_AND_BUY_ABI = [
    {
        "type": "function",
        "name": "launchAndBuy",
        "stateMutability": "payable",
        "inputs": [
            {
                "name": "params",
                "type": "tuple",
                "components": [
                    {"name": "name", "type": "string"},
                    {"name": "symbol", "type": "string"},
                    {"name": "logo", "type": "string"},
                    {"name": "description", "type": "string"},
                    {
                        "name": "socials",
                        "type": "tuple",
                        "components": [
                            {"name": n, "type": "string"} for n in launch.SOCIALS
                        ],
                    },
                    {"name": "creatorFeeRecipient", "type": "address"},
                    {"name": "creatorTaxBps", "type": "uint16"},
                    {"name": "buybackEnabled", "type": "bool"},
                    {"name": "expectedEconomics", "type": "bytes32"},
                    {"name": "salt", "type": "bytes32"},
                ],
            },
            {"name": "launchConfigId", "type": "uint256"},
            {"name": "pairToken", "type": "address"},
            {"name": "quoteIn", "type": "uint256"},
            {"name": "minTokensOut", "type": "uint256"},
            {"name": "recipient", "type": "address"},
            {"name": "snipeTaxExemptions", "type": "address[]"},
        ],
        "outputs": [],
    }
]


def word(*values: t.Any) -> bytes:
    """ABI-encode each value as one word."""
    out = b""
    for value in values:
        if isinstance(value, bool):
            out += abi_encode(["bool"], [value])
        elif isinstance(value, bytes):
            out += value.rjust(32, b"\0")
        elif isinstance(value, str):
            out += abi_encode(["address"], [value])
        else:
            out += abi_encode(["int256"], [value])
    return out


def data_of(sel: bytes, types: list[str], args: list[t.Any]) -> bytes:
    """Calldata the script would send for one read."""
    return sel + abi_encode(types, args)


class FakeEth:
    """An eth namespace answering eth_call from a table."""

    def __init__(self, answers: dict[tuple[str, bytes], t.Any]) -> None:
        """Keep the table keyed by (target, calldata or selector)."""
        self.answers = {(to.lower(), data): a for (to, data), a in answers.items()}
        self.balance = 10**18
        self.receipt: dict[str, t.Any] = {"logs": []}
        self.requests: list[dict[str, t.Any]] = []

    def call(self, tx: dict[str, t.Any]) -> bytes:
        """Answer from the table by full calldata, then by selector."""
        self.requests.append(tx)
        data = tx["data"]
        raw = bytes.fromhex(data[2:]) if isinstance(data, str) else bytes(data)
        to = tx["to"].lower()
        answer = self.answers.get((to, raw), self.answers.get((to, raw[:4])))
        if answer is None:
            raise AssertionError(f"unexpected call to {to}: {raw.hex()}")
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get_balance(self, _: str) -> int:
        """Return the safe's native balance."""
        return self.balance


class FakeW3:
    """Just enough of Web3 for the script."""

    def __init__(self, answers: dict[tuple[str, bytes], t.Any]) -> None:
        """Wrap a FakeEth."""
        self.eth = FakeEth(answers)


class FakeSigner:
    """A signer that only knows the safe address."""

    def chain_info(self, chain: str) -> dict[str, str]:
        """Return the safe on the skill's chain."""
        assert chain == pons.CHAIN
        return {"safe": SAFE}


def factory_answers(**over: t.Any) -> dict[tuple[str, bytes], t.Any]:
    """Live-like factory, USDG and simulation answers."""
    factory = pons.V2_FACTORY
    answers: dict[tuple[str, bytes], t.Any] = {
        (factory, launch.SEL_CONFIG_COUNT): word(over.get("configs", 1)),
        (factory, launch.SEL_GET_CONFIG): word(
            SUPPLY, 100, PHANTOM, THRESHOLD, 0, 200, over.get("enabled", True)
        ),
        (factory, launch.SEL_LAUNCH_FEE): word(FEE),
        (factory, launch.SEL_MAX_CREATOR_TAX): word(1000),
        (factory, launch.SEL_CAN_LAUNCH): word(over.get("can_launch", True)),
        (factory, launch.SEL_APPROVED_PAIR): word(over.get("approved", True)),
        (factory, launch.SEL_PAIR_ECONOMICS): word(3236 * 10**6, 8090 * 10**6, 6),
        (factory, launch.SEL_PREVIEW_ECONOMICS): ECONOMICS,
        (factory, launch.SEL_LAUNCH): word(TOKEN, CURVE),
        (pons.LAUNCH_ROUTER, launch.SEL_LAUNCH_AND_BUY): word(TOKEN, CURVE),
        (pons.USDG, evm.SEL_DECIMALS): word(6),
        (pons.USDG, evm.SEL_BALANCE_OF): word(over.get("usdg", 10**9)),
    }
    return answers


def run(command: str, args: argparse.Namespace) -> int:
    """Run one of the script's subcommands."""
    result: int = getattr(launch, f"_cmd_{command}")(args)
    return result


def launch_args(**over: t.Any) -> argparse.Namespace:
    """Arguments for a plain ETH launch."""
    values = {
        "name": "Probe",
        "symbol": "PRB",
        "logo": LOGO,
        "description": "a probe",
        "twitter": "",
        "telegram": "",
        "discord": "",
        "website": "https://example.org",
        "farcaster": "",
        "pair": "ETH",
        "buy": 0.0,
        "creator_tax_bps": 0,
        "no_buyback": False,
        "config_id": 0,
        "slippage": 0.5,
        "salt": None,
        "dry_run": False,
    }
    values.update(over)
    return argparse.Namespace(**values)


def sample_params(creator: str = SAFE) -> launch.TokenParams:
    """Build a TokenParams tuple with every field set."""
    meta = {
        "name": "Probe",
        "symbol": "PRB",
        "logo": LOGO,
        "description": "d",
        **{s: s for s in launch.SOCIALS},
    }
    return launch.token_params(meta, creator, 25, True, ECONOMICS, b"\x01" * 32)


@pytest.fixture(name="logo_ok")
def _logo_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the logo check always pass."""
    monkeypatch.setattr(launch, "check_logo", lambda uri: {"uri": uri})


@pytest.mark.parametrize(
    ("square", "warning"),
    [(True, ""), (None, ""), (False, "not square; Pons crops logos")],
)
def test_check_logo_warns_when_pons_would_crop(
    monkeypatch: pytest.MonkeyPatch, square: t.Optional[bool], warning: str
) -> None:
    """Only a known non-square logo is flagged, and the image check sends our agent."""
    seen: list[str] = []

    def check(uri: str, user_agent: str) -> dict:
        """Report the scripted shape."""
        seen.append(user_agent)
        return {"uri": uri, "square": square}

    monkeypatch.setattr(ipfs, "check_image", check)
    assert launch.check_logo(LOGO) == {
        "uri": LOGO,
        "square": square,
        "warning": warning,
    }
    assert seen == [pons.USER_AGENT]


def test_launch_selector_matches_the_docs_signature() -> None:
    """The factory selector is the one the docs' ABI produces."""
    docs = (
        "launchToken((string,string,string,string,(string,string,string,string,"
        "string),address,uint16,bool,bytes32,bytes32),uint256,address)"
    )
    assert launch.SEL_LAUNCH == keccak(text=docs)[:4]


def test_launch_and_buy_encoding_matches_web3() -> None:
    """Our router calldata is byte-identical to web3's encoder on the docs ABI."""
    params = sample_params()
    buy = launch.Buy(10**16, 123, SAFE)
    ours = launch.build_launch_call(params, 0, evm.NATIVE, FEE, buy)
    contract = Web3().eth.contract(abi=DOCS_LAUNCH_AND_BUY_ABI)
    theirs = contract.encode_abi(
        "launchAndBuy", args=[params, 0, evm.NATIVE, 10**16, 123, SAFE, []]
    )
    assert ours["data"] == theirs
    assert ours["to"] == pons.LAUNCH_ROUTER
    assert ours["value"] == FEE + 10**16


@pytest.mark.parametrize(
    ("pair", "buy", "value"),
    [
        (evm.NATIVE, None, FEE),
        (evm.NATIVE, launch.Buy(7, 3, SAFE), FEE + 7),
        (pons.USDG, launch.Buy(7, 3, SAFE), FEE),
        (pons.USDG, None, FEE),
    ],
)
def test_built_launch_calls_verify(
    pair: str, buy: t.Optional[launch.Buy], value: int
) -> None:
    """Every shape we build decodes back to exactly the plan."""
    params = sample_params()
    call = launch.build_launch_call(params, 0, pair, FEE, buy)
    assert call["value"] == value
    launch.verify_launch_call(call, params, 0, pair, FEE, buy)


def test_token_params_encode_as_the_factory_struct() -> None:
    """The named struct encodes exactly as the plain tuple it stands for."""
    params = sample_params()
    assert params.socials.website == "website"
    plain = tuple(params[:4]) + (tuple(params.socials),) + tuple(params[5:])
    assert abi_encode([launch.PARAMS_TUPLE], [params]) == abi_encode(
        [launch.PARAMS_TUPLE], [plain]
    )


def test_verify_catches_tampering() -> None:
    """A changed field, value or minimum is refused."""
    params = sample_params()
    buy = launch.Buy(7, 3, SAFE)
    call = launch.build_launch_call(params, 0, evm.NATIVE, FEE, buy)
    with pytest.raises(evm.SwapError, match="minimum out"):
        launch.verify_launch_call(
            call, params, 0, evm.NATIVE, FEE, buy._replace(min_tokens_out=4)
        )
    with pytest.raises(evm.SwapError, match="value"):
        launch.verify_launch_call(
            {**call, "value": FEE}, params, 0, evm.NATIVE, FEE, buy
        )
    other = params._replace(symbol="Other")
    with pytest.raises(evm.SwapError, match="params"):
        launch.verify_launch_call(call, other, 0, evm.NATIVE, FEE, buy)
    plain = launch.build_launch_call(params, 0, evm.NATIVE, FEE, None)
    with pytest.raises(evm.SwapError, match="config"):
        launch.verify_launch_call(plain, params, 1, evm.NATIVE, FEE, None)


def test_verify_refuses_zero_minimum_and_zero_creator() -> None:
    """No floor and no fee recipient are both refused."""
    params = sample_params()
    buy = launch.Buy(7, 0, SAFE)
    call = launch.build_launch_call(params, 0, evm.NATIVE, FEE, buy)
    with pytest.raises(evm.SwapError, match="no minimum"):
        launch.verify_launch_call(call, params, 0, evm.NATIVE, FEE, buy)
    nobody = sample_params(evm.NATIVE)
    call = launch.build_launch_call(nobody, 0, evm.NATIVE, FEE, None)
    with pytest.raises(evm.SwapError, match="creator fee recipient"):
        launch.verify_launch_call(call, nobody, 0, evm.NATIVE, FEE, None)


def test_errors_name_the_factory_reverts() -> None:
    """The error table covers the factory's custom errors."""
    assert len(launch.ERRORS) > 30
    slip = evm.selector("SlippageExceeded(uint256,uint256)") + word(5, 6)
    assert evm.describe_revert("0x" + slip.hex(), launch.ERRORS) == (
        "SlippageExceeded(5, 6)"
    )


def test_launch_config_and_pair_economics() -> None:
    """Configs are read by id; pairs resolve their own economics."""
    w3 = FakeW3(factory_answers())
    config = launch.launch_config(w3, 0)  # type: ignore[arg-type]
    assert config["phantom_quote"] == PHANTOM
    assert config["tick_spacing"] == 200
    with pytest.raises(evm.SwapError, match="does not exist"):
        launch.launch_config(w3, 1)  # type: ignore[arg-type]
    assert launch.pair_economics(w3, evm.NATIVE, config) == (PHANTOM, THRESHOLD)  # type: ignore[arg-type]
    assert launch.pair_economics(w3, pons.USDG, config) == (3236 * 10**6, 8090 * 10**6)  # type: ignore[arg-type]
    refused = FakeW3(factory_answers(approved=False))
    with pytest.raises(evm.SwapError, match="not an approved"):
        launch.pair_economics(refused, pons.USDG, config)  # type: ignore[arg-type]


@pytest.mark.parametrize("field", ["phantom_quote", "graduation_threshold"])
def test_native_pair_refuses_a_config_without_economics(field: str) -> None:
    """A zeroed native config is refused rather than dividing by zero later."""
    w3 = FakeW3(factory_answers())
    config = {**launch.launch_config(w3, 0), field: 0}  # type: ignore[arg-type]
    with pytest.raises(evm.SwapError, match="no native ETH economics"):
        launch.pair_economics(w3, evm.NATIVE, config)  # type: ignore[arg-type]


def test_short_read_is_refused() -> None:
    """An answer too short for its shape is an error, not zeros."""
    answers = factory_answers()
    answers[(pons.V2_FACTORY, launch.SEL_PAIR_ECONOMICS)] = word(1)
    config = launch.launch_config(FakeW3(answers), 0)  # type: ignore[arg-type]
    with pytest.raises(evm.SwapError, match="returned 32 bytes"):
        launch.pair_economics(FakeW3(answers), pons.USDG, config)  # type: ignore[arg-type]


def test_options_reports_live_terms(monkeypatch: pytest.MonkeyPatch) -> None:
    """Options lists configs, pairs, limits and the audit state."""
    monkeypatch.setattr(pons, "audit_status", lambda: {"status": "unaudited"})
    monkeypatch.setattr(pons, "v2_acknowledged", lambda: False)
    report = launch.options(FakeW3(factory_answers()), SAFE)  # type: ignore[arg-type]
    assert report["can_launch"] is True
    assert report["launch_fee_eth"] == 0.0005
    assert [p["usable"] for p in report["pairs"]] == [True, True]
    assert report["pairs"][1]["phantom_quote"] == 3236
    assert report["metadata_limits_bytes"]["symbol"] == 16
    refused = launch.options(FakeW3(factory_answers(approved=False)), SAFE)  # type: ignore[arg-type]
    assert refused["pairs"][1]["usable"] is False
    assert "not an approved" in refused["pairs"][1]["reason"]


def test_disabled_configs_are_not_offered(monkeypatch: pytest.MonkeyPatch) -> None:
    """A disabled config stays out of the options."""
    monkeypatch.setattr(pons, "audit_status", dict)
    monkeypatch.setattr(pons, "v2_acknowledged", lambda: True)
    reason = "the factory has no enabled launch config, so nothing can launch"
    for answers in (factory_answers(enabled=False), factory_answers(configs=0)):
        report = launch.options(FakeW3(answers), SAFE)  # type: ignore[arg-type]
        assert report["configs"] == []
        assert [(p["usable"], p["reason"]) for p in report["pairs"]] == [
            (False, reason),
            (False, reason),
        ]


def launched_log(deployer: str, address: str = pons.V2_FACTORY) -> dict[str, t.Any]:
    """Build a TokenLaunched log as web3 returns it."""
    return {
        "address": address.lower(),
        "topics": [
            pons.TOPIC_V2_LAUNCHED,
            bytes(12) + bytes.fromhex(TOKEN[2:]),
            bytes(12) + bytes.fromhex(CURVE[2:]),
            bytes(12) + bytes.fromhex(deployer[2:]),
        ],
    }


def test_launched_reads_the_event() -> None:
    """The token and curve come from this safe's TokenLaunched."""
    receipt = {
        "logs": [
            {"address": TOKEN, "topics": [b"\0" * 32]},
            launched_log(OTHER),
            launched_log(SAFE, OTHER),
            launched_log(SAFE),
        ]
    }
    assert launch.launched(receipt, SAFE) == {"token": TOKEN, "curve": CURVE}
    with pytest.raises(evm.SwapError, match="no TokenLaunched"):
        launch.launched({"logs": receipt["logs"][:3]}, SAFE)


def test_plan_plain_eth_launch(logo_ok: None) -> None:
    """A launch without a buy is one factory call paying the fee."""
    del logo_ok
    w3 = FakeW3(factory_answers())
    plan = launch.plan_launch(w3, SAFE, launch_args())  # type: ignore[arg-type]
    (call,) = plan["calls"]
    assert call["to"] == pons.V2_FACTORY
    assert call["value"] == FEE
    assert plan["opening_buy"] is None
    assert plan["expected_economics"] == "0x" + ECONOMICS.hex()
    assert plan["creator_fee_recipient"] == SAFE
    assert plan["buyback_enabled"] is True


def test_plan_launch_uses_the_salt_it_was_given(logo_ok: None) -> None:
    """The same --salt builds the same launch call, so it lands where predicted."""
    del logo_ok
    salt = "0x" + "5e" * 32
    plans = [
        launch.plan_launch(  # type: ignore[arg-type]
            FakeW3(factory_answers()), SAFE, launch_args(salt=salt)
        )
        for _ in range(2)
    ]
    assert [plan["salt"] for plan in plans] == [salt, salt]
    assert plans[0]["calls"] == plans[1]["calls"]
    assert bytes.fromhex(salt[2:]).hex() in plans[0]["calls"][0]["data"]


def test_plan_eth_launch_and_buy(logo_ok: None) -> None:
    """An ETH buy rides in the router call's value with a slippage floor."""
    del logo_ok
    w3 = FakeW3(factory_answers())
    plan = launch.plan_launch(  # type: ignore[arg-type]
        w3, SAFE, launch_args(buy=0.01, slippage=1.0, no_buyback=True)
    )
    (call,) = plan["calls"]
    state = curve.CurveState.fresh(SUPPLY, PHANTOM, THRESHOLD, 100, 0)
    tokens = curve.quote_buy(state, 10**16)
    assert call["to"] == pons.LAUNCH_ROUTER
    assert call["value"] == FEE + 10**16
    assert plan["opening_buy"]["tokens_out"] == tokens / 10**18
    assert plan["opening_buy"]["minimum_out"] == (tokens * 99 // 100) / 10**18
    assert plan["buyback_enabled"] is False


def test_plan_usdg_launch_and_buy_approves_router(logo_ok: None) -> None:
    """A USDG buy approves the router for exactly the buy first."""
    del logo_ok
    w3 = FakeW3(factory_answers())
    plan = launch.plan_launch(  # type: ignore[arg-type]
        w3, SAFE, launch_args(pair="USDG", buy=100, creator_tax_bps=50)
    )
    approve, call = plan["calls"]
    assert approve["to"] == pons.USDG
    assert (
        approve["data"]
        == evm.erc20_approval_call(pons.USDG, pons.LAUNCH_ROUTER, 100 * 10**6, "x")[
            "data"
        ]
    )
    assert call["value"] == FEE
    assert plan["creator_tax_bps"] == 50


@pytest.mark.parametrize(
    ("args", "answers", "match"),
    [
        ({"slippage": 6.0}, {}, "slippage"),
        ({"buy": -0.01}, {}, "--buy must not be negative"),
        ({"symbol": ""}, {}, "non-empty"),
        ({"symbol": "é" * 9}, {}, "symbol is 18 bytes"),
        ({"discord": "d" * 257}, {}, "discord is 257 bytes"),
        ({"creator_tax_bps": 1001}, {}, "creator tax"),
        ({}, {"can_launch": False}, "not accepting launches"),
        ({}, {"enabled": False}, "disabled"),
        ({"pair": "USDG"}, {"approved": False}, "not an approved"),
        ({"buy": 5.0}, {}, "whole curve allocation"),
        ({"buy": 1.0}, {}, "needs 1.0005 ETH"),
        ({"pair": "USDG", "buy": 2000.0}, {"usdg": 10**9}, "the buy needs"),
    ],
)
def test_plan_refusals(
    logo_ok: None, args: dict[str, t.Any], answers: dict[str, t.Any], match: str
) -> None:
    """Anything the factory would refuse, or the safe cannot pay, is refused."""
    del logo_ok
    w3 = FakeW3(factory_answers(**answers))
    with pytest.raises(evm.SwapError, match=match):
        launch.plan_launch(w3, SAFE, launch_args(**args))  # type: ignore[arg-type]


def connected(
    monkeypatch: pytest.MonkeyPatch,
    w3: FakeW3,
    sent: list[list[evm.Call]],
    on_send: t.Callable[[list[evm.Call]], None] = lambda calls: None,
) -> None:
    """Wire the script to a fake chain, signer and sender."""
    monkeypatch.setattr(evm, "connect", lambda chain: (w3, FakeSigner()))

    def send_calls(w3_: t.Any, signer: t.Any, calls: list[evm.Call]) -> list[evm.Sent]:
        """Record the calls and pretend they landed."""
        del w3_, signer
        sent.append(calls)
        on_send(calls)
        return [evm.Sent(c["what"], TX_HASH, w3.eth.receipt) for c in calls]

    monkeypatch.setattr(evm, "send_calls", send_calls)


def test_launch_command_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], logo_ok: None
) -> None:
    """A dry run prints the plan, predicted addresses and calls, sends nothing."""
    del logo_ok
    monkeypatch.setattr(pons, "require_v2_ack", lambda: {"status": "unaudited"})
    sent: list[list[evm.Call]] = []
    connected(monkeypatch, FakeW3(factory_answers()), sent)
    assert run("launch", launch_args(dry_run=True)) == 0
    out = capsys.readouterr().out
    assert json.loads(out[: out.index("dry-run")])["predicted"] == {
        "token": TOKEN,
        "curve": CURVE,
    }
    assert "dry-run launch:" in out
    assert '"status": "unaudited"' in out
    assert not sent


def test_launch_command_sends_and_reports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], logo_ok: None
) -> None:
    """A live launch sends the calls and reports the launched token."""
    del logo_ok
    monkeypatch.setattr(pons, "require_v2_ack", lambda: {"status": "unaudited"})
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(factory_answers())
    w3.eth.receipt = {"logs": [launched_log(SAFE)]}
    connected(monkeypatch, w3, sent)
    args = launch_args(pair="USDG", buy=1.0)
    assert run("launch", args) == 0
    assert [c["what"] for c in sent[0]] == ["approve launch router", "launch and buy"]
    out = capsys.readouterr().out
    assert '"predicted"' not in out
    assert json.loads(out[out.rindex("{") :]) == {"token": TOKEN, "curve": CURVE}


def test_eth_launch_and_buy_command_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], logo_ok: None
) -> None:
    """An ETH launch-and-buy dry run simulates the router call with fee plus buy."""
    del logo_ok
    monkeypatch.setattr(pons, "require_v2_ack", lambda: {"status": "unaudited"})
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(factory_answers())
    connected(monkeypatch, w3, sent)
    assert run("launch", launch_args(buy=0.01, dry_run=True)) == 0
    out = capsys.readouterr().out
    plan = json.loads(out[: out.index("dry-run")])
    assert plan["predicted"] == {"token": TOKEN, "curve": CURVE}
    (simulated,) = [r for r in w3.eth.requests if "from" in r]
    assert simulated["to"] == pons.LAUNCH_ROUTER
    assert simulated["value"] == FEE + 10**16
    assert (
        f"dry-run launch and buy: to={pons.LAUNCH_ROUTER} value={FEE + 10**16}" in out
    )
    assert not sent


def test_eth_launch_and_buy_command_sends_and_reports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], logo_ok: None
) -> None:
    """A live ETH launch-and-buy sends one router call and reads TokenLaunched."""
    del logo_ok
    monkeypatch.setattr(pons, "require_v2_ack", lambda: {"status": "unaudited"})
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(factory_answers())
    w3.eth.receipt = {"logs": [launched_log(OTHER), launched_log(SAFE)]}
    connected(monkeypatch, w3, sent)
    assert run("launch", launch_args(buy=0.01)) == 0
    ((call,),) = sent
    assert call["what"] == "launch and buy"
    assert call["to"] == pons.LAUNCH_ROUTER
    assert call["value"] == FEE + 10**16
    out = capsys.readouterr().out
    assert json.loads(out[out.rindex("{") :]) == {"token": TOKEN, "curve": CURVE}


def test_launch_command_needs_acknowledgement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the operator's V2 acknowledgement nothing is read or sent."""

    def refuse() -> dict[str, str]:
        """Refuse as pons does without an acknowledgement."""
        raise evm.SwapError("ask the operator first")

    monkeypatch.setattr(pons, "require_v2_ack", refuse)
    monkeypatch.setattr(evm, "connect", lambda chain: pytest.fail("connected"))
    with pytest.raises(evm.SwapError, match="ask the operator"):
        run("launch", launch_args())


def a_launch(**over: t.Any) -> pons.Launch:
    """Build a V2 launch record still on its curve."""
    record: dict[str, t.Any] = {
        "token": TOKEN,
        "name": "Probe",
        "symbol": "PRB",
        "decimals": 18,
        "generation": "v2",
        "factory": pons.V2_FACTORY,
        "phase": 0,
        "venue": "curve",
        "pair_token": evm.NATIVE,
        "pair_symbol": "ETH",
        "pair_decimals": 18,
        "curve": CURVE,
        "pool": None,
        "fee_bps": 100,
        "creator_tax_bps": 0,
        "deployer": SAFE,
        "buyback_enabled": False,
    }
    record.update(over)
    return t.cast(pons.Launch, record)


def fee_answers(
    creator: str = SAFE, share: int = 3000, **pending: int
) -> dict[tuple[str, bytes], t.Any]:
    """Answer the factory record, fee policy, pending buckets and escrow balances."""
    values = {"fees": 0, "tax": 0, "buyback": 0, "memecoin": 0, **pending}
    policy = (OTHER, share, 5000, 100, 300)
    pool_id = bytes.fromhex(POOL_ID[2:])

    def hook(sel: bytes, currency: str) -> tuple[str, bytes]:
        """Key for one hook bucket."""
        return (
            pons.MEME_HOOK,
            data_of(sel, ["bytes32", "address"], [pool_id, currency]),
        )

    return {
        (pons.V2_FACTORY, pons.SEL_GET_LAUNCHED): _v2_record(TOKEN, creator=creator),
        (pons.V2_FACTORY, pons.SEL_FEE_POLICY): abi_encode([pons.FEE_POLICY], [policy]),
        (CURVE, launch.SEL_QUOTE_FEES): word(values["fees"]),
        (CURVE, launch.SEL_CREATOR_TAX): word(values["tax"]),
        (CURVE, launch.SEL_BUYBACK): word(values["buyback"]),
        hook(launch.SEL_POOL_FEES, pons.USDG): word(values["fees"]),
        hook(launch.SEL_POOL_TAX, pons.USDG): word(values["tax"]),
        hook(launch.SEL_POOL_BUYBACK, pons.USDG): word(values["buyback"]),
        hook(launch.SEL_POOL_FEES, TOKEN): word(values["memecoin"]),
        hook(launch.SEL_POOL_TAX, TOKEN): word(0),
        (pons.FEE_ESCROW, evm.SEL_BALANCE_OF): word(values.get("escrow_eth", 0)),
        (pons.FEE_ESCROW, launch.SEL_ESCROW_TOKEN): word(values.get("escrow_token", 0)),
    }


def pooled(**over: t.Any) -> pons.Launch:
    """Build a graduated USDG launch trading on its v4 pool."""
    pool = {"version": "v4", "pool_id": POOL_ID}
    return a_launch(
        phase=2,
        venue="v4",
        curve=None,
        pool=pool,
        pair_token=pons.USDG,
        pair_symbol="USDG",
        pair_decimals=6,
        **over,
    )


def test_sweep_plan_on_the_curve() -> None:
    """Pending curve fees the creator may distribute become sweepFees(0)."""
    w3 = FakeW3(fee_answers(fees=10, tax=3))
    plan = launch.sweep_plan(w3, a_launch(), SAFE)  # type: ignore[arg-type]
    assert plan.reason == ""
    assert plan.pending["fees"] == 10
    assert plan.pending["creator_tax"] == 3
    assert plan.pending["creator_claimable"] == 10
    assert plan.call is not None
    assert plan.call["to"] == CURVE
    assert (
        plan.call["data"]
        == "0x" + data_of(launch.SEL_SWEEP_FEES, ["uint256"], [0]).hex()
    )


def test_sweep_plan_on_the_pool() -> None:
    """Pending hook fees become sweepPoolFees(poolId, 0, 0)."""
    w3 = FakeW3(fee_answers(tax=4))
    plan = launch.sweep_plan(w3, pooled(), SAFE)  # type: ignore[arg-type]
    assert plan.pending == {
        "fees": 0,
        "creator_tax": 4,
        "buyback": 0,
        "memecoin": 0,
        "creator_claimable": 4,
    }
    assert plan.call is not None
    assert plan.call["to"] == pons.MEME_HOOK
    expected = data_of(
        launch.SEL_SWEEP_POOL,
        ["bytes32", "uint256", "uint256"],
        [bytes.fromhex(POOL_ID[2:]), 0, 0],
    )
    assert plan.call["data"] == "0x" + expected.hex()


def test_hook_fees_need_a_v4_pool() -> None:
    """A pooled record whose pool is not v4 has no hook fees to read."""
    record = pooled()
    record["pool"] = t.cast(t.Any, {"version": "v3", "address": OTHER})
    with pytest.raises(evm.SwapError, match="only a v4 pool has hook fees"):
        launch.pending_fees(FakeW3({}), record)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("record", "answers", "reason"),
    [
        (a_launch(generation="v1", venue="v3"), {}, "only a V2 launch"),
        (a_launch(phase=1, venue="none"), {}, "only a V2 launch"),
        (a_launch(), {"creator": OTHER, "fees": 1}, "not this launch's creator"),
        (a_launch(), {"fees": 1, "buyback": 1}, "sweep operator"),
        (pooled(), {"fees": 1, "memecoin": 1}, "sweep operator"),
        (a_launch(), {}, "nothing is pending"),
    ],
)
def test_sweep_plan_refusals(
    record: pons.Launch, answers: dict[str, t.Any], reason: str
) -> None:
    """The safe is only offered sweeps the contracts let it make."""
    w3 = FakeW3(fee_answers(**answers))
    plan = launch.sweep_plan(w3, record, SAFE)  # type: ignore[arg-type]
    assert plan.call is None
    assert reason in plan.reason


def test_fees_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Fees reports escrow balances per asset and the sweep verdict."""
    w3 = FakeW3(fee_answers(fees=10, escrow_eth=10**18, escrow_token=5 * 10**6))
    connected(monkeypatch, w3, [])
    monkeypatch.setattr(pons, "launch_record", lambda w3_, token: pooled())
    assert run("fees", argparse.Namespace(token=TOKEN)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["escrow"]["ETH"] == 1.0
    assert report["escrow"]["USDG"] == 5.0
    assert report["sweepable_by_safe"] is True
    assert report["pending_base_units"]["fees"] == 10
    assert report["pending_base_units"]["creator_claimable"] == 7


@pytest.mark.parametrize(
    ("share", "fees", "tax", "claimable"),
    [
        (3000, 62326763344779, 62326763344779, 105955497686125),
        (3000, 1, 0, 1),
        (0, 7, 2, 9),
        (10_000, 7, 2, 2),
    ],
)
def test_creator_claimable_rounds_like_the_sweep(
    share: int, fees: int, tax: int, claimable: int
) -> None:
    """The creator gets fees less the floored protocol share, plus the whole tax."""
    w3 = FakeW3(fee_answers(share=share, fees=fees, tax=tax))
    plan = launch.sweep_plan(w3, pooled(), SAFE)  # type: ignore[arg-type]
    assert plan.pending["fees"] == fees
    assert plan.pending["creator_claimable"] == claimable


@pytest.mark.parametrize(
    ("record", "keys"),
    [
        (a_launch(), ["ETH", "PRB"]),
        (a_launch(symbol="ETH"), ["ETH", TOKEN]),
        (pooled(symbol="USDG"), ["ETH", "USDG", TOKEN]),
    ],
)
def test_escrow_report_never_reuses_a_key(record: pons.Launch, keys: list[str]) -> None:
    """An ETH pair is listed once, and a token named like another asset by address."""
    w3 = FakeW3(fee_answers(escrow_eth=10**18, escrow_token=5 * 10**6))
    report = launch.escrow_report(w3, SAFE, record)  # type: ignore[arg-type]
    assert list(report) == keys
    assert report["ETH"] == 1.0


def claim_args(**over: t.Any) -> argparse.Namespace:
    """Arguments for a claim."""
    args = argparse.Namespace(asset=None, sweep=False, token=None, dry_run=False)
    vars(args).update(over)
    return args


def test_claim_native_dry_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A dry run shows the claim() call and sends nothing."""
    sent: list[list[evm.Call]] = []
    connected(monkeypatch, FakeW3(fee_answers(escrow_eth=3)), sent)
    assert run("claim", claim_args(dry_run=True)) == 0
    out = capsys.readouterr().out
    assert '"claimable_now": 3' in out
    assert f"data=0x{launch.SEL_CLAIM.hex()}" in out
    assert not sent


def test_claim_native_sends_one_claim(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Without --sweep a funded escrow gets exactly one claim() batch."""
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(fee_answers(escrow_eth=3))
    connected(monkeypatch, w3, sent)
    assert run("claim", claim_args()) == 0
    assert sent == [
        [
            {
                "to": pons.FEE_ESCROW,
                "data": "0x" + launch.SEL_CLAIM.hex(),
                "what": "claim",
            }
        ]
    ]
    escrow = data_of(evm.SEL_BALANCE_OF, ["address"], [SAFE])
    assert [r["data"] for r in w3.eth.requests] == [escrow]
    assert json.loads(capsys.readouterr().out) == {
        "asset": evm.NATIVE,
        "claimable_now": 3,
    }


def test_claim_sweep_dry_run_says_the_sweep_runs_first(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A sweep dry run flags that the claim will also pay what the sweep moves."""
    sent: list[list[evm.Call]] = []
    connected(monkeypatch, FakeW3(fee_answers(fees=9)), sent)
    monkeypatch.setattr(pons, "launch_record", lambda w3_, token: pooled())
    assert run("claim", claim_args(sweep=True, token=TOKEN, dry_run=True)) == 0
    out = capsys.readouterr().out
    report = json.loads(out.splitlines()[0])
    assert report["claimable_now"] == 0
    assert report["creator_claimable"] == 7
    assert "sweep would run first" in report["note"]
    assert "dry-run sweep fees:" in out
    assert "dry-run claim:" in out
    assert not sent


def test_claim_sweeps_then_claims_the_pair_asset(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """With --sweep the sweep lands first, then claimToken(pair) for what it moved."""
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(fee_answers(fees=9))

    def sweep_lands(calls: list[evm.Call]) -> None:
        """Credit the escrow once the sweep confirms."""
        if calls[0]["what"] == "sweep fees":
            key = (pons.FEE_ESCROW.lower(), launch.SEL_ESCROW_TOKEN)
            w3.eth.answers[key] = word(9)

    connected(monkeypatch, w3, sent, sweep_lands)
    monkeypatch.setattr(pons, "launch_record", lambda w3_, token: pooled())
    args = claim_args(sweep=True, token=TOKEN, asset="USDG")
    assert run("claim", args) == 0
    assert [[c["what"] for c in batch] for batch in sent] == [["sweep fees"], ["claim"]]
    assert json.loads(capsys.readouterr().out) == {
        "asset": pons.USDG,
        "creator_claimable": 7,
        "claimable_now": 9,
    }
    claim = data_of(launch.SEL_CLAIM_TOKEN, ["address"], [pons.USDG])
    assert sent[1][0]["data"] == "0x" + claim.hex()
    assert sent[1][0]["to"] == pons.FEE_ESCROW


def test_claim_names_a_landed_sweep_when_the_escrow_read_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed read after the sweep says it landed instead of crashing."""
    sent: list[list[evm.Call]] = []
    w3 = FakeW3(fee_answers(fees=9))

    def sweep_lands(calls: list[evm.Call]) -> None:
        """Break the escrow read once the sweep confirms."""
        del calls
        key = (pons.FEE_ESCROW.lower(), launch.SEL_ESCROW_TOKEN)
        w3.eth.answers[key] = TimeoutError("rpc down")

    connected(monkeypatch, w3, sent, sweep_lands)
    monkeypatch.setattr(pons, "launch_record", lambda w3_, token: pooled())
    with pytest.raises(evm.SwapError, match=f"sweep fees: {TX_HASH}.*rpc down"):
        run("claim", claim_args(sweep=True, token=TOKEN))
    assert [[c["what"] for c in batch] for batch in sent] == [["sweep fees"]]


def test_claim_without_a_sweep_lets_a_failed_read_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nothing has been sent yet, so the read error is not reworded."""
    answers = fee_answers()
    answers[(pons.FEE_ESCROW, evm.SEL_BALANCE_OF)] = TimeoutError("rpc down")
    sent: list[list[evm.Call]] = []
    connected(monkeypatch, FakeW3(answers), sent)
    with pytest.raises(TimeoutError):
        run("claim", claim_args())
    assert not sent


@pytest.mark.parametrize(
    ("args", "answers", "match"),
    [
        (
            claim_args(sweep=True, token=TOKEN, asset="ETH"),
            {"fees": 1},
            "pays fees in USDG",
        ),
        (claim_args(sweep=True, token=TOKEN), {}, "cannot sweep: nothing"),
        (claim_args(asset="USDG"), {}, "holds nothing"),
    ],
)
def test_claim_refusals(
    monkeypatch: pytest.MonkeyPatch,
    args: argparse.Namespace,
    answers: dict[str, t.Any],
    match: str,
) -> None:
    """Mismatched assets, unsweepable launches and empty balances are refused."""
    sent: list[list[evm.Call]] = []
    connected(monkeypatch, FakeW3(fee_answers(**answers)), sent)
    monkeypatch.setattr(pons, "launch_record", lambda w3_, token: pooled())
    with pytest.raises(evm.SwapError, match=match):
        run("claim", args)
    assert not sent


def test_options_and_check_logo_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The read-only commands print JSON."""
    connected(monkeypatch, FakeW3(factory_answers()), [])
    monkeypatch.setattr(pons, "audit_status", dict)
    monkeypatch.setattr(pons, "v2_acknowledged", lambda: True)
    assert run("options", argparse.Namespace()) == 0
    assert json.loads(capsys.readouterr().out)["safe"] == SAFE
    monkeypatch.setattr(launch, "check_logo", lambda uri: {"uri": uri})
    assert run("check_logo", argparse.Namespace(logo=LOGO)) == 0
    assert json.loads(capsys.readouterr().out) == {"uri": LOGO}


def test_main_reports_refusals(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal exits 1 with the reason; a bad flag combination is an error."""
    monkeypatch.setattr(sys, "argv", ["launch.py", "check-logo", "--logo", "nope"])
    assert launch.main() == 1
    assert "refused: 'nope' is not an ipfs:// URI" in capsys.readouterr().err
    monkeypatch.setattr(sys, "argv", ["launch.py", "claim", "--sweep"])
    with pytest.raises(SystemExit):
        launch.main()
    assert "--sweep needs --token" in capsys.readouterr().err
    monkeypatch.setattr(launch, "check_logo", lambda uri: {"ok": uri})
    monkeypatch.setattr(sys, "argv", ["launch.py", "check-logo", "--logo", LOGO])
    assert launch.main() == 0


def test_main_passes_the_salt_to_the_launch(monkeypatch: pytest.MonkeyPatch) -> None:
    """The --salt a dry run printed reaches the real launch unchanged."""
    seen: list[argparse.Namespace] = []

    def record(args: argparse.Namespace) -> int:
        """Record the parsed arguments instead of launching."""
        seen.append(args)
        return 0

    monkeypatch.setattr(launch, "_cmd_launch", record)
    salt = "0x" + "5e" * 32
    argv = ["launch", "--name", "N", "--symbol", "S", "--logo", LOGO]
    argv += ["--description", "D", "--pair", "ETH", "--salt", salt]
    monkeypatch.setattr(sys, "argv", ["launch.py", *argv])
    assert launch.main() == 0
    assert seen[0].salt == salt
