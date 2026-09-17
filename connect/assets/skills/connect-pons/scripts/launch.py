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

"""Launch a Pons V2 token from the safe, check its logo, and claim creator fees.

Usage:
    python launch.py options
    python launch.py check-logo --logo ipfs://CID
    python launch.py launch --name N --symbol S --logo ipfs://CID --description D
        --pair ETH|USDG [--buy 0.01] [--creator-tax-bps 0] [--no-buyback]
        [--twitter ...] [--config-id 0] [--slippage 0.5] [--salt 0x..] [--dry-run]
    python launch.py fees  --token ADDR
    python launch.py claim [--asset ETH|USDG] [--sweep --token ADDR] [--dry-run]
"""

import argparse
import json
import sys
import typing as t

from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address
from web3 import Web3

import _pons_bootstrap  # noqa: F401  pylint: disable=unused-import  # isort: split

import cli  # noqa: E402  pylint: disable=wrong-import-position
import curve  # noqa: E402  pylint: disable=wrong-import-position
import evm  # noqa: E402  pylint: disable=wrong-import-position
import ipfs  # noqa: E402  pylint: disable=wrong-import-position
import pons  # noqa: E402  pylint: disable=wrong-import-position

PAIRS = {"ETH": evm.NATIVE, "USDG": pons.USDG}
METADATA_LIMITS = {"name": 64, "symbol": 16, "logo": 512, "description": 2048}
SOCIAL_LIMIT = 256

PARAMS_TUPLE = (
    "(string,string,string,string,(string,string,string,string,string),"
    "address,uint16,bool,bytes32,bytes32)"
)
LAUNCH_ARGS = [PARAMS_TUPLE, "uint256", "address"]
LAUNCH_AND_BUY_ARGS = LAUNCH_ARGS + ["uint256", "uint256", "address", "address[]"]
SEL_LAUNCH = evm.selector(f"launchToken({','.join(LAUNCH_ARGS)})")
SEL_LAUNCH_AND_BUY = evm.selector(f"launchAndBuy({','.join(LAUNCH_AND_BUY_ARGS)})")
SEL_CAN_LAUNCH = evm.selector("canLaunch(address)")
SEL_LAUNCH_FEE = evm.selector("launchFee()")
SEL_CONFIG_COUNT = evm.selector("launchConfigCount()")
SEL_GET_CONFIG = evm.selector("getLaunchConfig(uint256)")
SEL_MAX_CREATOR_TAX = evm.selector("maxCreatorTaxBps()")
SEL_APPROVED_PAIR = evm.selector("approvedPairTokens(address)")
SEL_PAIR_ECONOMICS = evm.selector("pairTokenEconomics(address)")
SEL_PREVIEW_ECONOMICS = evm.selector("previewLaunchEconomics(uint256,address)")
SEL_ESCROW_TOKEN = evm.selector("balanceOfToken(address,address)")
SEL_CLAIM = evm.selector("claim()")
SEL_CLAIM_TOKEN = evm.selector("claimToken(address)")
SEL_QUOTE_FEES = evm.selector("quoteFeeBalance()")
SEL_CREATOR_TAX = evm.selector("creatorTaxBalance()")
SEL_BUYBACK = evm.selector("buybackQuoteBalance()")
SEL_SWEEP_FEES = evm.selector("sweepFees(uint256)")
SEL_POOL_FEES = evm.selector("pendingFees(bytes32,address)")
SEL_POOL_TAX = evm.selector("pendingCreatorTax(bytes32,address)")
SEL_POOL_BUYBACK = evm.selector("pendingBuyback(bytes32,address)")
SEL_SWEEP_POOL = evm.selector("sweepPoolFees(bytes32,uint256,uint256)")

ERRORS = {
    evm.selector(signature): signature
    for signature in (
        "Error(string)",
        "InvalidLaunchConfigId()",
        "LaunchConfigDisabled()",
        "ExemptionListTooLong()",
        "CreatorTaxTooHigh()",
        "CombinedFeeTooHigh()",
        "LaunchFeeNotPaid()",
        "NotWhitelisted()",
        "FeeTransferFailed()",
        "ZeroAddress()",
        "InvalidTokenParams()",
        "TokenNotFound()",
        "PairTokenNotApproved()",
        "PairTokenValidationFailed()",
        "PairTokenDecimalsMismatch(uint8,uint8)",
        "PairTokenDecimalsUnavailable()",
        "LaunchEconomicsMismatch(bytes32,bytes32)",
        "InexactTransfer(address,uint256,uint256)",
        "GraduationSeedNotViable()",
        "LaunchDependenciesNotWired()",
        "LaunchDeployerNotSet()",
        "NotLaunchForwarder()",
        "CurveNotQuotable()",
        "MetadataTooLong()",
        "CurveGraduated()",
        "ZeroAmount()",
        "SlippageExceeded(uint256,uint256)",
        "NativeValueMismatch(uint256,uint256)",
        "UnexpectedNativeValue()",
        "AlreadyGraduated()",
        "NotFeeSweepOperator()",
        "InternalSwapRequiresOperator()",
        "MinimumOutputRequired()",
        "UnknownPool()",
        "ERC20InsufficientAllowance(address,uint256,uint256)",
        "ERC20InsufficientBalance(address,uint256,uint256)",
    )
}


class Socials(t.NamedTuple):
    """The TokenParams socials struct, in the factory's field order."""

    twitter: str
    telegram: str
    discord: str
    website: str
    farcaster: str


SOCIALS = Socials._fields


class TokenParams(t.NamedTuple):
    """The factory's TokenParams struct, in its field order."""

    name: str
    symbol: str
    logo: str
    description: str
    socials: Socials
    creator_fee_recipient: str
    creator_tax_bps: int
    buyback_enabled: bool
    expected_economics: bytes
    salt: bytes


class LaunchConfig(t.TypedDict):
    """One factory launch config, native-quote economics included."""

    id: int
    supply: int
    curve_fee_bps: int
    phantom_quote: int
    graduation_threshold: int
    pool_fee: int
    tick_spacing: int
    enabled: bool


def launch_config(w3: Web3, config_id: int) -> LaunchConfig:
    """Read one launch config by id.

    Raises:
        SwapError: when the id does not exist.
    """
    count = evm.call_int(w3, pons.V2_FACTORY, SEL_CONFIG_COUNT)
    if not 0 <= config_id < count:
        raise evm.SwapError(
            f"launch config {config_id} does not exist (0..{count - 1})"
        )
    fields = evm.call_types(
        w3,
        pons.V2_FACTORY,
        evm.encode_call(SEL_GET_CONFIG, ["uint256"], [config_id]),
        ["uint256", "uint256", "uint256", "uint256", "uint24", "int24", "bool"],
    )
    return {
        "id": config_id,
        "supply": fields[0],
        "curve_fee_bps": fields[1],
        "phantom_quote": fields[2],
        "graduation_threshold": fields[3],
        "pool_fee": fields[4],
        "tick_spacing": fields[5],
        "enabled": fields[6],
    }


def pair_economics(w3: Web3, pair: str, config: LaunchConfig) -> tuple[int, int]:
    """Phantom reserve and graduation threshold a launch against ``pair`` uses.

    Raises:
        SwapError: when the asset is not approved or has no economics set.
    """
    if evm.is_native(pair):
        phantom, threshold = config["phantom_quote"], config["graduation_threshold"]
        if not phantom or not threshold:
            raise evm.SwapError("the launch config has no native ETH economics set")
        return phantom, threshold
    approved = evm.call_int(
        w3, pons.V2_FACTORY, evm.encode_call(SEL_APPROVED_PAIR, ["address"], [pair])
    )
    phantom, threshold, _ = evm.call_types(
        w3,
        pons.V2_FACTORY,
        evm.encode_call(SEL_PAIR_ECONOMICS, ["address"], [pair]),
        ["uint256", "uint256", "uint8"],
    )
    if not approved or not phantom or not threshold:
        raise evm.SwapError(f"{pair} is not an approved Pons V2 pair asset")
    return phantom, threshold


def can_launch(w3: Web3, account: str) -> bool:
    """Whether the factory lets this account launch right now."""
    data = evm.encode_call(SEL_CAN_LAUNCH, ["address"], [to_checksum_address(account)])
    return bool(evm.call_int(w3, pons.V2_FACTORY, data))


def _pair_option(
    w3: Web3, symbol: str, address: str, config: t.Optional[LaunchConfig]
) -> dict[str, t.Any]:
    """Describe one pair asset under the first enabled launch config."""
    entry: dict[str, t.Any] = {"symbol": symbol, "address": address}
    if config is None:
        entry.update(
            usable=False,
            reason="the factory has no enabled launch config, so nothing can launch",
        )
        return entry
    try:
        phantom, threshold = pair_economics(w3, address, config)
    except evm.SwapError as exc:
        entry.update(usable=False, reason=str(exc))
        return entry
    decimals = evm.token_decimals(w3, address)
    entry.update(
        usable=True,
        decimals=decimals,
        phantom_quote=phantom / 10**decimals,
        graduation_threshold=threshold / 10**decimals,
    )
    return entry


def options(w3: Web3, safe: str) -> dict[str, t.Any]:
    """Everything the operator chooses from before a launch, read live."""
    count = evm.call_int(w3, pons.V2_FACTORY, SEL_CONFIG_COUNT)
    configs = [launch_config(w3, i) for i in range(count)]
    enabled = [c for c in configs if c["enabled"]]
    fee = evm.call_int(w3, pons.V2_FACTORY, SEL_LAUNCH_FEE)
    return {
        "factory": pons.V2_FACTORY,
        "safe": safe,
        "can_launch": can_launch(w3, safe),
        "launch_fee_eth": fee / 10**18,
        "launch_fee_wei": fee,
        "max_creator_tax_bps": evm.call_int(w3, pons.V2_FACTORY, SEL_MAX_CREATOR_TAX),
        "configs": enabled,
        "pairs": [
            _pair_option(w3, symbol, address, enabled[0] if enabled else None)
            for symbol, address in PAIRS.items()
        ],
        "metadata_limits_bytes": {**METADATA_LIMITS, "each_social": SOCIAL_LIMIT},
        "logo": {
            "scheme": "ipfs://",
            "types": ["image/png", "image/jpeg", "image/webp"],
            "max_bytes": ipfs.IMAGE_MAX_BYTES,
            "recommended": "square",
        },
        "audit": pons.audit_status(),
        "v2_acknowledged": pons.v2_acknowledged(),
    }


def check_logo(uri: str) -> dict[str, t.Any]:
    """Check an ipfs:// logo resolves to an image Pons accepts.

    Raises:
        SwapError: when the image is unusable.
    """
    report = ipfs.check_image(uri, pons.USER_AGENT)
    report["warning"] = (
        "" if report["square"] is not False else "not square; Pons crops logos"
    )
    return report


def token_params(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    meta: dict[str, str],
    creator: str,
    creator_tax_bps: int,
    buyback: bool,
    economics: bytes,
    salt: bytes,
) -> TokenParams:
    """Build the TokenParams struct from validated metadata."""
    return TokenParams(
        name=meta["name"],
        symbol=meta["symbol"],
        logo=meta["logo"],
        description=meta["description"],
        socials=Socials(**{s: meta[s] for s in SOCIALS}),
        creator_fee_recipient=to_checksum_address(creator),
        creator_tax_bps=creator_tax_bps,
        buyback_enabled=buyback,
        expected_economics=economics,
        salt=salt,
    )


class Buy(t.NamedTuple):
    """The opening buy riding along with a launch."""

    quote_in: int
    min_tokens_out: int
    recipient: str


def build_launch_call(
    params: TokenParams,
    config_id: int,
    pair: str,
    fee: int,
    buy: t.Optional[Buy],
) -> evm.Call:
    """Encode a factory launch, or a router launch-and-buy when buying."""
    pair = to_checksum_address(pair)
    if buy is None:
        data = evm.encode_call(SEL_LAUNCH, LAUNCH_ARGS, [params, config_id, pair])
        return {
            "to": pons.V2_FACTORY,
            "data": "0x" + data.hex(),
            "value": fee,
            "what": "launch",
        }
    args = [params, config_id, pair, buy.quote_in, buy.min_tokens_out]
    data = evm.encode_call(
        SEL_LAUNCH_AND_BUY,
        LAUNCH_AND_BUY_ARGS,
        args + [to_checksum_address(buy.recipient), []],
    )
    return {
        "to": pons.LAUNCH_ROUTER,
        "data": "0x" + data.hex(),
        "value": fee + (buy.quote_in if evm.is_native(pair) else 0),
        "what": "launch and buy",
    }


def verify_launch_call(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    call: evm.Call,
    params: TokenParams,
    config_id: int,
    pair: str,
    fee: int,
    buy: t.Optional[Buy],
) -> None:
    """Decode a built launch call and check it is exactly the planned launch.

    Raises:
        SwapError: on any field that differs from the plan.
    """
    raw = bytes.fromhex(call["data"].removeprefix("0x"))
    types = LAUNCH_ARGS if buy is None else LAUNCH_AND_BUY_ARGS
    got_params, got_config, got_pair, *got_buy = abi_decode(types, raw[4:])
    decoded = TokenParams(*got_params)
    decoded = decoded._replace(
        socials=Socials(*decoded.socials),
        creator_fee_recipient=to_checksum_address(decoded.creator_fee_recipient),
    )
    checks: dict[str, tuple[t.Any, t.Any]] = {
        "selector": (raw[:4], SEL_LAUNCH if buy is None else SEL_LAUNCH_AND_BUY),
        "target": (
            call["to"],
            pons.V2_FACTORY if buy is None else pons.LAUNCH_ROUTER,
        ),
        "params": (decoded, params),
        "config": (got_config, config_id),
        "pair": (to_checksum_address(got_pair), to_checksum_address(pair)),
    }
    if buy is None:
        checks["value"] = (call.get("value", 0), fee)
    else:
        if buy.min_tokens_out <= 0:
            raise evm.SwapError("the opening buy has no minimum output")
        quote_in, minimum, recipient, exemptions = got_buy
        native = evm.is_native(pair)
        checks.update(
            {
                "value": (call.get("value", 0), fee + (buy.quote_in if native else 0)),
                "quote in": (quote_in, buy.quote_in),
                "minimum out": (minimum, buy.min_tokens_out),
                "recipient": (
                    to_checksum_address(recipient),
                    to_checksum_address(buy.recipient),
                ),
                "exemptions": (exemptions, ()),
            }
        )
    evm.check_fields("launch", checks)
    if int(params.creator_fee_recipient, 16) == 0:
        raise evm.SwapError("the creator fee recipient must be set")


def launched(receipt: t.Any, deployer: str) -> dict[str, str]:
    """Read the token and curve a confirmed launch emitted.

    Raises:
        SwapError: when the receipt carries no TokenLaunched from this safe.
    """
    for log in receipt["logs"]:
        topics = [bytes(topic) for topic in log["topics"]]
        if (
            to_checksum_address(log["address"]) == pons.V2_FACTORY
            and len(topics) == 4
            and topics[0] == pons.TOPIC_V2_LAUNCHED
            and to_checksum_address(topics[3][-20:]) == to_checksum_address(deployer)
        ):
            return {
                "token": to_checksum_address(topics[1][-20:]),
                "curve": to_checksum_address(topics[2][-20:]),
            }
    raise evm.SwapError(
        "the launch confirmed but carries no TokenLaunched event for this safe; "
        "inspect the transaction before retrying"
    )


def _check_launch_balance(
    w3: Web3, safe: str, pair: str, fee: int, quote_in: int
) -> None:
    """Refuse a launch the safe cannot pay for.

    Raises:
        SwapError: when the ETH or pair-asset balance is short.
    """
    native = evm.is_native(pair)
    need_eth = fee + (quote_in if native else 0)
    have_eth = evm.raw_balance_of(w3, evm.NATIVE, safe)
    if have_eth < need_eth:
        raise evm.SwapError(
            f"the safe holds {have_eth / 10**18} ETH and this launch needs "
            f"{need_eth / 10**18} ETH"
        )
    if not native and quote_in:
        have = evm.raw_balance_of(w3, pair, safe)
        if have < quote_in:
            raise evm.SwapError(
                f"the safe holds {have} base units of {pair}; the buy needs {quote_in}"
            )


def plan_launch(  # pylint: disable=too-many-locals
    w3: Web3, safe: str, args: argparse.Namespace
) -> dict[str, t.Any]:
    """Validate a launch against live terms and build its checked calls.

    Raises:
        SwapError: for anything the factory would refuse, a logo that does
            not resolve, or a buy that is unaffordable or would clear the curve.
    """
    evm.check_slippage(args.slippage)
    salt = evm.parse_bytes32(args.salt, "--salt")
    if not args.buy >= 0:
        raise evm.SwapError(f"--buy must not be negative, got {args.buy}")
    meta = {f: getattr(args, f) or "" for f in (*METADATA_LIMITS, *SOCIALS)}
    cli.check_byte_limits(
        meta,
        {**METADATA_LIMITS, **dict.fromkeys(SOCIALS, SOCIAL_LIMIT)},
        ("name", "symbol"),
    )
    pair = PAIRS[args.pair]
    max_tax = evm.call_int(w3, pons.V2_FACTORY, SEL_MAX_CREATOR_TAX)
    if not 0 <= args.creator_tax_bps <= max_tax:
        raise evm.SwapError(
            f"creator tax {args.creator_tax_bps} bps is outside 0..{max_tax}"
        )
    if not can_launch(w3, safe):
        raise evm.SwapError("Pons is not accepting launches from this safe right now")
    config = launch_config(w3, args.config_id)
    if not config["enabled"]:
        raise evm.SwapError(f"launch config {args.config_id} is disabled")
    phantom, threshold = pair_economics(w3, pair, config)
    checked_logo = check_logo(meta["logo"])
    fee = evm.call_int(w3, pons.V2_FACTORY, SEL_LAUNCH_FEE)
    economics = bytes(
        evm.call_types(
            w3,
            pons.V2_FACTORY,
            evm.encode_call(
                SEL_PREVIEW_ECONOMICS, ["uint256", "address"], [config["id"], pair]
            ),
            ["bytes32"],
        )[0]
    )
    params = token_params(
        meta,
        safe,
        args.creator_tax_bps,
        not args.no_buyback,
        economics,
        salt,
    )
    buy = None
    opening: dict[str, t.Any] = {}
    if args.buy:
        quote_in = evm.to_base_units(w3, pair, args.buy)
        state = curve.CurveState.fresh(
            config["supply"],
            phantom,
            threshold,
            config["curve_fee_bps"],
            args.creator_tax_bps,
        )
        tokens = curve.quote_buy(state, quote_in)
        if tokens >= state.sellable:
            raise evm.SwapError(
                "that buy would take the whole curve allocation; buy less"
            )
        floor = evm.apply_slippage(tokens, args.slippage)
        buy = Buy(quote_in, floor, safe)
        opening = {
            "spend": args.buy,
            "tokens_out": tokens / 10**18,
            "minimum_out": floor / 10**18,
            "share_of_supply_pct": round(tokens * 100 / config["supply"], 4),
            "slippage": args.slippage,
        }
    _check_launch_balance(w3, safe, pair, fee, buy.quote_in if buy else 0)
    calls = []
    if buy is not None and not evm.is_native(pair):
        calls.append(
            evm.erc20_approval_call(
                pair, pons.LAUNCH_ROUTER, buy.quote_in, "approve launch router"
            )
        )
    call = build_launch_call(params, config["id"], pair, fee, buy)
    verify_launch_call(call, params, config["id"], pair, fee, buy)
    calls.append(call)
    return {
        "name": meta["name"],
        "symbol": meta["symbol"],
        "pair": args.pair,
        "config": config,
        "launch_fee_eth": fee / 10**18,
        "creator_fee_recipient": safe,
        "creator_tax_bps": args.creator_tax_bps,
        "buyback_enabled": not args.no_buyback,
        "expected_economics": "0x" + economics.hex(),
        "salt": "0x" + params.salt.hex(),
        "logo": checked_logo,
        "opening_buy": opening or None,
        "calls": calls,
    }


def _cmd_options(_: argparse.Namespace) -> int:
    """Print what a launch can be configured with right now."""
    w3, signer = evm.connect(pons.CHAIN)
    safe = signer.chain_info(pons.CHAIN)["safe"]
    print(json.dumps(options(w3, safe), indent=2))
    return 0


def _cmd_check_logo(args: argparse.Namespace) -> int:
    """Check an ipfs:// logo resolves to an acceptable image."""
    print(json.dumps(check_logo(args.logo), indent=2))
    return 0


def _cmd_launch(args: argparse.Namespace) -> int:
    """Launch a token from the safe, optionally buying into it atomically."""
    audit = pons.require_v2_ack()
    w3, signer = evm.connect(pons.CHAIN)
    safe = signer.chain_info(pons.CHAIN)["safe"]
    plan = plan_launch(w3, safe, args)
    calls = plan.pop("calls")
    final = calls[-1]
    if len(calls) == 1:
        raw = evm.simulate_call(w3, final, safe, ERRORS)
        token, curve_address = abi_decode(["address", "address"], raw[:64])
        plan["predicted"] = {
            "token": to_checksum_address(token),
            "curve": to_checksum_address(curve_address),
        }
    print(json.dumps({"audit": audit, **plan}, indent=2))
    if args.dry_run:
        evm.print_dry_run(calls)
        return 0
    landed = evm.send_calls(w3, signer, calls)
    print(json.dumps(launched(landed[-1].receipt, safe), indent=2))
    return 0


def _escrow_balance(w3: Web3, holder: str, asset: str) -> int:
    """Read what the fee escrow holds for ``holder`` in one asset."""
    if evm.is_native(asset):
        data = evm.encode_call(evm.SEL_BALANCE_OF, ["address"], [holder])
    else:
        data = evm.encode_call(
            SEL_ESCROW_TOKEN, ["address", "address"], [holder, asset]
        )
    return evm.call_int(w3, pons.FEE_ESCROW, data)


def creator_of(w3: Web3, token: str) -> str:
    """Read the launch's current creator fee recipient from the factory."""
    return pons.v2_record(w3, to_checksum_address(token)).creatorFeeRecipient


def _pool_id(launch: pons.Launch) -> bytes:
    """Return the v4 pool id a graduated V2 launch's hook keys its fees by.

    Raises:
        SwapError: when the launch's pool is not a v4 pool.
    """
    pool = pons.pool_of(launch)
    if pool["version"] != "v4":
        raise evm.SwapError(
            f"{launch['symbol']} trades on a {pool['version']} pool; only a v4 "
            f"pool has hook fees"
        )
    return bytes.fromhex(pool["pool_id"].removeprefix("0x"))


def pending_fees(w3: Web3, launch: pons.Launch) -> dict[str, int]:
    """Fees accrued on the launch's curve or hook and not yet swept."""
    if launch["venue"] == "curve":
        where = pons.curve_of(launch)
        return {
            "fees": evm.call_int(w3, where, SEL_QUOTE_FEES),
            "creator_tax": evm.call_int(w3, where, SEL_CREATOR_TAX),
            "buyback": evm.call_int(w3, where, SEL_BUYBACK),
            "memecoin": 0,
        }
    pool_id = _pool_id(launch)

    def read(sel: bytes, currency: str) -> int:
        """One pending bucket on the hook."""
        data = evm.encode_call(sel, ["bytes32", "address"], [pool_id, currency])
        return evm.call_int(w3, pons.MEME_HOOK, data)

    pair, token = launch["pair_token"], launch["token"]
    return {
        "fees": read(SEL_POOL_FEES, pair),
        "creator_tax": read(SEL_POOL_TAX, pair),
        "buyback": read(SEL_POOL_BUYBACK, pair),
        "memecoin": read(SEL_POOL_FEES, token) + read(SEL_POOL_TAX, token),
    }


class SweepPlan(t.NamedTuple):
    """The sweep the safe may send, or why not, and the fees pending."""

    call: t.Optional[evm.Call]
    reason: str
    pending: dict[str, int]


def sweep_plan(w3: Web3, launch: pons.Launch, safe: str) -> SweepPlan:
    """Build the sweep the safe may send itself, or say why it may not."""
    if launch["generation"] != "v2" or launch["venue"] not in ("curve", "v4"):
        return SweepPlan(
            None, "only a V2 launch on its curve or pool has fees to sweep", {}
        )
    pending = pending_fees(w3, launch)
    share = pons.fee_policy(w3, launch["token"]).protocolFeeShareBps
    protocol = pending["fees"] * share // curve.BPS
    pending["creator_claimable"] = pending["fees"] - protocol + pending["creator_tax"]
    if to_checksum_address(creator_of(w3, launch["token"])) != to_checksum_address(
        safe
    ):
        return SweepPlan(
            None, "the safe is not this launch's creator fee recipient", pending
        )
    if pending["buyback"] or pending["memecoin"]:
        return SweepPlan(
            None,
            (
                "a buyback or memecoin conversion is pending; only the Pons sweep "
                "operator may sweep it"
            ),
            pending,
        )
    if not pending["fees"] and not pending["creator_tax"]:
        return SweepPlan(None, "nothing is pending", pending)
    if launch["venue"] == "curve":
        data = evm.encode_call(SEL_SWEEP_FEES, ["uint256"], [0])
        target = pons.curve_of(launch)
    else:
        data = evm.encode_call(
            SEL_SWEEP_POOL,
            ["bytes32", "uint256", "uint256"],
            [_pool_id(launch), 0, 0],
        )
        target = pons.MEME_HOOK
    call: evm.Call = {"to": target, "data": "0x" + data.hex(), "what": "sweep fees"}
    return SweepPlan(call, "", pending)


def escrow_report(w3: Web3, safe: str, launch: pons.Launch) -> dict[str, float]:
    """Escrow balances per asset: by symbol, or by address when a symbol repeats."""
    assets = {
        evm.NATIVE: ("ETH", evm.NATIVE_DECIMALS),
        launch["pair_token"]: (launch["pair_symbol"], launch["pair_decimals"]),
        launch["token"]: (launch["symbol"], launch["decimals"]),
    }
    report: dict[str, float] = {}
    for asset, (symbol, decimals) in assets.items():
        key = asset if symbol in report else symbol
        report[key] = _escrow_balance(w3, safe, asset) / 10**decimals
    return report


def _cmd_fees(args: argparse.Namespace) -> int:
    """Show what the escrow holds for the safe and what a sweep would add."""
    w3, signer = evm.connect(pons.CHAIN)
    safe = signer.chain_info(pons.CHAIN)["safe"]
    launch = pons.launch_record(w3, args.token)
    plan = sweep_plan(w3, launch, safe)
    report = {
        "token": launch["token"],
        "pair": launch["pair_symbol"],
        "escrow": escrow_report(w3, safe, launch),
        "pending_base_units": plan.pending,
        "sweepable_by_safe": plan.call is not None,
        "reason": plan.reason,
    }
    print(json.dumps(report, indent=2))
    return 0


def _cmd_claim(args: argparse.Namespace) -> int:
    """Optionally sweep a launch's fees, then claim one asset from the escrow."""
    w3, signer = evm.connect(pons.CHAIN)
    safe = signer.chain_info(pons.CHAIN)["safe"]
    asset = PAIRS[args.asset or "ETH"]
    calls: list[evm.Call] = []
    extra: dict[str, int] = {}
    if args.sweep:
        launch = pons.launch_record(w3, args.token)
        if args.asset and asset != launch["pair_token"]:
            raise evm.SwapError(
                f"{args.token} pays fees in {launch['pair_symbol']}, not {args.asset}"
            )
        asset = launch["pair_token"]
        plan = sweep_plan(w3, launch, safe)
        if plan.call is None:
            raise evm.SwapError(f"cannot sweep: {plan.reason}")
        calls.append(plan.call)
        extra["creator_claimable"] = plan.pending["creator_claimable"]
    if evm.is_native(asset):
        claim = evm.encode_call(SEL_CLAIM, [], [])
    else:
        claim = evm.encode_call(SEL_CLAIM_TOKEN, ["address"], [asset])
    claim_call: evm.Call = {
        "to": pons.FEE_ESCROW,
        "data": "0x" + claim.hex(),
        "what": "claim",
    }
    if args.dry_run:
        report: dict[str, t.Any] = {
            "asset": asset,
            **extra,
            "claimable_now": _escrow_balance(w3, safe, asset),
        }
        if calls:
            report["note"] = (
                "the sweep would run first; the claim also pays what it moves "
                "into the escrow"
            )
        print(json.dumps(report))
        evm.print_dry_run(calls + [claim_call])
        return 0
    swept = evm.send_calls(w3, signer, calls) if calls else []
    try:
        claimable = _escrow_balance(w3, safe, asset)
    except Exception as exc:  # pylint: disable=broad-except
        if not swept:
            raise
        raise evm.SwapError(
            f"the sweep landed ({evm.summary(swept)}) but the escrow could not be "
            f"read ({exc}); rerun claim without --sweep to collect it"
        ) from exc
    print(json.dumps({"asset": asset, **extra, "claimable_now": claimable}))
    if not claimable:
        raise evm.SwapError("the escrow holds nothing for the safe in that asset")
    evm.send_calls(w3, signer, [claim_call])
    return 0


def main() -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(description="Pons V2 launches and creator fees")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("options").set_defaults(func=_cmd_options)
    check = sub.add_parser("check-logo")
    check.add_argument("--logo", required=True)
    check.set_defaults(func=_cmd_check_logo)
    launch = sub.add_parser("launch")
    for field in METADATA_LIMITS:
        launch.add_argument(f"--{field}", required=True)
    for field in SOCIALS:
        launch.add_argument(f"--{field}", default="")
    launch.add_argument("--pair", choices=sorted(PAIRS), required=True)
    launch.add_argument("--buy", type=float, default=0.0)
    launch.add_argument("--creator-tax-bps", type=int, default=0)
    launch.add_argument("--no-buyback", action="store_true")
    launch.add_argument("--config-id", type=int, default=0)
    launch.add_argument("--slippage", type=float, default=0.5)
    launch.add_argument("--salt")
    launch.add_argument("--dry-run", action="store_true")
    launch.set_defaults(func=_cmd_launch)
    fees = sub.add_parser("fees")
    fees.add_argument("--token", required=True)
    fees.set_defaults(func=_cmd_fees)
    claim = sub.add_parser("claim")
    claim.add_argument("--asset", choices=sorted(PAIRS))
    claim.add_argument("--sweep", action="store_true")
    claim.add_argument("--token")
    claim.add_argument("--dry-run", action="store_true")
    claim.set_defaults(func=_cmd_claim)
    args = parser.parse_args()
    if getattr(args, "sweep", False) and not args.token:
        parser.error("--sweep needs --token")
    try:
        result: int = args.func(args)
    except evm.SwapError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
