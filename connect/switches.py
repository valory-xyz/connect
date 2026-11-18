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


"""The switches between Connect's own behaviour and OnchainBench's.

Each switch has a production position, which Pearl always runs, and a
test-interface position, the bench's reference behaviour. The set is given
once, as a constructor argument, `Signer(..., switches=)`, and `create_app`
and `build_mcp` read it from the signer, so one build cannot mix two sets. No
env var, setting or route can set one, and `__main__` passes none, so Pearl
never leaves `PRODUCTION`.
"""

import typing as t
from dataclasses import dataclass

# what a send with no intent is held to (`intent.no_intent_hold`)
NoIntentPolicy = t.Literal["strict", "simulate-only"]


@dataclass(frozen=True)
class Switches:
    """One position per switch; the defaults are the production positions."""

    no_intent_policy: NoIntentPolicy = "strict"
    # refuse a tool argument the tool does not take, naming the ones it
    # does. Off in both positions: unknown arguments are ignored.
    strict_parameters: bool = False
    # S3: the tool arguments only Connect has (`tool_schema.EXTRA_PARAMETERS`);
    # off, they are neither published nor read
    extra_tool_parameters: bool = True
    # S4: `intent` published as its typed definitions, not a bare object
    rich_intent_schema: bool = True
    # POST /sign-and-send, a signing route the reference does not serve
    rest_signing_routes: bool = True
    # the native top-up from the safe to the agent EOA at startup
    agent_topup_at_boot: bool = True

    @property
    def holds_no_intent_calls(self) -> bool:
        """Whether a call with no intent is held to its implied one (S1).

        Fails closed: every policy but `simulate-only` holds it.
        """
        return self.no_intent_policy != "simulate-only"

    def __post_init__(self) -> None:
        """Refuse a position no switch has, rather than read it as another."""
        if self.no_intent_policy not in t.get_args(NoIntentPolicy):
            raise ValueError(f"no_intent_policy {self.no_intent_policy!r} is unknown")


PRODUCTION = Switches()

TEST_INTERFACE = Switches(
    no_intent_policy="simulate-only",
    strict_parameters=False,
    extra_tool_parameters=False,
    rich_intent_schema=False,
    rest_signing_routes=False,
    agent_topup_at_boot=False,
)
