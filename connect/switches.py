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
test-interface position, the bench's reference behaviour. They are
constructor arguments only (`create_app(..., switches=)`): no env var,
setting or route can set one, and `__main__` passes none, so Pearl never
leaves `PRODUCTION`.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Switches:
    """One position per switch; the defaults are the production positions."""

    # S2: refuse a tool argument the tool does not take, naming the ones it
    # does. Off in both positions: unknown arguments are ignored.
    strict_parameters: bool = False
    # S13: POST /sign-and-send, a signing route the reference does not serve
    rest_signing_routes: bool = True
    # S14: the native top-up from the safe to the agent EOA at startup
    agent_topup_at_boot: bool = True


PRODUCTION = Switches()

TEST_INTERFACE = Switches(
    strict_parameters=False,
    rest_signing_routes=False,
    agent_topup_at_boot=False,
)
