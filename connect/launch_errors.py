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

"""Why an agent session would not open, as POST /session reports it."""


class LaunchError(Exception):
    """An agent session could not be opened in the requested harness."""

    # POST /session's `reason` for a launch that failed this way
    reason = "not_installed"


class InstallError(LaunchError):
    """OCB could not be installed, so no OCB session could be opened."""

    reason = "install_failed"


class OcbLaunchError(LaunchError):
    """OCB is installed, but no terminal would open running it."""

    reason = "launch_failed"
