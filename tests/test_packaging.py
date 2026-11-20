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


"""The published package's dependency specifiers against uv.lock."""

import tomllib
from collections import defaultdict
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


def _locked_versions() -> dict[str, list[str]]:
    """Every version uv.lock holds, by canonical package name."""
    versions: dict[str, list[str]] = defaultdict(list)
    for package in tomllib.loads((ROOT / "uv.lock").read_text())["package"]:
        if "version" in package:
            versions[canonicalize_name(package["name"])].append(package["version"])
    return versions


def _next_breaking(floor: Version) -> Version:
    """Return the first release allowed to break `floor`: next major, or next 0.x minor."""
    major, minor = (*floor.release, 0)[:2]
    return Version(f"{major + 1}") if major else Version(f"0.{minor + 1}")


def test_every_dependency_is_a_pin_or_a_capped_range_holding_the_lock() -> None:
    """The unit suite runs on uv.lock, so a consumer must not resolve outside it."""
    locked = _locked_versions()
    dependencies = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"][
        "dependencies"
    ]
    for dependency in dependencies:
        requirement = Requirement(dependency)
        operators = sorted(spec.operator for spec in requirement.specifier)
        assert operators in (["=="], ["<", ">="]), dependency
        if operators != ["=="]:
            bounds = {
                spec.operator: Version(spec.version) for spec in requirement.specifier
            }
            assert bounds["<"] == _next_breaking(bounds[">="]), dependency
        versions = locked[canonicalize_name(requirement.name)]
        assert versions, dependency
        assert all(requirement.specifier.contains(v) for v in versions), dependency
