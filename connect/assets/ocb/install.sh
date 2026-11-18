#!/bin/sh
# Install olas-ocb-agent (macOS, Linux, WSL2). Non-interactive; rerun to upgrade or repair.
#
#   sh install.sh [X.Y.Z]        # the release to install (a leading v is accepted), default below
#
# Installs `olas-ocb-agent[facilitator]==X.Y.Z` from PyPI with `uv tool install`, on a uv-managed
# Python 3.12: it never uses or changes a system Python, and edits no shell profile or PATH.
# uv is always the script's own copy of the pinned UV_VERSION, never a uv found on PATH: when it's
# missing or another version, Astral's installer for that version is downloaded and checked against
# UV_INSTALLER_SHA256 before it runs.
# The installer runs unmanaged: no PATH edit and no install receipt (a user's own uv keeps its own).
# A rerun changes nothing when uv's olas-ocb-agent is already exactly that requirement (same
# version, same source, the facilitator extra) on a uv-managed Python 3.12; anything else is reinstalled.
#
# Output: on success the only stdout line is the absolute path of `ocb-agent`. On failure, stderr
# gets exactly one `ocb-install: error: ...` line (naming the log with uv's details) and the exit
# code is non-zero. Progress goes to the log, and to stderr only when stderr is a terminal.
#
# Environment overrides:
#   OCB_AGENT_VERSION   the release to install (the argument wins)
#   OCB_AGENT_SPEC      the whole requirement instead, always reinstalled, e.g. a GitHub archive:
#                       'olas-ocb-agent[facilitator] @ https://github.com/valory-xyz/olas-ocb-agent/archive/<ref>.tar.gz'
#   UV_TOOL_DIR, UV_TOOL_BIN_DIR, UV_PYTHON_INSTALL_DIR, UV_CACHE_DIR   uv's own locations
set -eu

DEFAULT_VERSION="0.1.0"  # keep in step with pyproject.toml (tests/test_install_scripts.py checks)
# Its dependencies resolve as PyPI stood at its release: bump with DEFAULT_VERSION.
EXCLUDE_NEWER="2026-11-17T18:00:00Z"
UV_VERSION="0.13.8"
UV_INSTALLER_SHA256="4d8fa56e00f16b66feecacbd943773c61d61ab768b13856de350d86fd8740e2f"  # astral.sh/uv/0.13.8/install.sh

log="$(mktemp "${TMPDIR:-/tmp}/ocb-install.XXXXXX")" || {
    printf 'ocb-install: error: %s\n' "can't create a log file in ${TMPDIR:-/tmp}" >&2
    exit 1
}
installer=""
shim=""
trap 'rm -f "$installer"; rm -rf "$shim"' EXIT

fail() {
    printf 'ocb-install: error: %s (details: %s)\n' "$1" "$log" >&2
    exit 1
}
say() {
    printf 'ocb-install: %s\n' "$1" >>"$log"
    if [ -t 2 ]; then printf 'ocb-install: %s\n' "$1" >&2; fi
}

case "$(uname -s)" in
    Linux | Darwin) ;;
    *) fail "unsupported OS $(uname -s); on Windows, run it in WSL2" ;;
esac

version="${1:-${OCB_AGENT_VERSION:-$DEFAULT_VERSION}}"
version="${version#v}"
case "$version" in
    "" | *[!0-9A-Za-z.+-]*) fail "not a version: '$version' (expected X.Y.Z)" ;;
esac
# Only the facilitator extra: the default model needs it. The `mcp` dependency lives in the `litellm` extra.
spec="${OCB_AGENT_SPEC:-olas-ocb-agent[facilitator]==$version}"

# ---- uv ------------------------------------------------------------------------------------------
uv_dir="${XDG_DATA_HOME:-$HOME/.local/share}/olas-ocb-agent/bin"
own_uv="$uv_dir/uv"

own_uv_current() {
    case "$("$own_uv" --version 2>/dev/null)" in
        "uv $UV_VERSION "* | "uv $UV_VERSION") return 0 ;;
        *) return 1 ;;
    esac
}

bootstrap_uv() {
    if [ -x "$own_uv" ] && own_uv_current; then return 0; fi
    url="https://astral.sh/uv/$UV_VERSION/install.sh"
    say "installing uv $UV_VERSION into $uv_dir"
    mkdir -p "$uv_dir" 2>>"$log" || fail "can't create $uv_dir"
    installer="$(mktemp "${TMPDIR:-/tmp}/uv-installer.XXXXXX")" || fail "can't create a temporary file"
    if command -v curl >/dev/null 2>&1; then
        curl -LsSf "$url" -o "$installer" 2>>"$log" || fail "couldn't download $url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$installer" 2>>"$log" || fail "couldn't download $url"
    else
        fail "neither curl nor wget is available to download uv"
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        got="$(sha256sum "$installer" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
        got="$(shasum -a 256 "$installer" | cut -d' ' -f1)"
    else
        fail "neither sha256sum nor shasum is available to check the uv installer"
    fi
    [ "$got" = "$UV_INSTALLER_SHA256" ] || fail "the uv installer from $url has sha256 $got, not the pinned one; not run"
    # Astral's installer checks the uv archive it downloads only if `sha256sum` is on PATH, and otherwise skips
    # the check: where there's only `shasum` (macOS), give it a `sha256sum` that is `shasum -a 256`.
    installer_path="$PATH"
    if ! command -v sha256sum >/dev/null 2>&1; then
        shim="$(mktemp -d "${TMPDIR:-/tmp}/ocb-sha256sum.XXXXXX")" || fail "can't create a temporary directory"
        { printf '#!/bin/sh\nexec shasum -a 256 "$@"\n' >"$shim/sha256sum" && chmod +x "$shim/sha256sum"; } \
            || fail "can't create a sha256sum for the uv installer"
        installer_path="$shim:$PATH"
    fi
    # Unmanaged: flat into $uv_dir, no PATH edit, and no install receipt, so a uv the user installed with
    # Astral's script keeps its own receipt (`uv self update`). UV_DISABLE_UPDATE also skips the receipt.
    PATH="$installer_path" UV_UNMANAGED_INSTALL="$uv_dir" UV_DISABLE_UPDATE=1 UV_NO_MODIFY_PATH=1 \
        sh "$installer" >>"$log" 2>&1 || fail "the uv $UV_VERSION installer failed"
    own_uv_current || fail "$own_uv isn't uv $UV_VERSION after installing it"
}

# Always the script's own pinned uv: a uv on PATH is never used (nothing unpinned runs).
bootstrap_uv
uv="$own_uv"
bin_dir="$("$uv" tool dir --bin 2>>"$log")" || fail "couldn't get uv's tool bin directory"
say "using $("$uv" --version 2>/dev/null) at $uv"
agent="$bin_dir/ocb-agent"

# A uv-managed Python only: never a system one, downloaded if missing.
export UV_PYTHON_PREFERENCE=only-managed
export UV_PYTHON_DOWNLOADS=automatic

# ---- install, unless already exactly this -------------------------------------------------------
# uv lists a tool as `olas-ocb-agent v0.1.0 [required: ==0.1.0] [extras: facilitator]`: the version, the
# source it came from (a branch or archive build shows its URL) and the extras, all of which must match.
# The tool directory is shared with any other uv, so its interpreter must be a uv-managed Python 3.12 too.
managed_312() {
    tools="$("$uv" tool dir 2>>"$log")" && pythons="$("$uv" python dir 2>>"$log")" || return 1
    cfg="$tools/olas-ocb-agent/pyvenv.cfg"
    [ -f "$cfg" ] || return 1
    home="$(sed -n 's/^home *= *//p' "$cfg")"
    case "$(sed -n 's/^version_info *= *//p' "$cfg")" in 3.12.*) ;; *) return 1 ;; esac
    case "$home" in "$pythons"/*) return 0 ;; *) return 1 ;; esac
}
if [ -z "${OCB_AGENT_SPEC:-}" ] && "$agent" --version >/dev/null 2>>"$log" && managed_312 \
    && "$uv" tool list --show-extras --show-version-specifiers 2>>"$log" \
    | grep -qxF "olas-ocb-agent v$version [required: ==$version] [extras: facilitator]"; then
    say "olas-ocb-agent[facilitator]==$version is already installed"
    rm -f "$log"
    printf '%s\n' "$agent"
    exit 0
fi

say "installing $spec"
# No --force: an ocb-agent or pearl that the user or another tool put in the bin directory is never
# replaced (uv refuses, and that is the error). olas-ocb-agent itself is pinned by version, not by date.
if ! "$uv" tool install --python 3.12 --reinstall-package olas-ocb-agent \
    --exclude-newer "$EXCLUDE_NEWER" --exclude-newer-package olas-ocb-agent=false "$spec" >>"$log" 2>&1; then
    reason="$(grep -m1 '^error: ' "$log" | cut -c8-)" || true
    taken="$(printf '%s\n' "$reason" | sed -n 's/^Executable already exists: \([^ ]*\).*/\1/p')"
    if [ -n "$taken" ]; then
        fail "$bin_dir/$taken already exists and isn't olas-ocb-agent's (another tool's, e.g. the unrelated '$taken' package from PyPI): uninstall that tool (uv tool uninstall <its package>) or remove the file, then rerun"
    fi
    fail "$uv couldn't install $spec${reason:+: $reason}"
fi

[ -x "$agent" ] || fail "ocb-agent isn't at $agent after installing"
installed="$("$agent" --version 2>>"$log")" || fail "$agent --version failed"
say "installed $installed"
rm -f "$log"
printf '%s\n' "$agent"
