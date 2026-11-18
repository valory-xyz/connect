# OCB bundle

The files Connect installs OCB (`olas-ocb-agent`) from. The OCB team supplies
them; they are committed exactly as given, never built or edited here:

- `install.sh` — the installer Connect runs with `OCB_AGENT_SPEC` set to
  `olas-ocb-agent[facilitator] @ file:///.../<the wheel below>` (contract:
  README, "OCB")
- `olas_ocb_agent-<version>-py3-none-any.whl` — the built wheel; exactly one
  may be present
- `VERSION` — the `olas-ocb-agent` tag to install from once that repo is
  public. Connect does not read it

Until `install.sh` and the wheel are here, every OCB install fails with
`install_failed`. A release that bundles a different wheel makes Connect run
the installer again.

## What is here now

- Source: `valory-xyz/olas-ocb-agent` commit `e5ccec2` (main, the merge of
  olas-ocb-agent#71, after #70 set the launch version 0.1.0); `install.sh`
  copied byte for byte from it
- Wheel: `olas_ocb_agent-0.1.0-py3-none-any.whl`, sha256
  `98a68cd9e7ee62eb04412342f7d3c84da6004a91cc793e9c6eceaa8d7998846f`
- Built on Linux from `git archive e5ccec2` (LF line endings) with uv 0.13.8:
  `SOURCE_DATE_EPOCH=$(git show -s --format=%ct e5ccec2) uv build --wheel`
  (two builds gave the same sha256; the project names no build backend, so
  uv uses the latest setuptools)
- `VERSION`: `v0.1.0`. It sorts below the 0.4.1 that earlier Connect
  releases bundled; an install from those is still replaced, since Connect
  reinstalls whenever the bundled wheel (name or sha256) changes and the
  script installs the bundled wheel by URL
