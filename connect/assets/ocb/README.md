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

- Source: `valory-xyz/olas-ocb-agent` commit `879c5ff` (main, the merge of
  olas-ocb-agent#68, release 0.5.0); `install.sh` copied byte for byte from it
- Wheel: `olas_ocb_agent-0.5.0-py3-none-any.whl`, sha256
  `07487bd77eaea6c2f09a6c877a04b77c3bd68c578d776b7fa95a1f0a6e41bd1f`
- Built on Linux from `git archive 879c5ff` (LF line endings) with uv 0.13.8:
  `SOURCE_DATE_EPOCH=$(git show -s --format=%ct 879c5ff) uv build --wheel`
  (two builds gave the same sha256; the project names no build backend, so
  uv uses the latest setuptools)
- `VERSION`: `v0.5.0`
