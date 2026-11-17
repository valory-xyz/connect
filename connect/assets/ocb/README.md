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

- `install.sh`: `valory-xyz/olas-ocb-agent` commit `6ea9fd0`, copied byte
  for byte (unchanged at `5dd58e5`)
- Wheel: `olas_ocb_agent-0.4.1-py3-none-any.whl` from commit `5dd58e5`
  (olas-ocb-agent#67, branch `fix/mech-delivery-reader`: MechModel reads
  Connect's real mech answer, a dict `payment` label and the two-wrapper
  delivery), sha256
  `5b0a8d77e29f439f1dd68e7f43b3a92029e7d18104d233cb0ec899e4d1206cd0`
- Built on Linux from `git archive 5dd58e5` (LF line endings) with uv 0.13.8:
  `SOURCE_DATE_EPOCH=$(git show -s --format=%ct 5dd58e5) uv build --wheel`
  (two builds gave the same sha256; the project names no build backend, so
  uv uses the latest setuptools)
- `VERSION`: `v0.4.1` (the package version is still 0.4.1, so the wheel's
  file name, and with it Connect's install identity, did not change)
