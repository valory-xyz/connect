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
