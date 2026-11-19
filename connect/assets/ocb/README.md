# OCB bundle

What Connect installs OCB (`olas-ocb-agent`) with. Connect installs OCB from
PyPI; no wheel is bundled:

- `install.sh` — the OCB team's installer, committed exactly as given, never
  edited here. Connect runs it as `sh install.sh <VERSION>`, without
  `OCB_AGENT_SPEC`, so it installs `olas-ocb-agent[facilitator]==<VERSION>`
  from PyPI (contract: README, "OCB")
- `VERSION` — the `olas-ocb-agent` release to install (a leading `v` is
  dropped). Keep it equal to install.sh's `DEFAULT_VERSION`
  (`test_this_build_bundles_ocb` checks)

Until both are here, every OCB install fails with `install_failed`. A release
with another `VERSION` makes Connect run the installer again.

## What is here now

- Source: `valory-xyz/olas-ocb-agent` commit `e5ccec2` (main, the merge of
  olas-ocb-agent#71, after #70 set the launch version 0.1.0); `install.sh`
  copied byte for byte from it
- `VERSION`: `v0.1.0`, published to PyPI on 2026-11-19 (wheel sha256
  `18116ccab4df544d04e17e0ef33cbc0338aea3af3ab3f5aaf0c914ca7667a18a`)
- Connect v0.1.16 and v0.1.17 bundled a wheel built locally from `e5ccec2`
  (sha256 `98a68cd9…`), and earlier releases a 0.4.1 wheel. Their install
  records name that wheel, not the PyPI requirement, so those installs are
  replaced from PyPI once
