# Pearl Connect agent

Agent blueprint for the Pearl Connect BYOA agent. The runtime is the
`pearl-connect` binary (built from this repository, released as
`agent_runner_{os}_{arch}` assets): it custodies the agent EOA key, serves the
Pearl SDK endpoints on port 8716, and exposes an MCP + HTTP signing service so
an agent-harness session (e.g. Claude Code) can act on-chain without any key
access.

This package carries the on-chain identity and configuration schema; the
executable logic lives in the repository root (`pearl_connect/`).
