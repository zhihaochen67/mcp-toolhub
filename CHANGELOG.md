# Changelog

All notable changes to MCP ToolHub are documented in this file.

The format is based on [Keep a Changelog], and this project uses semantic
versioning for package releases. The package version is independent of the
Contract V1 protocol version.

## [0.1.0] - 2026-09-04

### Added

- Local, stdio-only MCP server with exactly 14 production tools for bounded
  workspace, Git, approval, shell, and audit workflows.
- Out-of-band `mcp-toolhub-admin` CLI for human approval decisions and state
  maintenance; approval is not exposed through MCP.
- Immutable, expiring, single-use approval lifecycle and stable Contract V1
  structured outcomes.
- Bounded, sanitized audit trail with cross-lifecycle trace correlation.
- Architecture, approval lifecycle, demo, operations, and maintenance
  documentation.

### Security

- Canonical workspace confinement with portable traversal and mutation-time
  symlink protections.
- Trusted approval and audit state stored outside the workspace with hardened,
  atomic persistence.
- Approval-bound executable identity and sanitized execution-environment
  snapshots.
- OS-backed process-tree lifetime containment plus bounded command, Git, and
  audit output.
- Read-only Git inspection protections against helper, filter, pager,
  text-conversion, and submodule execution paths.

### Reliability

- Validation on Ubuntu/Linux and Windows with Python 3.12 and 3.13.
- Atomic mutation publication and cross-process locking for approval and audit
  state.
- Build validation through an isolated installed-wheel smoke test.

### Limitations

- MCP ToolHub is a local, single-user stdio gateway, not a remote service,
  authorization platform, container, or general operating-system sandbox.
- Approved programs are not filesystem- or network-isolated. See the
  [README non-goals] and [architecture and threat model] for the complete
  boundaries and assumptions.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[0.1.0]: https://github.com/zhihaochen67/mcp-toolhub/releases/tag/v0.1.0
[README non-goals]: README.md#non-goals
[architecture and threat model]: docs/architecture.md
