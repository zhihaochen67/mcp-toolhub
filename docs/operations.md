# Operations

This guide covers installation, runtime configuration, MCP client wiring,
trusted administration, maintenance, and troubleshooting. For design
boundaries, see [Architecture](architecture.md); for client state handling,
see [Approval lifecycle](approval-lifecycle.md).

## Requirements

- Python 3.12 or newer
- An MCP client with stdio transport support
- Git when using `git.status`, `git.diff`, or approval-gated Git commands
- [uv](https://docs.astral.sh/uv/) for the source and development workflows
  below

CI validates Python 3.12 and 3.13 on Ubuntu and Windows.

## Installation

### Normal source install

From a source checkout:

```text
uv tool install .
```

This installs two isolated console commands:

- `mcp-toolhub` — stdio MCP server
- `mcp-toolhub-admin` — trusted human administrator CLI

This is the primary local installation path. It does not depend on a
hard-coded wheel filename.

### Development environment

Contributors should create the locked project environment instead:

```text
uv sync --all-groups
```

This installs the project editably with development dependencies, so commands
are run as `uv run mcp-toolhub ...`, `uv run pytest ...`, and so on.

## Runtime environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `TOOLHUB_WORKSPACE_ROOT` | Yes | Absolute path to an existing workspace directory |
| `TOOLHUB_STATE_ROOT` | No | Absolute path to a ToolHub-owned trusted state directory outside the workspace |
| `TOOLHUB_APPROVAL_TTL_SECONDS` | No | Nonnegative request lifetime in seconds; defaults to 300 |

The server and admin CLI must use the same OS user and the same workspace and
state settings. Configuration is canonicalized, validated, and frozen for the
life of each process.

### Workspace root

ToolHub never defaults the workspace to the current directory, source
checkout, or installation location. `TOOLHUB_WORKSPACE_ROOT` must be absolute,
must already exist, and must be a directory.

Every MCP filesystem and Git path is interpreted relative to this root.

### Trusted state root

An explicit `TOOLHUB_STATE_ROOT` must be absolute and outside the workspace.
It names a directory ToolHub owns; do not point it at a general-purpose
directory.

When the variable is absent, ToolHub uses the platform-appropriate per-user
state base from `platformdirs` and creates:

```text
mcp-toolhub/
  workspaces/
    SHA256_OF_PLATFORM_NORMALIZED_CANONICAL_WORKSPACE/
```

The identifier separates namespaces without exposing the workspace path in a
directory name. It is not an authentication secret. Moving or renaming the
workspace normally selects a new default namespace.

The state root is permanently bound on first valid use to one canonical
workspace. It is not silently reassigned.

### Approval lifetime

`TOOLHUB_APPROVAL_TTL_SECONDS` defaults to 300 seconds. An invalid value falls
back to the default; a negative value is clamped to zero and therefore expires
new requests immediately. Set it consistently in the server environment
before the server starts.

## Start the server and admin CLI

### POSIX

```text
export TOOLHUB_WORKSPACE_ROOT=/home/alice/projects/example
export TOOLHUB_STATE_ROOT=/home/alice/.local/state/mcp-toolhub-example
mcp-toolhub serve
```

In another terminal, export the same values:

```text
mcp-toolhub-admin list
mcp-toolhub-admin approve REQUEST_ID
mcp-toolhub-admin reject REQUEST_ID
```

### Windows PowerShell

```powershell
$env:TOOLHUB_WORKSPACE_ROOT = "D:\work\example"
$env:TOOLHUB_STATE_ROOT = "$env:LOCALAPPDATA\mcp-toolhub-example"
mcp-toolhub serve
```

In another PowerShell window, set the same values:

```powershell
mcp-toolhub-admin list
mcp-toolhub-admin approve REQUEST_ID
mcp-toolhub-admin reject REQUEST_ID
```

`approve` prints the candidate and prompts:

```text
Type APPROVE to approve REQUEST_ID:
```

Only the exact input `APPROVE` records the decision. Rejection is
non-interactive after the request ID is supplied.

The server writes no banner or human log text to stdout; stdout is reserved
for MCP protocol messages. Expected configuration errors go to stderr and
exit nonzero. The administrator is not an MCP process and writes ordinary
human-readable terminal output.

## MCP client configuration

The outer key varies by client. A typical POSIX entry is:

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "mcp-toolhub",
      "args": ["serve"],
      "env": {
        "TOOLHUB_WORKSPACE_ROOT": "/home/alice/projects/example",
        "TOOLHUB_STATE_ROOT": "/home/alice/.local/state/mcp-toolhub-example"
      }
    }
  }
}
```

Windows paths need JSON escaping:

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "mcp-toolhub",
      "args": ["serve"],
      "env": {
        "TOOLHUB_WORKSPACE_ROOT": "D:\\work\\example",
        "TOOLHUB_STATE_ROOT": "C:\\Users\\alice\\AppData\\Local\\mcp-toolhub-example"
      }
    }
  }
}
```

Use an absolute path for `command` if the client does not inherit the shell's
`PATH`. For a development checkout, a client can invoke `uv` with
`["run", "mcp-toolhub", "serve"]` and set its working directory to that
checkout, but this is an editable development setup rather than normal
installation.

## Command reference

```text
mcp-toolhub --version
mcp-toolhub serve
python -m mcp_toolhub serve

mcp-toolhub-admin --version
mcp-toolhub-admin --help
mcp-toolhub-admin list
mcp-toolhub-admin approve REQUEST_ID
mcp-toolhub-admin reject REQUEST_ID
mcp-toolhub-admin prune approvals --older-than-days N [--apply]
mcp-toolhub-admin prune audit --keep-last N [--apply]
```

## Trusted state layout

Objects appear as they are needed:

```text
STATE_ROOT/
  workspace-binding.json
  workspace-binding.json.lock
  approvals.json
  approvals.json.lock
  audit.jsonl
  audit.jsonl.lock
```

The binding ties the namespace to the canonical workspace. `approvals.json`
contains protected request snapshots and statuses. `audit.jsonl` contains
bounded, sanitized events. Lock sidecars coordinate server/admin processes
and must not be deleted merely because they exist.

ToolHub rejects unsafe object types and unexpected entries in this directory.
Do not place backups, notes, or archives inside it. Do not edit state files by
hand or expose the directory through the workspace.

## Maintenance

Approval and audit retention is explicit and human-operated. Nothing is
automatically pruned at startup.

Both prune commands are dry runs by default:

```text
mcp-toolhub-admin prune approvals --older-than-days 30
mcp-toolhub-admin prune approvals --older-than-days 30 --apply
mcp-toolhub-admin prune audit --keep-last 10000
mcp-toolhub-admin prune audit --keep-last 10000 --apply
```

Approval pruning selects only sufficiently old effective terminal records:
`REJECTED`, `EXPIRED`, or `CONSUMED`. Valid pending and approved requests are
not pruned. Apply mode re-reads and recomputes eligibility while holding the
approval lock.

Audit pruning retains the newest complete events in original order. Counts
from 0 through 100,000 are accepted; `--keep-last 0 --apply` empties an
existing valid log. Malformed or unsafe input fails without replacement.

The approval store accepts at most 10,000 records and a 16 MiB final serialized
form. ToolHub does not evict active or terminal records automatically when it
fills.

For a log above the 64 MiB compaction-read ceiling, do not bypass the bound or
rotate it live. Follow the
[audit maintenance recovery runbook](audit-maintenance-recovery.md).

## Troubleshooting

### `TOOLHUB_WORKSPACE_ROOT is required`

Add an absolute existing workspace directory to the MCP child's environment.
Setting it only in a different terminal does not change the client process.

### Workspace path is missing or not a directory

Create the intended directory or correct the configured absolute path. ToolHub
does not create the workspace.

### State root must be outside the workspace

Move `TOOLHUB_STATE_ROOT` to a directory that MCP filesystem tools cannot
address. Do not place `.toolhub` beneath the workspace.

### State namespace belongs to a different workspace

Restore the original workspace setting or choose a new ToolHub-owned state
root. Bindings are intentionally not reassigned.

### Client reports invalid stdio JSON

Ensure wrappers and startup scripts print no banners, diagnostics, or logs to
stdout. If needed, use the console command directly and let the MCP client own
the child process.

### Admin cannot see a request

Confirm the server and CLI run as the same OS user and have identical
workspace, explicit/default state-root, and relevant platform state-directory
environment.

### Request expired

Submit the original operation again. Polling does not extend expiry, and
expired or consumed requests cannot be revived.

### Executable changed after approval

Submit a new shell request. The approved request is consumed before final
snapshot validation and cannot be replayed.

### Audit event is missing

Audit failures are non-fatal to tool execution. Check state-directory
permissions, disk capacity, lock contention, and the server's stderr. For an
oversized audit log, use the recovery runbook.

## Verification and release operations

Project checks and installed-wheel smoke commands are in the
[README](../README.md#development-and-verification). The final tagging,
checksum, and GitHub Release procedure remains in the
[v0.1.0 release checklist](release-checklist.md).

The [demo guide](demo.md) provides a disposable end-to-end operator exercise
without changing production behavior.
