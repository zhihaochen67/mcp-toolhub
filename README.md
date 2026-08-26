# MCP ToolHub

MCP ToolHub is a local, stdio-only Model Context Protocol server that exposes
bounded workspace filesystem operations, read-only Git inspection, structured
command execution, and an audit trail. Mutating filesystem operations and all
external command execution use the existing out-of-band human approval model.

ToolHub does not expose an HTTP, SSE, or other network listener.

## Features

- Workspace-confined file reading, directory listing, writes, and patches
- Read-only Git status and diff operations
- Structured shell commands with deny-by-default risk classification
- Atomic, expiring, single-use approval requests
- Separate trusted administrator CLI; no MCP self-approval tool
- Bounded, redacted JSON Lines audit events
- Windows and POSIX support

## Requirements

- Python 3.12 or newer (CI currently validates 3.12 and 3.13)
- An MCP client that supports stdio servers
- `git` for Git tools and approval-gated Git shell requests

## Installation

Install from a source checkout with uv:

```text
uv tool install .
```

Or build and install the wheel:

```text
uv build
uv tool install dist/mcp_toolhub-0.1.0-py3-none-any.whl
```

Installation provides two executables:

- `mcp-toolhub` — the stdio MCP server
- `mcp-toolhub-admin` — the trusted human approval CLI

## Runtime configuration

### Workspace root

`TOOLHUB_WORKSPACE_ROOT` is required for `mcp-toolhub serve` and for the admin
CLI. It must contain an absolute path to an existing directory. ToolHub
canonicalizes the path once and freezes it for the lifetime of the process.

ToolHub intentionally does not default to the current directory, source
checkout, or installation directory.

### Trusted state root

`TOOLHUB_STATE_ROOT` optionally selects the directory containing
`approvals.json` and `audit.jsonl`. It must be absolute when provided. When it
is unset, ToolHub uses the platform-appropriate per-user state directory from
`platformdirs`.

The state directory is created as needed, canonicalized, and frozen with the
workspace configuration. Startup fails if the state root is inside the
workspace. The server and administrator CLI must run as the same user and with
the same environment so they share this state.

### POSIX example

```text
export TOOLHUB_WORKSPACE_ROOT=/home/alice/projects/example
export TOOLHUB_STATE_ROOT=/home/alice/.local/state/mcp-toolhub
mcp-toolhub serve
```

### Windows PowerShell example

```powershell
$env:TOOLHUB_WORKSPACE_ROOT = "D:\work\example"
$env:TOOLHUB_STATE_ROOT = "$env:LOCALAPPDATA\mcp-toolhub"
mcp-toolhub serve
```

The server writes no banner or human log text to stdout. Stdout is reserved
exclusively for MCP protocol messages. Expected configuration errors are
reported concisely on stderr and exit nonzero.

## Commands

```text
mcp-toolhub --version
mcp-toolhub serve
python -m mcp_toolhub serve

mcp-toolhub-admin --help
mcp-toolhub-admin list
mcp-toolhub-admin approve REQUEST_ID
mcp-toolhub-admin reject REQUEST_ID
```

The admin command is human-facing and may write ordinary output to stdout. It
is not an MCP transport process.

## MCP client configuration

The exact outer configuration key varies by client. A typical POSIX stdio
entry is:

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "mcp-toolhub",
      "args": ["serve"],
      "env": {
        "TOOLHUB_WORKSPACE_ROOT": "/home/alice/projects/example",
        "TOOLHUB_STATE_ROOT": "/home/alice/.local/state/mcp-toolhub"
      }
    }
  }
}
```

Windows paths require JSON escaping:

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "mcp-toolhub",
      "args": ["serve"],
      "env": {
        "TOOLHUB_WORKSPACE_ROOT": "D:\\work\\example",
        "TOOLHUB_STATE_ROOT": "C:\\Users\\alice\\AppData\\Local\\mcp-toolhub"
      }
    }
  }
}
```

Use an absolute executable path if the MCP client does not inherit the shell's
`PATH`.

## Tool inventory

The production server exposes exactly these 12 MCP tools:

- `toolhub.ping`
- `toolhub.audit_recent`
- `filesystem.list_directory`
- `filesystem.read_file`
- `filesystem.write_file`
- `filesystem.write_file_approved`
- `filesystem.apply_patch`
- `filesystem.apply_patch_approved`
- `git.status`
- `git.diff`
- `shell.run`
- `shell.run_approved`

There is no MCP administration, approve, or reject tool.

## Human approval workflow

1. An MCP mutation or external shell request returns a pending request ID.
2. The administrator runs `mcp-toolhub-admin list` with the same workspace and
   state environment as the server.
3. For approval, the administrator runs
   `mcp-toolhub-admin approve REQUEST_ID`.
4. The CLI displays the protected request and requires the operator to type
   `APPROVE` exactly.
5. The MCP caller invokes the corresponding `_approved` tool with the request
   ID. Successful consumption is atomic and single-use.

For shell requests, the approval display includes the original program,
canonical resolved executable, SHA-256, byte size, cwd, and separately
JSON-escaped argument values. It does not represent arguments as an ambiguous
shell command string.

## Security model and limitations

### Structured shell commands

`shell.run` uses a deny-by-default command policy. LOW is limited to exact
ToolHub intrinsics, currently the running Python version query. LOW never
searches `PATH` and never creates an external subprocess. Generic Git, shell
interpreters, Windows batch scripts, the `py` launcher, and unknown programs
are never LOW.

Every external shell command is MEDIUM or HIGH and requires an out-of-band
administrator approval. The approval captures immutable program, argument,
cwd, timeout, workspace, and primary-executable snapshots. An approved shell
request is atomically consumed before snapshot validation; any later failure
permanently consumes it, so a retry requires a new approval.

Immediately before `subprocess` launch, ToolHub validates the primary
executable's canonical path, size, and SHA-256. Execution uses that absolute
path with `shell=False`. This is a **validated primary executable identity
immediately before launch**, not a cryptographic guarantee of the exact bytes
ultimately mapped by the operating system.

ToolHub guarantees:

- LOW never creates an external subprocess.
- Every external shell execution requires MEDIUM or HIGH approval.
- The agent cannot replace approved program, arguments, cwd, or timeout.
- Approvals are atomic, expiring, and single-use.
- Workspace and primary-executable snapshots are required and fail closed.
- The primary executable's canonical identity and hash are revalidated
  immediately before launch.
- Filesystem paths remain within the frozen workspace boundary.
- Mutation paths reject symlink traversal and enforce `expected_hash`
  concurrency checks where applicable.

ToolHub does not guarantee:

- Exact byte identity against a concurrent local filesystem adversary during
  the narrow final check-to-exec race.
- Identity of DLLs, interpreters, helpers, plugins, configuration files,
  environment-selected dependencies, or descendant processes.
- That approved executable bytes are benign, signed, or from a reputable
  publisher.

The administrator approval display exposes the protected canonical path,
hash, size, cwd, and exact JSON-escaped argument boundaries. Agent-readable
audit events omit external executable directories, retaining basename, hash,
size, scope, and request-ID correlation.

### Audit behavior

Audit events are appended to `audit.jsonl` under the trusted state root. They
contain bounded metadata, redact recognizable secret arguments, and store only
stdout/stderr character counts rather than raw process output. Audit write
failures are non-fatal to tool execution.

## Development

Install all locked runtime and development dependencies:

```text
uv sync --all-groups
```

Run the required checks:

```text
uv run ruff check .
uv run ruff format --check .
uv run python -m compileall -q src/mcp_toolhub
uv run pytest -q
uv build
git diff --check
```

To apply formatting deliberately:

```text
uv run ruff format .
```

### Artifact smoke test

After `uv build`, run the cross-platform smoke driver with a virtual
environment outside the checkout.

POSIX:

```text
uv run python scripts/artifact_smoke.py --dist-dir dist --venv /tmp/mcp-toolhub-wheel-env --repository .
```

Windows PowerShell:

```powershell
uv run python scripts/artifact_smoke.py --dist-dir dist --venv "$env:TEMP\mcp-toolhub-wheel-env" --repository .
```

The driver inspects wheel contents, installs only the wheel into the isolated
environment, verifies console/version behavior, and runs initialize,
`list_tools`, ping, configured workspace access, invalid configuration, and
server/admin shared-state tests from outside the repository.

## Troubleshooting

- **`TOOLHUB_WORKSPACE_ROOT is required`**: add an absolute existing workspace
  path to the MCP client's environment.
- **Workspace is not a directory**: create the directory or correct the path.
- **State root must be outside the workspace**: move `TOOLHUB_STATE_ROOT` to a
  trusted directory the MCP filesystem tools cannot address.
- **Client reports invalid stdio JSON**: verify wrappers and startup scripts do
  not print banners or logs to stdout.
- **Admin cannot see a request**: confirm server and admin run as the same user
  with identical workspace and state-root settings.
- **Executable changed after approval**: request a new approval; consumed or
  invalidated approvals are never replayed.

Production ToolHub intentionally exposes no HTTP, SSE, public network,
authentication-server, container-orchestration, or cloud-hosting surface.
