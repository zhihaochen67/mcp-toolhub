# MCP ToolHub

MCP ToolHub is a local, stdio-only Model Context Protocol server that exposes
bounded workspace filesystem operations, read-only Git inspection, structured
command execution, and an audit trail. Mutating filesystem operations and all
agent-selected external shell commands use the existing out-of-band human
approval model.

ToolHub does not expose an HTTP, SSE, or other network listener.

## Features

- Workspace-confined file reading, directory listing, writes, and patches
- Read-only Git status and diff operations
- Structured shell commands with deny-by-default risk classification
- OS-backed process-tree containment for external executions
- Atomic, expiring, single-use approval requests
- Versioned, resumable Contract V1 lifecycle results
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
`workspace-binding.json`, `approvals.json`, and `audit.jsonl`. It must be
absolute when provided. The directory is permanently bound on first valid use
to exactly one canonical workspace; reusing it for another workspace fails
closed.

When `TOOLHUB_STATE_ROOT` is unset, ToolHub uses the platform-appropriate
per-user state directory from `platformdirs` as a base. Each canonical
workspace receives an independent namespace below `workspaces/`, named with a
deterministic SHA-256 identifier derived from the platform-normalized canonical
workspace path. The identifier avoids placing the workspace path in directory
names, but it is namespace separation rather than an authentication secret.
Moving or renaming a workspace normally creates a new default namespace.

The state directory is created as needed, canonicalized, and frozen with the
workspace configuration. Startup fails if the state root is inside the
workspace. The server and administrator CLI must run as the same user and with
the same workspace and state configuration so they share this state.

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
mcp-toolhub-admin prune approvals --older-than-days N [--apply]
mcp-toolhub-admin prune audit --keep-last N [--apply]
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

The production server exposes exactly these 14 MCP tools:

- `toolhub.ping`
- `toolhub.audit_recent`
- `toolhub.capabilities`
- `toolhub.request_status`
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

## Execution Contract V1

ToolHub's agent-facing execution contract is version `1.0`. This contract
version is independent of the package/server version: compatible package
releases may keep Contract V1, while a deliberate incompatible contract change
requires a new contract version.

`toolhub.capabilities` is a deterministic, read-only discovery tool. It returns
`contract_version`, `package_version`, `transport` (`stdio`), the public human
approval model, approval-gated initial/resume tool mappings, and bounded public
limits. `shell_output_retained_chars` and `git_output_retained_chars` are the
number of original output characters retained before a truncation marker is
appended; they are not maximum lengths for the returned strings. Capabilities
does not expose approval payloads, trusted state paths, executable paths, or
secrets.

Approval-gated operation results use MCP `structuredContent` as the primary
machine-readable API and include:

- `outcome`: one of `APPROVAL_REQUIRED`, `APPROVAL_PENDING`,
  `APPROVAL_APPROVED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`,
  `APPROVAL_CONSUMED`, `SUCCEEDED`, `COMMAND_FAILED`, `TIMED_OUT`, `CONFLICT`,
  `REFUSED`, or `FAILED`.
- `trace_id`: one lifecycle correlation ID preserved across submission,
  approval state, approved execution, and audit events.
- `approval`: when applicable, an approval handle containing `request_id`,
  `status`, `expires_at`, and the server-derived `resume_tool`.
- `error`: when applicable, a bounded object containing a stable `code`, a
  human-readable `message`, and a `retryable` boolean.

Expected domain outcomes—approval states, unknown requests, policy refusals,
conflicts, nonzero commands, and timeouts—are structured results. Input-schema
validation errors and unexpected internal failures remain MCP/tool errors.
Clients must make decisions from `outcome`, `approval`, and `error`, never by
parsing the compatibility `message` or text representation.

`toolhub.request_status` accepts only `request_id`. It is strictly read-only:
it never approves, rejects, consumes, extends expiry, or persists lazy expiry.
For a current-workspace request it returns the effective approval state,
original `trace_id`, and safe approval handle without the protected payload.
An unknown ID and an ID belonging to another workspace receive the same
`REFUSED` / `REQUEST_NOT_FOUND` shape, with no existence metadata.

### Generic client state machine

1. Call `toolhub.capabilities` and select a supported Contract V1 operation.
2. Call the operation and inspect its structured `outcome`.
3. On `APPROVAL_REQUIRED`, retain the returned approval handle.
4. Poll `toolhub.request_status` at an appropriate cadence while it reports
   `APPROVAL_PENDING`.
5. On `APPROVAL_APPROVED`, invoke `approval.resume_tool` with only the stored
   `request_id`.
6. Inspect the resumed structured outcome; do not retry a consumed approval.

**CLIENTS MUST NEVER AUTOMATE HUMAN APPROVAL.** Approval and rejection remain
out-of-band actions performed through the trusted local administrator CLI.
Coding-agent integrations, including Repo Doctor-style clients, should use
only the generic MCP discovery, status, and resume flow; ToolHub embeds no
client-specific code.

## Human approval workflow

1. An MCP mutation or external shell request returns `APPROVAL_REQUIRED` and
   an approval handle.
2. The administrator runs `mcp-toolhub-admin list` with the same workspace and
   state environment as the server.
3. For approval, the administrator runs
   `mcp-toolhub-admin approve REQUEST_ID`.
4. The CLI displays the protected request and requires the operator to type
   `APPROVE` exactly.
5. The MCP caller observes `APPROVAL_APPROVED` through
   `toolhub.request_status`, then invokes the handle's `resume_tool` with the
   request ID. Successful consumption is atomic and single-use.

For shell requests, the approval display includes the original program,
canonical resolved executable, SHA-256, byte size, cwd, and separately
JSON-escaped argument values. It does not represent arguments as an ambiguous
shell command string.

## Trusted state maintenance

Trusted-state pruning is explicit, human-operated maintenance through
`mcp-toolhub-admin`; it never runs at server startup or from an environment
toggle. Both commands are dry runs unless `--apply` is supplied:

```text
mcp-toolhub-admin prune approvals --older-than-days 30
mcp-toolhub-admin prune approvals --older-than-days 30 --apply
mcp-toolhub-admin prune audit --keep-last 10000
mcp-toolhub-admin prune audit --keep-last 10000 --apply
```

Approval pruning removes only terminal `REJECTED`, `EXPIRED`, or `CONSUMED`
records whose terminal timestamp is at or before the cutoff. A `PENDING` or
`APPROVED` record that is already past `expires_at` is effectively expired and
uses that expiry time for eligibility; still-valid pending and approved
requests are never pruned. Apply mode re-reads and recomputes eligibility while
holding the approval-store lock.

### Approval store capacity

`approvals.json` has fixed ceilings of 10,000 records and 16 MiB for its final
serialized UTF-8 representation. ToolHub checks both limits atomically under
the approval-store lock when adding a request. Values exactly at either limit
are allowed; a new request that would exceed a limit fails closed without
changing the store.

ToolHub never automatically deletes approval records or evicts valid active
requests to make room. When the store is full, an administrator can inspect and
prune old terminal records with `mcp-toolhub-admin prune approvals
--older-than-days N`; pruning remains explicit and is a dry run unless
`--apply` is supplied. Existing approval state transitions and explicit pruning
remain available when a previously created or restored store is already over a
current ceiling. These ceilings bound ToolHub's approval store; they are not a
general disk quota or operating-system resource sandbox.

Audit pruning retains the newest `N` complete events in their original order;
`--keep-last 0 --apply` explicitly empties an existing valid log. Appends and
compaction share a cross-process lock, and malformed audit content causes a
safe refusal without replacement. Maintenance uses only the already-bound
workspace/state namespace, exposes no protected payloads, and adds no MCP tool
or Contract V1 surface.

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

### Sanitized child-process environment

External commands do not inherit the ToolHub server process environment.
ToolHub builds a minimal sanitized environment when the approval request is
created, stores its versioned snapshot in protected approval state, and
executes with exactly that snapshot after approval. The snapshot is validated
and bound by a deterministic digest; legacy or malformed shell approvals that
lack it cannot execute and require a new request.

On POSIX, the current baseline inherits no environment variables. On Windows,
only validated absolute `SystemRoot`, `WINDIR`, `TEMP`, and `TMP` values are
preserved when present. `PATH`, shell profiles, home/configuration locations,
credentials, and interpreter, module, loader, shell, and Git injection
variables are excluded. Users should not expect arbitrary profile or `PATH`
behavior in approved children. Primary executable selection remains absolute,
fingerprinted, and approval-bound; the sanitized environment is not used to
select it.

### Process-tree containment

Every approved external command executes inside a dedicated OS-backed
process-tree lifetime boundary. Fixed read-only Git subprocesses use the same
boundary. On POSIX, ToolHub creates a new session/process group for each
execution. On Windows, it creates a per-execution Job Object with
kill-on-job-close enabled, starts the primary process suspended, assigns it to
the Job Object, and resumes it only after assignment succeeds.

On timeout, ToolHub terminates the contained execution tree rather than only
the primary process, captures available output with bounded cleanup waits, and
reaps the launched child. Containment resources are released deterministically
on success, command failure, timeout, start/setup failure, and internal cleanup
paths; remaining contained descendants are terminated when an execution is
cleaned up.

Process-tree containment complements rather than replaces human approval,
primary-executable identity binding, workspace binding, and the sanitized
environment policy. It is a process-lifetime boundary, not a full OS sandbox or
container: it does not add filesystem or network sandboxing, CPU or memory
resource isolation, kernel-level protection, or safe execution of arbitrary
hostile code.

### Bounded output capture

Approved shell executions and fixed read-only Git subprocesses capture stdout
and stderr through dedicated per-stream drain threads that start together with
the child process and read continuously until the pipes reach EOF. Each stream
retains at most 256 KiB (`MAX_CAPTURE_BYTES_PER_STREAM`) in a fixed-capacity
buffer; everything beyond that cap is still drained from the pipe but
discarded, with exact total/retained/dropped byte counters recorded as bounded
audit metadata.

Because the pipes are always drained, a child or contained descendant that
writes more than the OS pipe capacity cannot block the capture path, and
ToolHub memory for retained output is O(1) in the volume produced. Output
truncation is a reporting fact, not a failure: a command that exits 0 with
discarded output remains `SUCCEEDED`, a non-zero exit remains
`COMMAND_FAILED`, and timeouts remain `TIMED_OUT`. When the capture cap
discards output, the affected stdout/stderr value carries a deterministic
`[ToolHub discarded N output bytes]` marker.

Timeout and process-tree containment semantics are unchanged: on timeout
ToolHub terminates the contained tree, keeps draining until EOF or a bounded
deadline, closes its pipe handles as a final unblock if needed, and returns
`TIMED_OUT` with the retained output prefix.

Bounded capture protects ToolHub's own retained output memory (at most a few
hundred KiB of retained buffers per subprocess plus small transient read
chunks). It is not a CPU, memory, network, or filesystem sandbox for the child
process itself.

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
  code-selected dependencies, or descendant processes.
- That approved executable bytes are benign, signed, or from a reputable
  publisher.

The administrator approval display exposes the protected canonical path,
hash, size, cwd, and exact JSON-escaped argument boundaries. Agent-readable
audit events omit external executable directories, retaining basename, hash,
size, scope, and request-ID correlation.

### Audit behavior

Audit events are appended to `audit.jsonl` under the trusted state root. They
contain bounded metadata, redact recognizable secret arguments, and store only
stdout/stderr character counts and bounded capture byte counters rather than
raw process output. Audit write failures are non-fatal to tool execution.

### Contract compatibility fixture

`tests/fixtures/contract_v1.json` locks Contract V1's tool names, annotations,
approval mappings, stable enums, public input/output fields, required fields,
and normalized schema digests. Descriptions and other cosmetic SDK noise are
excluded.

To update it deliberately, first decide whether the change is compatible. An
incompatible change requires a new contract version and fixture. For a
compatible intentional schema change, update the models, regenerate the
normalized surface using `tests/test_contract.py::_contract_surface`, review
the readable field lists and changed digests, then update the fixture in the
same reviewed change. Never accept a fixture diff solely to make the test pass.

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
`list_tools`, structured capability/status calls, complete write/patch/shell
approval lifecycles, rejection, replay, cross-workspace isolation, invalid
configuration, and server/admin shared-state tests from outside the repository.

## Troubleshooting

- **`TOOLHUB_WORKSPACE_ROOT is required`**: add an absolute existing workspace
  path to the MCP client's environment.
- **Workspace is not a directory**: create the directory or correct the path.
- **State root must be outside the workspace**: move `TOOLHUB_STATE_ROOT` to a
  trusted directory the MCP filesystem tools cannot address.
- **State namespace belongs to a different workspace**: select a different
  explicit `TOOLHUB_STATE_ROOT`; bindings are never silently reassigned.
- **Client reports invalid stdio JSON**: verify wrappers and startup scripts do
  not print banners or logs to stdout.
- **Admin cannot see a request**: confirm server and admin run as the same user
  with identical workspace and state-root settings.
- **Executable changed after approval**: request a new approval; consumed or
  invalidated approvals are never replayed.

Production ToolHub intentionally exposes no HTTP, SSE, public network,
authentication-server, container-orchestration, or cloud-hosting surface.
