# Architecture and threat model

MCP ToolHub is a local process boundary between an untrusted MCP client, a
configured workspace, and a human-controlled approval path. It uses stdio for
MCP transport and has no HTTP, SSE, or other network listener.

![MCP ToolHub trust-boundary architecture](assets/architecture.svg)

## Architecture overview

The server exposes 14 tools in three paths:

1. Bounded inspection and control calls execute directly: filesystem reads and
   listing, Git status/diff, capabilities, request status, recent audit
   metadata, and ping.
2. File writes and patches validate the exact proposed change and create a
   pending request in trusted state; they do not mutate the workspace.
3. `shell.run` executes one exact LOW-risk intrinsic in-process. Every
   agent-selected external command creates a pending request.

The trusted administrator CLI is a separate process. It shares only the bound
state namespace with the server, presents the approval candidate to the human,
and records approval or rejection. The MCP surface cannot invoke that code
path.

After approval, the matching resume tool accepts only the request ID,
atomically consumes the request, revalidates the stored snapshot, and performs
the action.

## Trust boundaries

| Zone | Contents | Trust position |
| --- | --- | --- |
| Agent-controlled | MCP client, tool names, arguments, request IDs, polling cadence | All inputs are untrusted |
| MCP ToolHub process | stdio server, validation, policy, bounded execution, result shaping | Enforcement boundary |
| Workspace | Files and optional Git repository selected at startup | Accessible only through workspace-relative ToolHub paths; not trusted state |
| Trusted state | Workspace binding, approvals, locks, audit log | Outside the workspace and unavailable through filesystem MCP tools |
| Trusted human boundary | `mcp-toolhub-admin` and its interactive operator | Only source of approval/rejection decisions |

The server and administrator must run as the same local user with identical
`TOOLHUB_WORKSPACE_ROOT` and `TOOLHUB_STATE_ROOT` settings. The operating
system, Python runtime, installed ToolHub code, and trusted state ownership are
part of the trusted computing base.

## Workspace and trusted state

`TOOLHUB_WORKSPACE_ROOT` is required, absolute, existing, canonicalized, and
frozen for the process lifetime. API paths are relative and checked using
portable POSIX and Windows path rules before canonical containment.

`TOOLHUB_STATE_ROOT` is optional. When explicit, it must be absolute. When
omitted, ToolHub creates a deterministic per-workspace namespace below the
platform user-state directory. Either way:

- the state root must be outside the workspace;
- a binding file permanently associates it with one canonical workspace;
- unexpected files, unsafe types, symlinks, or binding mismatches fail closed;
- approval and binding writes use same-directory temporary files, flushing,
  atomic replacement, and cross-process locks; and
- on POSIX, managed state directories/files are normalized to `0700`/`0600`.

Windows POSIX mode bits are not ACLs. ToolHub does not claim to create or
preserve Windows ACL policy; operators must choose an appropriately protected
state location.

## MCP-facing surface

The MCP process reserves stdout for protocol messages. Configuration failures
are concise stderr errors with a nonzero exit.

The public surface contains:

- eight direct inspection/control tools;
- three approval-submission tools; and
- three single-use resume tools.

The full matrix is in the [README](../README.md#production-tool-surface).
`toolhub.ping` uses the SDK defaults for annotations; all read-only inspection
and control tools explicitly declare read-only, non-open-world behavior.
Submission and resume tools are marked mutating/destructive because they
participate in or execute state-changing operations.

There is no MCP admin, approve, reject, pruning, arbitrary state read, or
shutdown tool.

## Trusted administrator CLI

`mcp-toolhub-admin` is intentionally human-facing and may write ordinary
terminal output. It can:

- list approval candidates;
- approve a pending request after exact interactive confirmation;
- reject a pending request; and
- explicitly prune eligible terminal approvals or compact bounded audit
  history.

Maintenance commands are dry runs unless `--apply` is supplied. The CLI never
changes the state-root binding and does not expose an MCP transport.

## Execution boundaries

### Filesystem

Reads are bounded to UTF-8 regular files within the workspace. Directory
listing is bounded and reports entry types.

Mutation submissions reject absolute paths, portable parent traversal, and
symlink path components. Writes publish through an exclusive same-directory
temporary file, flush/fsync, and `os.replace`. New POSIX files use `0600`;
replacement retains ordinary `rwx` mode bits but clears special bits.

An optional `expected_hash` provides optimistic concurrency. Target
creation/disappearance, metadata replacement, hash mismatch, malformed patch,
or a patch that does not apply cleanly results in refusal/conflict without
partial patch publication.

These pathname checks do not provide an atomic compare-and-swap against a
local adversary replacing ancestors during the remaining narrow races.
Ownership, extended attributes, ACLs, and Windows ACL preservation are not
guaranteed.

### External commands

`shell.run` accepts a program and argument array; it never builds a shell
command string. The only LOW operation is ToolHub's in-process Python version
query. It performs no subprocess launch.

Every external command is MEDIUM or HIGH and requires approval. Its request
binds the structured arguments, workspace-relative working directory, timeout,
workspace identity, resolved primary executable path/size/SHA-256, and a
minimal sanitized environment. Before launch, ToolHub revalidates the primary
executable and uses its absolute path with `shell=False`.

The executable check is a validation immediately before launch, not a
cryptographic guarantee against the operating system's check-to-exec race. It
does not attest DLLs, interpreters, helpers, plugins, configuration, loaded
dependencies, or descendants.

Approved processes are not network-isolated and do not receive a general
filesystem sandbox. On POSIX they run in a new session/process group. On
Windows they are assigned, while initially suspended, to a kill-on-close Job
Object. Timeout and cleanup terminate the contained process tree, but this is
a process-lifetime boundary rather than a container or kernel security
sandbox.

### Read-only Git

`git.status` and `git.diff` invoke fixed Git commands with a sanitized
environment, bounded preflight/execution budgets, output capture, and
process-tree containment. ToolHub disables or refuses pagers, external diff,
textconv, fsmonitor, prompts, transport-backed missing-object lookup, and
applicable executable clean/process filters. Gitlinks/submodules are refused.

ToolHub asks Git itself to resolve attributes, including configured attribute
sources, rather than implementing a partial matcher. The checks are a
fail-closed preflight for a cooperating workspace, not an atomic snapshot
against a local process racing Git configuration, attributes, or index files.

## Approval and audit state

Approval requests use cryptographically random IDs and retain an immutable
protected action snapshot while status changes under a cross-process lock.
They expire and transition atomically from `APPROVED` to `CONSUMED` before
execution. See [Approval lifecycle](approval-lifecycle.md).

Audit events are appended as JSON Lines in trusted state. Fields and
collections are bounded; recognizable secret arguments are redacted; command
stdout/stderr content is not stored. Audit failures are non-fatal to the
underlying tool action, so an action result is not proof that an audit append
succeeded.

The agent-facing `toolhub.audit_recent` reads at most 100 sanitized recent
events through a bounded tail scan. Administrative recovery for an audit log
above the compaction limit is documented in the
[audit maintenance runbook](audit-maintenance-recovery.md).

## Bounded resource model

The public capability response reports the client-relevant limits. Current
important bounds include:

| Resource | Bound |
| --- | --- |
| File read or write payload | 256 KiB |
| Patch text | 256 KiB characters |
| Directory entries returned | 2,048 |
| Shell timeout | 60 seconds maximum |
| Public shell/Git output retained | 20,000 characters per field |
| Subprocess capture retained | 256 KiB per stdout/stderr stream; excess is drained and discarded |
| Git execution/preflight budget | 20 seconds |
| Git status entries | 1,024 |
| Recent audit events | 100; tail scan bounded to 1,000,000 bytes |
| Approval store | 10,000 records and 16 MiB serialized |
| Audit compaction input | 64 MiB |

These are ToolHub resource bounds, not general CPU, memory, disk, or network
quotas for an approved child.

## Threat assumptions

ToolHub is designed to treat MCP tool calls and their parameters as untrusted.
It aims to prevent the agent from escaping the configured workspace through
ToolHub paths, modifying files without human approval, changing an approved
snapshot at resume time, replaying approval, or silently invoking an external
program through the LOW path.

It assumes:

- the local human and administrator CLI are trusted;
- the OS account, runtime, installed code, and trusted state are not controlled
  by the agent;
- the chosen workspace may contain unusual or hostile-looking repository
  configuration, which read-only Git preflight handles conservatively; and
- an approved external executable may exercise the permissions of the local
  account, because approval is authorization rather than sandboxing.

A concurrent malicious local process with access to the same account or files
is outside the complete protection model. Specific validation narrows races
but does not eliminate all host-filesystem or OS loader races.

## Major guarantees

- No HTTP/SSE or other ToolHub network listener
- No agent-accessible approval or rejection operation
- Frozen canonical workspace and separate, workspace-bound trusted state
- Relative path confinement and mutation symlink/traversal rejection
- Immutable approval payloads with expiry and atomic single-use consumption
- Stored-action-only resume tools
- Structured `shell=False` external launch with primary-executable
  revalidation and sanitized environment
- Bounded timeout/output handling and process-tree cleanup
- Fail-closed fixed Git inspection policy
- Bounded, sanitized, correlated audit metadata
- Contract V1 fixture and cross-platform CI/build smoke coverage

## Explicit non-goals

- Remote or cloud MCP transport
- Multi-user authentication, authorization, or RBAC
- A general filesystem, CPU, memory, kernel, or network sandbox
- Agent self-approval or automated human confirmation
- Proving approved executable bytes or dependencies are benign
- Identity guarantees for dynamically loaded code or descendant processes
- Complete protection from a same-user local adversary racing filesystem state
- Automatic approval/audit retention policy or log rotation

## Cross-platform notes

CI exercises Python 3.12 and 3.13 on Ubuntu and Windows, including the built
wheel and complete stdio approval flows. POSIX uses process groups,
`flock`-style state locking, and file modes. Windows uses Job Objects,
byte-range file locks, and native replacement semantics. Where an OS does not
offer equivalent semantics—most notably POSIX modes versus Windows ACLs—the
difference is documented rather than emulated.
