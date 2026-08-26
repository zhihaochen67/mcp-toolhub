# ToolHub security model

## Structured shell commands

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
