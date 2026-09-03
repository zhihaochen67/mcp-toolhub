# Audit maintenance recovery

Use this runbook when `audit.jsonl` exceeds the **64 MiB (67,108,864 bytes)**
compaction-read ceiling. Recovery is an offline administrator filesystem
operation; ToolHub has no rotation or oversized-log recovery command.
For configuration and routine maintenance, see the
[README](../README.md#trusted-state-maintenance).

## Symptoms

Both `mcp-toolhub-admin prune audit --keep-last 10000` and the same command
with `--apply` exit with status `1` and write this message to stderr:

```text
error: Audit maintenance failed: Audit log exceeds the safe compaction read limit.
```

The refusal leaves audit contents unreplaced. Lowering `--keep-last`, even to
`0`, cannot bypass the full-input check. A file exactly at the ceiling can
still be compacted if its content passes the other checks.

An oversized log alone does not prevent startup or further audit appends.
`toolhub.audit_recent` may still return recent events. Audit write failures
are non-fatal to tool execution, so a successful tool response does not by
itself prove that an event was recorded.

## Security rationale

Events are appended without automatic rotation or startup pruning. Long
operation, high event volume, missed maintenance, or restoration of a large
log can therefore leave more data than compaction will accept.

Compaction intentionally refuses oversized input to bound memory use, disk
I/O, temporary-copy work, and other resource exposure. Its 64 MiB input
ceiling is independent of the normal bounded tail reads and 100-event cap of
`toolhub.audit_recent`; it is not a disk quota or an append limit. This is a
fail-closed maintenance refusal, not evidence that the log is corrupt.

## Diagnosis

1. Inspect the MCP client's launch configuration. Use the same OS user,
   `TOOLHUB_WORKSPACE_ROOT`, and `TOOLHUB_STATE_ROOT` setting as that server.
   The server freezes these paths at initialization; changing a shell's
   environment does not change a running server's paths. If the state setting
   is absent, keep it unset: the default is the per-user `platformdirs` state
   base for `mcp-toolhub`, then `workspaces/<workspace-identifier>`. The
   identifier is a SHA-256 of the canonical workspace path, normalized for the
   platform. Do not guess the namespace or switch roots to clear the error.
2. The admin CLI has no path-display subcommand or audit-path override. With
   that same environment, use the existing Python configuration helper to
   resolve the root and audit filename. Run this in the Python environment
   containing ToolHub; from a source checkout, use `uv run python` in place of
   `python`:

   ```text
   python -c "from mcp_toolhub.security.paths import get_state_root; p = get_state_root(); print(p); print(p / 'audit.jsonl')"
   ```

   This initializes and validates configuration just as the CLI does. It can
   create missing state/binding/lock objects and normalize POSIX permissions;
   confirm the launch settings first. It does not read the audit contents.
3. Inspect file metadata rather than loading the JSONL file. Replace the
   placeholder below with the printed absolute audit path. This portable
   command uses `lstat` and refuses a non-regular file, including a symlink:

   ```text
   python -c "import os, stat, sys; s = os.lstat(sys.argv[1]); assert stat.S_ISREG(s.st_mode), 'Expected a regular audit file'; print(s.st_size)" "ABSOLUTE_PATH_TO_AUDIT_JSONL"
   ```

   Compare the byte count with `67108864`. Metadata from a running server can
   change; repeat after stopping writers before recovery. A missing file is
   not an oversized-log condition: compaction treats it as an empty log.
4. Use the dry-run command above to distinguish maintenance errors. Size is
   checked before JSON parsing, so an oversized log could also contain bad
   data; the size error does not validate its contents. For input within the
   ceiling, these are actual error suffixes after
   `error: Audit maintenance failed: `:

   | Error suffix | Meaning / next step |
   | --- | --- |
   | `Audit log contains malformed JSON.` | Preserve evidence; investigate invalid JSON or encoding. |
   | `Audit log contains an incomplete or empty event.` | Preserve evidence; a line is unfinished or empty. |
   | `Audit log contains an oversized or incomplete event.` | A line exceeds the separate event-size bound; reducing the retained count does not repair it. |
   | `Audit log contains a non-object event.` | JSON parsed but is not an event object. |
   | `Audit log could not be read safely.` | Investigate file type, access, and I/O failures. |
   | `Audit log changed while reading for compaction.` | Quiesce writers and investigate concurrent changes. |

   Configuration/binding errors from `mcp-toolhub-admin` exit with status `2`
   before maintenance. Treat those as a separate state/configuration problem;
   do not reset the state directory. Recent-event reads skip malformed entries
   and inspect only the tail, so they are not a whole-log integrity check.

## Recovery

**ToolHub must be stopped before direct filesystem rotation.** Use this
procedure only after identifying the correct namespace and regular audit
file. If diagnosis reveals unexpected state objects or binding/access errors,
preserve the evidence and investigate those separately before proceeding.

1. Stop every ToolHub server using this state root through its MCP client or
   process manager. Prevent automatic restarts and wait for in-flight work
   and administrator maintenance to finish. Ensure no other process is
   writing this log. ToolHub provides no shutdown or offline-rotation CLI.
2. Copy the entire `audit.jsonl`, byte for byte, to a unique archive filename
   in an administrator-controlled location **outside both the workspace and
   the trusted state root**. Use a real file, not a symlink or hard link, and
   do not overwrite an existing archive. Keep the original in place for now.
   Check destination capacity and restrict archive access before copying.
   Do not keep `audit.jsonl.bak` or an archive subdirectory inside the state
   root: startup rejects unexpected entries there.
3. Verify the archive exists, the copy completed successfully, and its byte
   count and streaming SHA-256 match the stopped original. For example, run
   this command separately for the original and archive, substituting each
   absolute path, and compare the hashes:

   ```text
   python -c "import hashlib, sys; f = open(sys.argv[1], 'rb'); print(hashlib.file_digest(f, 'sha256').hexdigest()); f.close()" "ABSOLUTE_PATH_TO_FILE"
   ```

   Record the original path, archive path, byte count, hash, and recovery time
   with the archive, outside trusted state. If copying or verification fails,
   leave the original untouched and resolve that failure before continuing.
4. Only after successful verification, remove the original `audit.jsonl`
   using the administrator's filesystem tools. Leave the state directory,
   `workspace-binding.json`, `approvals.json`, and **all lock sidecars** in
   place. Do not manually create or edit an empty replacement log.
5. Restart ToolHub with the same OS user and workspace/state configuration.
   A missing audit file is permitted; the first successful audit append
   creates it. Startup alone, `toolhub.ping`, and `toolhub.audit_recent` do
   not create an audit event. Through the MCP client, call the existing
   `shell.run` tool with:

   ```json
   {"program":"python","args":["--version"],"cwd":"."}
   ```

   This exact intrinsic query reports the hosting Python version without
   launching a subprocess or requiring approval. Retain its `trace_id`, then
   call `toolhub.audit_recent` with `{"limit":20}`. Verify a new event with
   that trace ID, `tool: "shell.run"`, `action: "execute"`, and
   `success: true`, and confirm the new `audit.jsonl` exists. If the event is
   missing, investigate configuration, access, locking, and disk space before
   treating recovery as complete; tool success alone is insufficient.
6. Retain the verified archive according to operator audit/backup policy.
   The new log starts a separate history; `audit_recent` and admin pruning
   do not read archives. Keep any investigation of archived malformed data
   offline and bounded, preserving the original bytes.

## Safety warnings

- Never delete the only copy before making and verifying an archive.
- Never edit JSONL contents in place, truncate, or rotate the log while
  ToolHub is running. Direct filesystem operations do not take its audit lock.
- Never replace the trusted state directory or delete/rewrite its binding,
  approval store, or lock files to recover an oversized audit log. In
  particular, keep `audit.jsonl.lock` stable: removing it can let processes
  acquire locks on different files. A sidecar's existence does not mean a
  process still holds its OS lock.
- Do not broaden permissions recursively or use `os.umask()`-style global
  workarounds. Protect archives as audit evidence even though events are
  bounded and redacted.
- Do not disable or raise the compaction bound, or use `--keep-last 0` as a
  bypass. Do not split/rewrite the active log to make it pass validation.

## Prevention

Run existing administrator maintenance regularly, well before 64 MiB, with
the same server configuration:

```text
mcp-toolhub-admin prune audit --keep-last 10000
mcp-toolhub-admin prune audit --keep-last 10000 --apply
```

The first command only plans content changes; the second retains the newest
10,000 complete events in original order. Choose `N` according to retention
policy (`0` through `100000` are accepted). Applied pruning removes older
events without creating an archive, so preserve them first if policy requires
it, with writers stopped for a consistent filesystem copy. `--keep-last 0
--apply` empties an existing valid log only if all input checks pass.

Apply mode holds the same cross-process audit lock as appends while scanning
and replacing the log, so routine CLI compaction can coordinate with a running
server. Dry runs do not hold that audit lock and can observe concurrent
changes; apply re-scans under lock. Lock acquisition has a five-second timeout;
the maintenance error may be `Audit compaction could not acquire the audit
lock.` Investigate contention instead of deleting a lock file.

Monitor byte size and maintenance exit status as well as retained event count:
event sizes and growth rates vary, and a dry run alone removes nothing. Choose
an interval with enough headroom for growth and maintenance failures. ToolHub
provides no built-in schedule, automatic log rotation, or startup compaction;
any scheduled maintenance must be arranged by the operator.

## Platform notes

- On POSIX, ToolHub secures its state directories to `0700` and trusted files
  to `0600`, including newly created audit logs. Even diagnostic/maintenance
  reads can normalize trusted-file permissions. Archive copies are outside
  this management; give them suitably restrictive access yourself.
- On Windows, POSIX modes are not Windows ACLs; ToolHub's POSIX permission
  helpers do not establish or preserve Windows ACLs. Verify access controls
  for the archive destination and the existing state location using Windows
  administration practices. Wait for all relevant process/file handles to
  close before removing the original; a sharing failure is not a reason to
  force a live rotation.
- The audit sidecar uses POSIX `flock` or Windows byte-range locking. Neither
  makes manual filesystem rotation safe with active writers. The offline
  procedure and unchanged namespace requirement apply on both platforms.
