# 60–120 second demo

This demo uses a throwaway workspace, a separate trusted state directory, the
public stdio MCP API, and the real administrator CLI. It demonstrates the
human boundary without modifying this repository.

The included [demo client](../examples/demo_client.py) is intentionally small:
it launches `mcp-toolhub serve` with the same Python environment, communicates
only through public MCP calls, and has no approval capability.

## 1. Prepare the source environment

From the repository checkout:

```text
uv sync --all-groups
```

The demo uses this editable development environment. A normal user
installation instead uses `uv tool install .`.

## 2. Create disposable workspace and trusted state

### POSIX

```text
export TOOLHUB_DEMO_ROOT="$(mktemp -d)"
mkdir "$TOOLHUB_DEMO_ROOT/workspace" "$TOOLHUB_DEMO_ROOT/state"
printf 'Agent-readable seed file.\n' > "$TOOLHUB_DEMO_ROOT/workspace/seed.txt"
export TOOLHUB_WORKSPACE_ROOT="$TOOLHUB_DEMO_ROOT/workspace"
export TOOLHUB_STATE_ROOT="$TOOLHUB_DEMO_ROOT/state"
```

### Windows PowerShell

```powershell
$toolhubDemoRoot = Join-Path $env:TEMP ("mcp-toolhub-demo-" + [guid]::NewGuid())
New-Item -ItemType Directory "$toolhubDemoRoot\workspace", "$toolhubDemoRoot\state"
Set-Content -NoNewline "$toolhubDemoRoot\workspace\seed.txt" "Agent-readable seed file."
$env:TOOLHUB_WORKSPACE_ROOT = "$toolhubDemoRoot\workspace"
$env:TOOLHUB_STATE_ROOT = "$toolhubDemoRoot\state"
```

The state directory is a sibling of the workspace, so the MCP filesystem
surface cannot read approval or audit storage.

## 3. Initialize, inspect, read, and submit

Run:

```text
uv run python examples/demo_client.py submit
```

The script:

1. starts `mcp-toolhub serve` as a stdio child;
2. performs MCP initialization;
3. calls `tools/list` and verifies the exact 14-tool inventory;
4. calls `toolhub.capabilities` and prints Contract `1.0` / transport `stdio`;
5. reads `seed.txt` with `filesystem.read_file`; and
6. submits `filesystem.write_file` for `approved.txt`.

The final result is `APPROVAL_REQUIRED` with a `REQUEST_ID` and `TRACE_ID`.
Copy the request ID. The script exits; the pending request remains in trusted
state and no `approved.txt` exists yet.

## 4. Cross the human boundary

Open a second terminal in the repository. Set the same
`TOOLHUB_WORKSPACE_ROOT` and `TOOLHUB_STATE_ROOT` values, then run:

```text
uv run mcp-toolhub-admin list
uv run mcp-toolhub-admin approve REQUEST_ID
```

Inspect the displayed candidate. At the prompt, type:

```text
APPROVE
```

The admin CLI reports `Approved REQUEST_ID.` The important boundary is visible:
there is no MCP call in the demo client that can produce this decision.

## 5. Resume, audit, and prove single use

Back in the first terminal:

```text
uv run python examples/demo_client.py resume REQUEST_ID
```

The script verifies and prints:

1. `toolhub.request_status -> APPROVAL_APPROVED`;
2. `filesystem.write_file_approved -> SUCCEEDED`;
3. correlated `toolhub.audit_recent` events sharing the original `trace_id`;
4. a replay of the resume call -> `APPROVAL_CONSUMED`; and
5. `approved.txt` read back through MCP.

At this point the protected status is `CONSUMED`. The approval cannot be
revived even if execution had failed after consumption.

## What to narrate

> The agent can inspect a confined workspace directly. A mutation only creates
> an immutable, expiring request in state outside that workspace. A separate
> human CLI authorizes it, the resume tool accepts only the request ID, and
> atomic consumption prevents replay. Everything remains local over stdio.

That is the project in under two minutes: MCP infrastructure, a concrete human
trust boundary, structured lifecycle semantics, and bounded cross-platform
execution.

## Optional cleanup

After the demo and after both ToolHub processes have exited, remove only the
throwaway root printed or assigned above using the normal filesystem tools for
your platform. It contains the disposable workspace, trusted state, approval
record, and audit log.

Do not point the cleanup command at the repository or a shared state
directory.

## Expected outcomes

| Step | Expected observation |
| --- | --- |
| Initialize | Server name `MCP ToolHub`, package version `0.1.0` |
| `tools/list` | Exactly 14 names and no approve/reject MCP tool |
| Capabilities | Contract `1.0`, transport `stdio`, `human_only: true` |
| Read | `seed.txt` content and SHA-256 |
| Submit | `APPROVAL_REQUIRED`, `executed: false` |
| Status after CLI | `APPROVAL_APPROVED` |
| Resume | `SUCCEEDED`, `executed: true` |
| Audit | Events correlated by the submission `trace_id` |
| Replay | `APPROVAL_CONSUMED` / error code `APPROVAL_CONSUMED` |

These expectations are also covered at transport level by the repository test
suite and by the installed-wheel smoke validation.
