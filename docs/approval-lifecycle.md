# Approval lifecycle and Contract V1

MCP ToolHub separates proposing an action from authorizing and executing it.
The MCP client can submit a request and observe its state. Only a human using
the separate local administrator CLI can approve or reject it.

Contract V1 is the agent-facing protocol for that lifecycle. Its version is
`1.0` and is independent of package version `0.1.0`.

## The two views of a lifecycle

Contract results have an `outcome`; the protected request has a `status`.
Keeping those concepts separate avoids an important ambiguity:

```text
submission
  -> APPROVAL_REQUIRED outcome / PENDING status
  -> APPROVED / REJECTED / EXPIRED status
  -> resume
       -> atomic APPROVED -> CONSUMED status transition
       -> SUCCEEDED / COMMAND_FAILED / TIMED_OUT /
          CONFLICT / REFUSED / FAILED outcome
  -> later status observation reports APPROVAL_CONSUMED
```

The resume path consumes an approved request *before* attempting its stored
action. A command failure, conflict, validation refusal, or internal failure
after consumption does not make the approval reusable.

The state-specific outcomes are:

| Protected status | `toolhub.request_status` outcome |
| --- | --- |
| `PENDING` | `APPROVAL_PENDING` |
| `APPROVED` | `APPROVAL_APPROVED` |
| `REJECTED` | `APPROVAL_REJECTED` |
| `EXPIRED` | `APPROVAL_EXPIRED` |
| `CONSUMED` | `APPROVAL_CONSUMED` |

## Submission

These initial tools create approval requests:

| Initial tool | Resume tool | Protected action |
| --- | --- | --- |
| `filesystem.write_file` | `filesystem.write_file_approved` | Exact path, content, expected hash, parent-creation flag, and workspace snapshot |
| `filesystem.apply_patch` | `filesystem.apply_patch_approved` | Exact path, unified diff, expected hash, and workspace snapshot |
| `shell.run` for an external command | `shell.run_approved` | Program, argument boundaries, working directory, timeout, workspace, primary executable, and sanitized environment snapshots |

The initial call validates and bounds the proposal, persists the protected
request, and returns `APPROVAL_REQUIRED`. It does not perform the write, patch,
or external execution.

The returned `approval` handle contains only:

- `request_id`
- `status`
- `expires_at`
- the server-derived `resume_tool`

The agent does not receive the protected payload from either the handle or
`toolhub.request_status`.

## Human decision

The trusted operator uses the same workspace and state configuration as the
server:

```text
mcp-toolhub-admin list
mcp-toolhub-admin approve REQUEST_ID
mcp-toolhub-admin reject REQUEST_ID
```

Approval displays the candidate and requires `APPROVE` typed exactly. File
mutations are represented by bounded metadata, including path, size/hash, and
concurrency fields; shell requests display the requested program, canonical
primary executable identity, working directory, and separately JSON-escaped
arguments. The CLI then makes an atomic `PENDING -> APPROVED` decision.

There is deliberately no MCP approval or rejection endpoint. Possession of a
request ID is not approval authority.

## Expiry

Requests default to a five-minute lifetime. The operator may set
`TOOLHUB_APPROVAL_TTL_SECONDS` to a nonnegative integer before starting the
server; this is a runtime setting, not an MCP input.

Pending and approved requests cannot execute after `expires_at`. The
read-only status tool computes effective expiry without writing to the store.
Decision and resume paths persist terminal expiry when they encounter it.

Expiry never extends when the agent polls, and an expired request requires a
new submission.

## Resume and single-use consumption

After `toolhub.request_status` returns `APPROVAL_APPROVED`, the client calls
the handle's `resume_tool` with only:

```json
{"request_id": "req_..."}
```

The client cannot replace the approved path, content, patch, program,
arguments, working directory, timeout, executable snapshot, or execution
environment during resume.

Under the cross-process approval-store lock, ToolHub atomically changes
`APPROVED` to `CONSUMED`. Only the caller that wins this transition receives
the stored action for execution. Concurrent or later resumes receive
`APPROVAL_CONSUMED`, which prevents replay.

## Outcomes

All approval-gated result models share the Contract V1 lifecycle fields:

- `outcome` — the stable machine-readable branch
- `trace_id` — correlation across submission, status, execution, and audit
- `approval` — a safe public handle when applicable
- `error` — a bounded code, message, and retryable flag when applicable

Expected domain results are represented in MCP `structuredContent`:

| Outcome | Meaning |
| --- | --- |
| `APPROVAL_REQUIRED` | A new protected request was stored |
| `APPROVAL_PENDING` | Human review has not completed |
| `APPROVAL_APPROVED` | The matching resume tool may be called before expiry |
| `APPROVAL_REJECTED` | The human rejected the request |
| `APPROVAL_EXPIRED` | The request is no longer executable |
| `APPROVAL_CONSUMED` | The single-use request was already consumed |
| `SUCCEEDED` | The stored action completed successfully |
| `COMMAND_FAILED` | An approved command exited nonzero |
| `TIMED_OUT` | An approved command exceeded its bounded timeout |
| `CONFLICT` | Mutation concurrency or target state did not match |
| `REFUSED` | Policy or request-state validation refused the action |
| `FAILED` | The approved action could not complete |

Input-schema violations and unexpected tool failures may still be MCP errors.
Clients must use `structuredContent` as authoritative and must not parse the
compatibility `message` or rendered text to make decisions.

## Read-only status observation

`toolhub.request_status` accepts only `request_id`. It does not:

- approve or reject;
- consume a request;
- extend expiry;
- persist a lazy expiry observation; or
- return the protected payload.

Unknown IDs and IDs bound to another workspace receive the same `REFUSED` /
`REQUEST_NOT_FOUND` shape so the API does not reveal cross-workspace
existence.

## Client algorithm

1. Call `toolhub.capabilities` and select a Contract V1 operation.
2. Call the initial tool and inspect `structuredContent.outcome`.
3. On `APPROVAL_REQUIRED`, retain the returned handle and `trace_id`.
4. Poll `toolhub.request_status` at a reasonable cadence while pending.
5. On `APPROVAL_APPROVED`, call the supplied `resume_tool` once with the
   request ID.
6. Handle the returned execution outcome. Never retry a consumed approval;
   submit a new request if another attempt is appropriate.

Clients must never automate the human approval CLI.

## Correlation and audit

One `trace_id` follows the proposal through status and resumed execution.
Audit events include that correlation ID and bounded request metadata, allowing
an operator or client to reconstruct the lifecycle without exposing mutation
contents, raw command output, or trusted state paths.

See the [demo](demo.md) for the complete flow and
[architecture](architecture.md) for the trust assumptions behind it.
