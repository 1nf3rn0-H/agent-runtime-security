# Trace-token propagation

Status: Prototype
Last updated: September 10, 2026

## Objective

Link a Codex session, its subagents, each tool call, and every ordinary descendant process into one queryable execution trace.

## Identity model

| Field | Scope | Purpose |
|---|---|---|
| `ARS_TRACE_ID` | Codex session | Stable public correlation identifier |
| `ARS_TRACE_TOKEN` | Codex session | Opaque correlation token inherited by all actors and processes |
| `ARS_ACTOR_ID` | Root agent or known subagent | Identifies the agent responsible for the tool call |
| `ARS_ACTOR_TOKEN` | Root agent or known subagent | Opaque actor-level correlation token |
| `ARS_CODEX_SESSION_ID` | Codex session | Links the normalized trace to the vendor session |
| `ARS_TOOL_CALL_ID` | Tool call | Links descendant processes to the initiating action |
| `ARS_ACTION_ID` | Agent Runtime Security action lifecycle | Joins descendants to exact pre/post hook observations and detections |
| `ARS_REQUEST_FINGERPRINT` | Sanitized request | Supports best-effort correlation when a hook omits the tool-call ID |

The registry persists one trace record per hashed Codex session ID under `.agent-runtime-security/state/`. State directories use mode `0700`; state and lock files use mode `0600`. Telemetry records token fingerprints rather than token values. Because `PostToolUse` receives the rewritten command, the adapter strips its injected prefix and applies token redaction before storing or reparsing that event.

## Propagation path

```text
Codex session
  trace_id + trace_token
       |
       +-- root agent
       |     actor_id + actor_token
       |          |
       |          +-- PreToolUse shell call
       |                 tool_call_id
       |                      |
       |                      +-- process
       |                           +-- child process
       |                                +-- grandchild process
       |
       +-- subagent
             same trace_id + trace_token
             distinct actor_id + actor_token when identifiable
```

For an allowed Bash action, `PreToolUse` rewrites the command to the equivalent of:

```sh
export ARS_TRACE_ID=... ARS_TRACE_TOKEN=... ARS_ACTOR_ID=... ARS_ACTOR_TOKEN=... ARS_CODEX_SESSION_ID=... ARS_TOOL_CALL_ID=... ARS_ACTION_ID=... ARS_REQUEST_FINGERPRINT=...; original-command
```

Policy evaluation always runs against the original command before trace injection.

## Subagent behavior

Codex documents that subagent hooks use the parent session ID. That guarantees a common session trace across the agent tree.

`SubagentStart` supplies `agent_id` and `agent_type`, so Agent Runtime Security registers a distinct actor token. Current Codex documentation does not guarantee that a later `PreToolUse` event contains `agent_id`. If it is present, Agent Runtime Security injects the distinct subagent actor identity. If it is absent, Agent Runtime Security safely falls back to the root actor while retaining the correct session trace.

An end-to-end test on `codex-cli 0.153.4` observed the same `agent_id` on `SubagentStart`, `PreToolUse`, and `PostToolUse`. The subagent and its child process received the distinct actor token and the root session trace. This is useful current behavior, but Agent Runtime Security retains the fallback because the field is not part of the documented `PreToolUse` contract.

Resolving that attribution gap requires one of:

1. a stable Codex correlation field connecting tool events to subagents;
2. a vendor adapter with an internal event-stream mapping;
3. a per-subagent launcher or execution wrapper; or
4. correlation from an endpoint process sensor.

## Security properties

The token mechanism provides:

- stable correlation without a remote lookup;
- propagation through normal process inheritance;
- a link from descendants back to a session, actor, and tool call;
- random, non-guessable identifiers; and
- token fingerprints safe for routine telemetry correlation.

It does not provide:

- proof that a process is trustworthy;
- protection against a process reading or replacing its environment;
- propagation across `sudo`, containers, SSH, or services that sanitize the environment;
- complete parent-child edges without process telemetry; or
- protection when the hook is disabled or bypassed.

Codex may surface the rewritten command in its local UI, event stream, or session history. The tokens are therefore non-secret correlation values and must never be accepted as authentication credentials.

Accordingly, no authorization decision should trust possession of an `ARS_*` environment variable by itself.

## Lifecycle and retention gaps

- Session state currently has no automatic expiry.
- `SessionEnd` cleanup is not enabled because traces should remain available for investigation.
- State rotation and retention policy are required before production use.
- State is repository-local and readable by an agent with sufficient workspace access.
- The POSIX file lock currently targets macOS/Linux; Windows needs a different locking backend.
