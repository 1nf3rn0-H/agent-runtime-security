# ADR-0007: Use a uniform response contract for supported tools

Status: Accepted for prototype
Date: 2026-09-12

## Context

The first Agent Runtime Security prototype intercepted only Bash commands. Agent activity also occurs through file-edit tools, MCP servers, delegation tools, and other local functions. Maintaining a separate policy engine for every tool would produce inconsistent decisions and incomplete correlation.

Codex can route supported local function tools through `PreToolUse` and `PostToolUse`, with a wildcard matcher covering every supported occurrence. Tool input shapes and safe rewrite behavior remain tool-specific.

## Options considered

1. Continue protecting Bash only. This leaves important file, integration, and delegation actions outside application-level policy.
2. Build independent rule and response engines for each tool. This provides specialization but fragments semantics and evidence.
3. Normalize every supported tool into a common action and use one allow/deny contract, retaining adapters for tool-specific parsing and rewriting.

## Decision

Configure Codex tool and permission hooks with `matcher: "*"`. Normalize each supported tool call into an action family and action type, then apply the same deterministic local policy evaluation. A deny emits the event-specific blocking response. An unchanged allow emits no hook override so Codex retains its normal permission and approval flow.

Only Bash is rewritten today, solely to inject trace context; this documented rewrite path requires `permissionDecision: "allow"` with `updatedInput`. Non-shell calls continue unchanged. Tool-specific rewrites require dedicated adapters and contract tests.

## Consequences

- File edits, MCP calls, agent delegation calls, and other supported local tools now reach the Agent Runtime Security decision path.
- Generic input metadata can be correlated without persisting complete tool arguments.
- Policies can deny a non-shell tool by canonical `tool_name` even before richer semantic matchers are introduced.
- Permission escalation is evaluated again, and Agent Runtime Security never silently approves it.
- Hosted and specialized opt-out tool paths remain uncovered.
- `PostToolUse` response is detective because it cannot undo completed side effects.
- A future adapter registry should replace the initial name-based classifier as tool semantics mature.
