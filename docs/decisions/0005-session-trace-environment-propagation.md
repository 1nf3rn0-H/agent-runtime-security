# ADR-0005: Propagate session traces through the process environment

Status: Accepted for prototype
Date: September 10, 2026

## Context

Agent Runtime Security needs to correlate a Codex session and its subagents with subprocesses created by agent-initiated shell commands. Codex supplies lifecycle and tool-call identifiers, but a new operating-system process does not automatically carry those identifiers.

## Options considered

1. Correlate only by PID and parent PID after execution.
2. Launch Codex with a session environment and rely on harness inheritance.
3. Rewrite each allowed shell command through `PreToolUse` to export trace context.
4. Interpose a shell or `execve` wrapper.
5. Begin with a platform endpoint sensor.

## Decision

For the prototype, maintain a local session registry and use synchronous `PreToolUse` rewriting to export an opaque session trace, an actor trace when identifiable, and the current tool-call ID before the original command runs.

Treat all injected values as correlation hints, not authenticated identity. Store only fingerprints in routine telemetry.

## Consequences

- Ordinary child and descendant processes inherit trace context without application changes.
- Every rewritten command changes the literal shell input, although the original command remains semantically intact for supported POSIX shells.
- A process can clear, copy, or forge environment values.
- Environment-sanitizing boundaries break propagation.
- Tokens may appear in local process arguments while the shell evaluates the rewritten command.
- The rewritten command may appear in Codex event output or history; correlation tokens are therefore explicitly non-secret.
- `PostToolUse` telemetry must strip the injected prefix and redact token values before persistence.
- Subagent-level attribution depends on the vendor supplying an actor identifier on the tool event; session-level correlation does not.
- `codex-cli 0.153.4` supplied that identifier in an end-to-end test, but the adapter must preserve its root-actor fallback because the field is not a documented guarantee.
- Production enforcement still requires process ancestry and OS-level controls.
