# ADR-0001: Use Codex PreToolUse for initial inline enforcement

Status: Accepted
Date: August 18, 2026

## Context

Agent Runtime Security must prevent a disallowed action before it reaches the shell or another underlying tool. Exported telemetry is generally observed after an event is emitted and cannot guarantee a synchronous decision before execution.

Codex exposes a synchronous `PreToolUse` hook for supported local tool paths. The hook receives structured tool input and can deny or rewrite the proposed call.

## Options considered

1. Detect from exported telemetry and issue a response afterward.
2. Wrap selected shell binaries.
3. Use Codex `PreToolUse` as the initial inline interception point.
4. Begin with an operating-system endpoint sensor.

## Decision

Use `PreToolUse` as the first Codex enforcement adapter. Keep its input and output translation separate from the vendor-neutral policy model so other harnesses can be added later.

## Consequences

- Supported calls can be denied before execution with rich agent context.
- The implementation is vendor-specific at the adapter boundary.
- Hosted and specialized tool paths may not be covered.
- Users can disable non-managed hooks, so this is not a complete security boundary.
- OS-level enforcement remains necessary for stronger guarantees.

