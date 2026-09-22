# ADR-0004: Fail closed on policy loading and parsing errors

Status: Accepted
Date: August 18, 2026

## Context

If the inline hook cannot load its rules or safely interpret a proposed shell command, allowing execution would turn a policy failure into an enforcement bypass.

## Options considered

1. Fail open and record an error.
2. Fail closed and deny the action.
3. Ask the user whenever evaluation fails.
4. Select behavior per policy or action class.

## Decision

The prototype fails closed for policy-loading and command-parsing failures.

## Consequences

- Evaluation failures do not silently become execution permission.
- Configuration errors can prevent legitimate work.
- Error messages and local diagnostics must be clear.
- Production behavior may need action-specific controls, cached last-known-good policy, and a carefully governed break-glass mechanism.

