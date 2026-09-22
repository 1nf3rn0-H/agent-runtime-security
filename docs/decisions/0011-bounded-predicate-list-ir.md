# ADR-0011: Use a bounded predicate-list policy IR

Status: Accepted for prototype
Date: 2026-09-19
Extends: ADR-0010

## Context

The first compiler output could express one tool-name set, one executable set, a few argument tests, and a raw-command regex. It could not represent repeated conditions on one field or predicates over MCP inputs, session context, and agent identity. Lowering richer authoring syntax into those legacy keys would either lose semantics or require special cases in every frontend.

## Options considered

1. Add one JSON key per new field and operator.
2. Introduce a general Boolean expression tree now.
3. Emit a bounded conjunction of typed field/operator/value predicates.

## Decision

Use option 3. The compiler emits a `match.conditions` list and a rule-level `case_sensitive` flag. The hook evaluates non-process predicates against the proposed tool event and all process predicates against the **same** parsed invocation. This preserves conjunction semantics for compound shell commands. The hook continues to read legacy matcher keys for existing hand-written policies.

The authoring compiler imposes limits on source size, rule count, conditions, list values, and literal length. All predicates are evaluated locally before supported tool execution.

## Consequences

- New fields and operators can be added without adding bespoke JSON keys.
- Sigma/KQL/SQL-subset frontends can target the same small matcher contract.
- Repeated predicates are expressible; OR and nested Boolean logic remain out of scope.
- `tool.input.<key>` is dynamic and cannot be statically typed without a tool schema registry; wrong-type comparisons simply do not match.
- Python regex validation does not provide a linear-time guarantee. Production use needs a safer regex strategy or strict input/time limits.
- The shell invocation extractor remains a prototype parser, not an OS security boundary.
