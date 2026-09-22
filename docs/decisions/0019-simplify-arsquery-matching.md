# ADR-0019: Simplify ARSQuery matching while preserving the runtime IR

Status: Accepted
Date: September 22, 2026

## Context

ARSQuery/1 exposed runtime details to rule authors. Exact matching used different operators for scalar and list fields (`==`, `IN`, and `HAS_ANY`), while regex used `MATCHES` or `ANY_MATCHES`. Case selection used the implementation-shaped `CASE_SENSITIVE true` statement. Authors therefore had to know field storage types before expressing a basic detection.

Regex is necessary for real patterns, but it is not a general performance optimization. Exact equality and literal substring search are cheaper, easier to validate, and less vulnerable to pathological expressions.

## Decision

ARSQuery/2 provides three common matching operations:

- `IS` for an exact value or any value in a supplied list;
- `CONTAINS` for a literal substring; and
- `MATCHES` for an explicit regular expression.

The compiler infers scalar/list behavior and lowers these forms to the existing bounded runtime IR. `CASE SENSITIVE` and `CASE INSENSITIVE` replace the boolean-shaped source syntax, with insensitive matching remaining the default. `THEN DENY "reason"` combines the deny action and required user-facing message.

Existing ARSQuery/1 operators and statements remain accepted as an advanced compatibility surface. Regex is validated at compile time and compiled once per predicate evaluation rather than once per candidate list value.

## Consequences

- Most policies no longer expose scalar/list implementation details.
- The runtime policy version remains `1.4.0`; adapters need no semantic migration.
- Exact and scalar literal matching remain available without regex overhead; list `CONTAINS` lowers to an escaped regex to preserve literal semantics.
- Advanced negative, all-values, prefix, suffix, and existence predicates remain available but are no longer the primary authoring path.
- Agent Runtime Security still uses Python regex semantics and existing input bounds; a production-safe regex complexity strategy remains required.
