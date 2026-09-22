# ADR-0010: Compile human-readable policies to a vendor-neutral IR

Status: Accepted for prototype
Date: 2026-09-18
Supersedes: ADR-0003 as the authoring direction

## Context

The prototype JSON rules are deterministic but cumbersome to author and couple detection intent to the runtime representation. Detection engineers are more familiar with declarative formats such as Sigma and query languages such as KQL or SQL.

Parsing a rich authoring language inside the synchronous hook would add latency, dependencies, and additional failure modes to the enforcement path.

## Options considered

1. Continue authoring runtime JSON directly.
2. Interpret Sigma, SQL, or KQL directly inside each harness hook.
3. Compile a readable, vendor-neutral source language ahead of time into a small validated runtime IR.

## Decision

Introduce a compiler boundary. The first frontend is dependency-free `arsquery/1`, a line-oriented SQL/KQL-style language. It parses into a typed source model, validates field/operator compatibility, and lowers to the existing deterministic JSON runtime IR.

The generated JSON is consumed by all harness adapters and is not an authoring interface. Runtime configuration remains separate from detection source. Future Sigma-YAML and query-language frontends must target the same typed model or a compatible successor.

## Consequences

- Rule authors work with readable semantic fields rather than hook-specific JSON.
- The inline hook retains a dependency-free, precompiled policy.
- Compiler errors occur before deployment and include source locations.
- Generated policy drift can be detected with `--check` in CI.
- The initial language supports conjunctions only; richer Boolean logic requires evolving the IR.
- ADR-0003 remains historically accurate for the initial prototype but no longer describes the authoring direction.
