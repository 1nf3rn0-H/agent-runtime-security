# ADR-0003: Use dependency-free JSON rules for the prototype

Status: Accepted  
Date: August 18, 2026

## Context

The first prototype needs deterministic rules, a small installation footprint, and enough expressiveness to prove semantic blocking of a program and target combination.

## Options considered

1. Purpose-built JSON rules evaluated with the Python standard library.
2. YAML rules with an external parser.
3. CEL expressions.
4. Rego through Open Policy Agent.
5. A Sigma-like detection language and compiler.

## Decision

Use purpose-built JSON rules during the proof-of-concept stage. Limit the language deliberately and validate behavior through tests.

## Consequences

- The prototype has no runtime package dependency.
- Rules are deterministic and easily replayed.
- Complex conditions, reusable values, and policy composition are limited.
- The schema is experimental and should not be treated as a stable public API.
- CEL and a detection-engineer-friendly authoring format must be evaluated before production.

