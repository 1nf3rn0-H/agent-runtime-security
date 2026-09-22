# ADR-0016: Use validated local threat-intelligence snapshots inline

Status: Superseded by [ADR-0017](0017-policy-gated-remote-threat-intelligence.md)

Status: Accepted for prototype
Date: 2026-09-22
Extends: ADR-0002, ADR-0012, ADR-0015

## Context

Threat-intelligence decisions must occur before a proposed action reaches a shell or integration. A live HTTP lookup would add availability, latency, privacy, and time-of-check dependencies to the enforcement path. Matching raw command text would also lose the invocation binding established by semantic target extraction.

## Options considered

1. Query a remote reputation service synchronously for each proposed action.
2. Perform reputation lookups asynchronously and respond only after execution.
3. Match typed targets against a complete, validated local snapshot on the synchronous path.

## Decision

Use option 3. Load a bounded local snapshot, validate its structure and freshness, normalize its indicators, and build exact-match indexes. Enrich process targets on their originating invocation and normalized tool targets on their tool call. Expose indicator IDs, verdicts, labels, sources, and matched targets as list fields in runtime policy IR `1.3.0`.

The configured `required` flag controls availability behavior. Required snapshot failures deny preventive events. Optional failures produce no matches and remain visible in local diagnostics. Remote feed acquisition is never performed by the policy evaluator.

Threat-driven detections include bounded match evidence and the exact feed SHA-256. Confidence values are evidence only until ARSQuery gains numeric comparison semantics.

## Consequences

- Reputation can block a proposed process or MCP target before dispatch without remote inline latency.
- Process predicates and threat predicates cannot accidentally join across different commands in one shell expression.
- Feed freshness and exact artifact provenance are explicit.
- Local compromise can replace both policy and feed; signed distribution remains necessary for managed deployment.
- Per-hook snapshot parsing is acceptable for the prototype but should move to an authenticated local service or compiled immutable index.
- Exact matching deliberately omits suffix, CIDR, and fuzzy semantics until their false-positive and canonicalization behavior is specified.
