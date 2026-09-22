# ADR-0017: Use policy-gated remote threat intelligence

Status: Accepted
Date: September 22, 2026
Supersedes: [ADR-0016](0016-local-offline-threat-intelligence.md)

## Context

Agent Runtime Security previously loaded a complete local indicator snapshot on every hook invocation. The product direction now treats reputation as an optional add-on and requires a current provider lookup only for domains/IPs deliberately selected by policy.

Unconditional remote enrichment would disclose every destination, consume quota, add latency to benign actions, and make unrelated rules dependent on a third party. A policy condition must therefore identify the subset that justifies enrichment before the request occurs.

## Decision

Use a two-phase evaluation model:

1. Extract normalized domain/IP targets without DNS resolution.
2. Evaluate all non-threat predicates and an explicit list-regex gate.
3. Query VirusTotal only for targets selected by a viable rule.
4. Convert bounded analysis statistics to `malicious`, `suspicious`, `benign`, or `unknown`.
5. Resume ordinary deterministic rule evaluation with the enrichment bound to its originating invocation or tool call.

Process rules using `threat.*` must contain exactly one `network.destinations ANY_MATCHES` gate. Tool rules using `tool.threat.*` must contain exactly one `tool.network.destinations ANY_MATCHES` gate. Policies violating this invariant are rejected.

The API key is referenced only by environment-variable name. The VirusTotal HTTPS origin is fixed in code. Responses are bounded and schema-checked, duplicate targets are memoized only within one event, and no feed or response cache is persisted.

Provider failures obey `failure_mode`: `open` produces no reputation match and records a warning; `closed` fails the preventive action closed. The checked-in optional configuration is disabled and defaults to `open` when enabled.

## Consequences

- Non-matching actions incur no provider request.
- Reputation is current at lookup time and requires no feed distribution mechanism.
- Enabling the add-on adds third-party latency, availability, privacy, quota, and licensing dependencies to selected pre-execution decisions.
- Decisions are not fully reproducible later unless the bounded detection evidence is sufficient, because provider state may change and raw responses are not retained.
- No cross-event cache means repeated targets consume repeated quota; adding a cache later requires an explicit retention and staleness decision.
- Runtime policy IR `1.4.0` adds `ANY_MATCHES`, `tool.network.destinations`, and remote-provider settings.
