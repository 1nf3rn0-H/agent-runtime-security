# ADR-0009: Separate observation, action, and request identifiers

Status: Accepted for prototype  
Date: 2026-09-18

## Context

AiDR receives multiple hook observations for one tool lifecycle. Pre- and post-tool events expose the same Codex `tool_use_id`, while permission-request events do not document that field. A single identifier cannot honestly represent both exact and inferred correlation.

Rewritten Bash commands also contain injected trace values, which must not change the identity of the underlying request.

## Options considered

1. Use the session trace for all correlation. This collapses unrelated actions.
2. Use the tool-input hash for all correlation. This collides for repeated identical requests and changes after trace injection.
3. Maintain separate identifiers for observations, exact action lifecycles, and best-effort request matching.

## Decision

Every internal observation receives a unique `observation_id`.

When `tool_use_id` is present, AiDR derives `action_id` from the trace and tool-use identifier, producing an exact pre/post lifecycle join. Otherwise it derives the action identifier from the request fingerprint and labels the correlation `best_effort`.

The `request_fingerprint` is derived from trace, turn, actor, canonical tool name, and sanitized input digest. Hook-only approval descriptions and injected trace prefixes are excluded.

Detection schema v1.2 adds `correlation.action_ids` and `correlation.request_fingerprints`.

## Consequences

- Pre- and post-tool observations join exactly without storing raw arguments.
- Permission requests can be associated with the likely original request without overstating certainty.
- Identical requests in the same turn can share a request fingerprint; consumers must use the correlation-strength field internally and prefer exact action IDs.
- Allowed shell processes inherit `AIDR_ACTION_ID` and `AIDR_REQUEST_FINGERPRINT`, so process sensors can join observations without translating the vendor tool-call ID.
