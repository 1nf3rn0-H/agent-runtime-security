# ADR-0002: Separate synchronous enforcement from telemetry export

Status: Accepted  
Date: August 18, 2026

## Context

AiDR needs both low-latency blocking and rich telemetry. A remote collector introduces network latency, availability dependencies, and backpressure. Making it authoritative for each tool call would increase the chance of missed deadlines or widespread denial of service.

## Options considered

1. Send every event to a remote service and wait for its decision.
2. Evaluate locally and export the result asynchronously.
3. Record only local telemetry with no future export path.

## Decision

Evaluate policies locally on the synchronous path. Record local decision evidence and export telemetry asynchronously when remote aggregation is enabled.

## Consequences

- Remote outages do not prevent local evaluation.
- Policy distribution and versioning must be designed separately.
- Local event buffering, retention, and redaction become product responsibilities.
- Remote analytics may observe an event after the local action was allowed or denied.

