# ADR-0006: Emit detections instead of raw observations

Status: Accepted
Date: 2026-09-11

## Context

Agent Runtime Security receives high-volume, vendor-specific hook and process observations to correlate activity and evaluate policy. Sending every observation to a data lake or SIEM would increase storage, privacy, integration, and operating costs without being necessary for the local enforcement product.

The durable record must still explain detections spanning agents, tools, and descendant process chains.

## Options considered

1. Export every raw observation to an external analytics platform. This maximizes retrospective query flexibility but violates the desired deployment and data-minimization model.
2. Persist all normalized observations locally as the public interface. This avoids external infrastructure but creates an unbounded sensitive local log.
3. Correlate locally and emit only self-contained detection events with bounded evidence graphs.

## Decision

Agent Runtime Security will use raw observations only as internal, short-lived correlation inputs. The only durable or outbound product event is a versioned detection event produced after a rule matches.

Each detection contains a bounded graph of entities and relationships plus sanitized supporting evidence. It can represent multiple agent sessions, tool calls, and process chains without embedding the complete underlying event stream.

Enforcement remains synchronous and local. Detection delivery is downstream of the decision and cannot change an already-issued allow or deny result.

## Consequences

- Agent Runtime Security does not require a data lake or SIEM.
- Detection volume and sensitive-data exposure are substantially lower than raw telemetry export.
- Each rule must declare what minimum evidence is needed for an explainable detection.
- Retrospective hunts over benign raw activity are unavailable unless a separately enabled, bounded diagnostic buffer retained it.
- Correlation state, expiry, deduplication, and event delivery durability become local product responsibilities.
- The prototype `.agent-runtime-security/events.jsonl` observation log is temporary diagnostic infrastructure, not the stable output contract.
