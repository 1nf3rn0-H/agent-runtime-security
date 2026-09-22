# Agent Runtime Security detection event schema

Status: Accepted for prototype
Schema version: `1.2.0`
Last updated: September 11, 2026

## Boundary

Agent Runtime Security collects hook, tool, process, filesystem, and network observations only as internal correlation inputs. Those observations may be held in memory or in a bounded local diagnostic buffer, but they are not the product's outbound event stream.

Agent Runtime Security emits a durable event only when a detection rule matches. Each emitted event is self-contained and includes the minimum evidence needed to understand the detection and response. Agent Runtime Security does not require a data lake or SIEM.

The normative JSON Schema is [`schemas/agent-runtime-security-detection-event.schema.json`](../schemas/agent-runtime-security-detection-event.schema.json).

## Event model

| Object | Purpose |
|---|---|
| `detection` | Rule identity, category, severity, confidence, and analyst-facing description |
| `observed_window` | Time range and count of internal observations summarized by the detection |
| `correlation` | Correlation ID, one or more trace IDs, contributing agent sessions, and initiating entity |
| `entities` | Deduplicated agents, tool calls, processes, files, endpoints, identities, or other objects involved |
| `relationships` | Directed edges explaining causal or contextual links between entities |
| `evidence` | A bounded set of sanitized observations supporting the rule match |
| `evidence_chains` | Ordered causal, temporal, delegation, or data-flow paths referencing evidence and entities |
| `response` | What Agent Runtime Security did, where enforcement occurred, and why |
| `data_handling` | Explicit disclosure of command handling and secret scanning |
| `extensions` | Namespaced, non-sensitive vendor fields; never a raw vendor payload |

The `entities` and `relationships` arrays form a compact evidence graph. For example:

```text
agent --initiated--> tool_call --spawned--> shell process
                                              |
                                           parent_of
                                              |
                                              v
                                         curl process --connected_to--> endpoint
```

This graph lets a single detection explain behavior correlated across multiple tools and descendant processes without shipping every underlying event.

For pre-execution denials, recognized semantic targets are emitted as bounded `network_endpoint`, `file`, `repository`, or `other` entities. The proposed tool call uses a `targeted` relationship to those entities. This records intent visible in the proposed action; it does not claim that a connection, write, installation, or Git operation completed.

Threat-driven detections add only bounded provider-result IDs, verdicts, labels, sources, matched targets, and detection-ratio values. Provider availability, lookup count, latency, and failure mode appear in the namespaced `com.agent_runtime_security.threat_intelligence` extension. API keys, complete provider responses, URL credentials, query strings, and fragments are prohibited from detection output.

For detections involving more than one hop, `evidence_chains` provides the ordered explanation that the graph alone does not convey. Every step references an `evidence_id` and expresses one entity-to-entity relationship. Step sequence numbers start at `1`, are contiguous, and must follow the observed causal or temporal order. Atomic detections may omit `evidence_chains`.

## Identity and correlation rules

- `event_id` uniquely identifies one immutable detection event.
- `correlation.correlation_id` identifies the logical detection case. A later update is a new event with its own `event_id` and the same `correlation_id`.
- `correlation.trace_ids` lists every Agent Runtime Security execution trace that contributed evidence. It supports rules spanning sessions or process chains.
- `correlation.action_ids` identifies exact tool-call lifecycles when the harness supplies a tool-use identifier.
- `correlation.request_fingerprints` links semantically identical request and approval observations when an event lacks the exact tool-use identifier.
- `correlation.sessions` identifies contributing harness sessions without making the schema vendor-specific.
- Entity IDs are stable within the detection. Process IDs should combine host identity, PID, and process start time; a PID alone is insufficient because operating systems reuse it.
- `parent_detection_id` links a derived or follow-up detection to the event that caused it to be evaluated.
- Every relationship endpoint and evidence entity reference must resolve to an entry in `entities`.
- Every evidence-chain step must reference an existing evidence record and an edge present in `relationships`.

## Detection lifecycle

Detection events are immutable facts, not mutable database rows. If correlation adds evidence or a response changes, emit another event with:

- a new `event_id`;
- the same `correlation_id`;
- an updated observation window and evidence graph; and
- `parent_detection_id` pointing to the prior event when there is a direct derivation.

Consumers can retain only the latest event per correlation ID if they need a current view.

## Evidence minimization

- Include evidence only when it materially supports the rule result.
- Summaries must be safe to display and must not contain raw trace or actor tokens.
- Commands are optional evidence attributes and must follow `data_handling.command_content`.
- Secrets must be removed before event construction. `findings_redacted` means secret-like content was found and replaced.
- Arbitrary original hook payloads, model prompts, model responses, and command output are prohibited in `extensions`.
- Evidence and graph sizes are bounded by the schema to prevent a detection event from becoming a disguised raw-event archive.

## Internal observations versus detection events

| Property | Internal observation | Detection event |
|---|---|---|
| Purpose | Correlation and rule evaluation | Durable explanation and response record |
| Emission rate | Potentially every supported action | Only rule matches |
| Retention | Memory or bounded diagnostic buffer | Product retention policy |
| Stability | Adapter-internal | Versioned public contract |
| Sensitive payload | May exist briefly for evaluation | Minimized and explicitly classified |
| Export | Never | Only through an explicitly configured detection sink |

The current `.agent-runtime-security/events.jsonl` file predates this boundary and records all hook observations for prototype debugging. It is not conformant with this detection schema and must not be treated as the future output interface. Runtime rule denials are emitted separately to `.agent-runtime-security/detections.jsonl` using this schema.

## Examples

- [Blocked command before execution](../examples/detection-blocked-network-command.json)
- [Detection correlated across a tool and process chain](../examples/detection-correlated-process-chain.json)

## Versioning

The schema uses semantic versioning:

- Patch: clarifications or constraints that do not invalidate conformant events.
- Minor: optional fields or enum values that existing consumers may ignore.
- Major: removed or renamed fields, changed meanings, or newly required fields.

Producers must emit exactly one supported `schema_version`. Consumers must reject unsupported major versions and ignore unknown compatible extensions.
