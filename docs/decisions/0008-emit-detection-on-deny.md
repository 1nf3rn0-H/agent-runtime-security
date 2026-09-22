# ADR-0008: Emit a detection event for each denying rule

Status: Accepted for prototype
Date: 2026-09-18

## Context

Agent Runtime Security has a versioned detection-event schema, but the runtime previously wrote only internal hook observations. The product boundary requires durable output only when policy detects activity, without copying complete tool inputs or trace tokens.

Multiple denying rules may independently explain the same proposed action. A detection event has one primary rule identity.

## Options considered

1. Continue producing schema fixtures without runtime emission.
2. Produce one combined event containing every matching rule. This weakens rule-specific lifecycle and severity semantics.
3. Emit one immutable detection per denying rule, correlated through the same trace and input fingerprint.

## Decision

After a successful pre-execution deny decision, emit one versioned detection event for each denying rule. Store detections separately from internal diagnostic observations. The current schema version is documented in the canonical detection-schema document.

The initial event includes a minimal evidence chain from the responsible agent to the denied tool call. It stores an input digest and argument names, not the complete command, patch, or function arguments. Process and network sensors may extend later detections with descendant evidence chains.

Allowed and audit-only actions do not produce detection events.

## Consequences

- The detection schema is now exercised by the runtime rather than examples alone.
- The product stream remains low-volume and detection-only.
- Multiple matching deny rules can produce multiple correlated events.
- The local detection file is still prototype storage and needs rotation and delivery guarantees.
- Detection construction failure currently fails the protected action closed because it occurs in the synchronous hook path; this durability coupling must be revisited before production.
