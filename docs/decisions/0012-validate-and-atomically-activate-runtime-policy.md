# ADR-0012: Validate and atomically activate runtime policy

Status: Accepted for prototype  
Date: 2026-09-21  
Extends: ADR-0010 and ADR-0011

## Context

The compiler generated deterministic JSON and wrote it atomically, but the hook accepted the loaded object without validating a formal runtime contract. Truncated, manually modified, forward-versioned, or semantically inconsistent policy could therefore fail deep in evaluation. There was no stable bundle identity or recoverable last-known-good policy.

## Options considered

1. Trust compiler output and validate only while compiling.
2. Add a JSON Schema and require a third-party validator inside every hook process.
3. Define a JSON Schema for interoperability and implement the same security-critical constraints in a dependency-free loader shared by compiler and hook.

## Decision

Use option 3. Runtime policies declare `policy_ir_version: "1.0.0"`. The compiler validates the lowered object before activation. Activation writes a mode-`0600` temporary file in the destination directory, flushes it, and atomically replaces the active path.

The hook reads a bounded snapshot, rejects duplicate JSON keys, validates structure and semantics, computes a canonical SHA-256, and evaluates only the validated in-memory object. A successfully loaded active policy refreshes a `.lkg` snapshot. An invalid active file falls back to the validated LKG; if neither is valid, preventive hooks fail closed.

Policy version, canonical hash, source language, source path, and fallback status are attached to local decision telemetry. Deny detections include the version, hash, source, and fallback status but omit local parser warnings.

## Consequences

- Malformed and incompatible policy fails before rule evaluation.
- Compiler and hook use one semantic validator and one set of bounds.
- Atomic replacement prevents partially written active policy.
- LKG recovery improves availability without weakening the current no-valid-policy fail-closed behavior.
- Policy hashes make decisions and detections attributable to an exact bundle.
- Each hook invocation performs local parsing and validation; this cost is explicitly benchmarked.
- JSON Schema consumers can inspect the portable contract without becoming an inline dependency.
- Neither schema validation nor SHA-256 authenticates who authorized a valid policy. Signed bundles and managed ownership remain future controls.

