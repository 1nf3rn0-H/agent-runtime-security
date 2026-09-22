# Architecture decision log

| ADR | Status | Decision |
|---|---|---|
| [0001](0001-codex-pretooluse-enforcement.md) | Accepted | Use Codex `PreToolUse` for initial inline enforcement |
| [0002](0002-separate-enforcement-and-telemetry.md) | Accepted | Separate synchronous enforcement from telemetry export |
| [0003](0003-prototype-rule-engine.md) | Accepted | Use dependency-free JSON rules for the prototype |
| [0004](0004-fail-closed-policy-errors.md) | Accepted | Fail closed on policy loading and parsing errors |
| [0005](0005-session-trace-environment-propagation.md) | Prototype | Propagate session traces through the process environment |
| [0006](0006-emit-detections-not-raw-observations.md) | Accepted | Correlate locally and emit only detection events |
| [0007](0007-uniform-response-for-supported-tools.md) | Prototype | Use one response contract across supported local tools |
| [0008](0008-emit-detection-on-deny.md) | Prototype | Emit one detection event for each denying rule |
| [0009](0009-tool-lifecycle-correlation-identifiers.md) | Prototype | Separate observation, exact action, and request identifiers |
| [0010](0010-compile-human-readable-policies-to-ir.md) | Prototype | Compile human-readable policies to a vendor-neutral IR |
| [0011](0011-bounded-predicate-list-ir.md) | Prototype | Use a bounded predicate-list IR for expanded fields and operators |
| [0012](0012-validate-and-atomically-activate-runtime-policy.md) | Prototype | Validate, identify, and atomically activate runtime policy with LKG recovery |
| [0013](0013-bounded-non-executing-shell-parser.md) | Prototype | Replace flat command splitting with a bounded non-executing subset parser |
| [0014](0014-model-known-indirect-process-dispatch.md) | Prototype | Extract known indirect child commands and preserve dispatch provenance |
| [0015](0015-extract-typed-semantic-targets.md) | Prototype | Extract bounded typed targets for policy and detection evidence |
| [0016](0016-local-offline-threat-intelligence.md) | Superseded | Match semantic targets against validated local threat-intelligence snapshots |
| [0017](0017-policy-gated-remote-threat-intelligence.md) | Accepted | Query VirusTotal only for domain/IP targets selected by policy regex gates |
| [0018](0018-local-cli-and-reversible-codex-installation.md) | Accepted | Provide a local control plane and reversible Codex hook installation |
| [0019](0019-simplify-arsquery-matching.md) | Accepted | Simplify exact, literal, regex, case, and deny authoring while preserving the runtime IR |
| [0020](0020-rename-product-to-agent-runtime-security.md) | Accepted | Rename the product and its public technical namespaces to agent-runtime-security |

New records should use [the ADR template](template.md).
