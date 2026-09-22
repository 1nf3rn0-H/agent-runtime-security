# Agent Runtime Security engineering requirements document

Status: Draft for alignment
Owner: Agent Runtime Security engineering
Last updated: September 21, 2026
Companion: [Product requirements document](product-requirements.md)

This is the Engineering Requirements Document (ERD), not an entity-relationship diagram. It converts the product outcomes into testable system requirements and defines the engineering and security methodology used to validate them.

## 1. System objective

For every action exposed at a supported preventive hook, Agent Runtime Security must produce a local, deterministic decision over the exact proposed action and available context before the harness dispatches that action. It must preserve enough correlation to explain a policy match while preventing raw observation streams, secrets, and correlation credentials from becoming product telemetry.

## 2. System boundary and trust model

```text
Untrusted or partially trusted                 Agent Runtime Security trusted computing path

model/server response
        |
agent harness ---- lifecycle event ----> harness adapter
                                             |
                                      normalize + validate
                                             |
                              context/correlation enrichment
                                             |
                              target parser + policy engine
                                             |
                           allow / deny / audit / safe rewrite
                                             |
                         harness dispatches only if permitted
                                             |
                    internal observations -> correlator -> detection
                                                        |
                                                 local detection sink
```

### 2.1 Trusted for the prototype

- The installed Agent Runtime Security adapter and policy compiler source.
- The generated runtime policy after successful validation and atomic activation.
- The harness correctly invoking its documented hook and honoring the response.
- Local files and state protected by the current user account permissions.

### 2.2 Not trusted as security identity

- Model output, prompts, tool input, tool output, MCP responses, and command strings.
- Environment-carried trace or actor values; these are correlation hints.
- Agent-supplied descriptions, user names, working directories, or process identifiers without local verification.
- Arbitrary extensions in vendor payloads.

### 2.3 Out-of-boundary threats

The application layer alone cannot guarantee control when the hook is disabled, skipped, or compromised; when a tool path does not emit a preventive event; when a privileged local actor changes Agent Runtime Security; or when side effects occur outside the evaluated input. These cases must be reported as uncovered and addressed by deployment controls or endpoint defense in depth.

## 3. Reference architecture

| Component | Responsibility | Must not do |
|---|---|---|
| Harness adapter | Validate vendor event, map lifecycle and response contracts | Embed vendor fields directly into policy semantics |
| Action normalizer | Produce canonical tool family, action type, and bounded input metadata | Persist arbitrary raw payloads as detection extensions |
| Context registry | Maintain session, actor, action, and request correlation | Treat bearer-like environment tokens as authenticated identity |
| Target interpreter | Extract semantic process, file, URL, endpoint, or integration targets without execution | Execute, source, expand, or import untrusted input to understand it |
| Policy compiler | Parse readable source, type-check predicates, enforce bounds, emit deterministic IR | Accept unsupported constructs by silently weakening them |
| Policy engine | Evaluate validated IR with documented precedence and missing-value semantics | Make network calls or mutate the proposed action during matching |
| Response adapter | Return harness-correct allow, deny, abstain, or safe rewrite | Convert a deny into an approval prompt unless policy requires it |
| Correlator | Join bounded lifecycle and process observations into evidence | Export the raw observation stream |
| Detection builder | Emit schema-valid, minimized detections and evidence chains | Include raw tokens, prompts, model responses, or arbitrary hook payloads |
| Local state/sink | Store protected state and detections atomically | Become an inline remote-service dependency |

## 4. Functional requirements

Requirements use `MUST`, `SHOULD`, and `MAY` in their normative sense.

### 4.1 Adapter and lifecycle

| ID | Requirement | Verification |
|---|---|---|
| ER-F-001 | Each adapter MUST declare the harness versions, lifecycle events, action types, and response behaviors it supports | Versioned adapter manifest and contract test |
| ER-F-002 | Preventive events MUST be evaluated before dispatch, and the adapter MUST return the harness-specific deny contract without executing the input | Harmless sentinel test in direct and live harness modes |
| ER-F-003 | Non-preventive lifecycle events MUST NOT be represented as retroactive prevention | Response-shape and detection assertions |
| ER-F-004 | Unknown preventive event versions or malformed critical fields MUST follow an explicit failure policy and MUST NOT silently allow | Malformed and forward-version fixtures |
| ER-F-005 | Permission-request correlation MUST distinguish the request from the eventual tool action and avoid duplicate or mismatched decisions | Lifecycle ordering and fingerprint fixtures |
| ER-F-006 | Adapter rewrites MUST be limited to documented, semantics-preserving enrichment such as trace injection | Original-versus-rewritten input assertions |

### 4.2 Normalization and interpretation

| ID | Requirement | Verification |
|---|---|---|
| ER-F-010 | Every evaluated request MUST have a canonical action type, tool family, tool name, and bounded input descriptor | Golden normalization fixtures for every supported tool family |
| ER-F-011 | Target extraction MUST be non-executing and MUST preserve the relationship between an executable and its own arguments | Compound, nested, quoted, and malformed command fixtures |
| ER-F-012 | Process predicates in one conjunction MUST bind to one parsed invocation | Cross-command false-positive regression test |
| ER-F-013 | Missing, null, scalar, and list values MUST have distinct documented semantics | Operator truth-table tests |
| ER-F-014 | Unsupported syntax that affects a protected semantic match MUST produce a safe parse outcome rather than partial silent interpretation | Adversarial parser corpus |
| ER-F-015 | Dynamic tool inputs MUST be bounded and accessed only through explicitly supported direct or typed paths | Oversize, nested, wrong-type, and missing-key fixtures |
| ER-F-016 | Remote threat intelligence MUST be optional and MUST run only after a viable rule's explicit domain/IP regex gate matches | Zero-call non-match tests and process/tool gate fixtures |
| ER-F-017 | Provider responses MUST be bounded, structurally validated, normalized by target type, and bound to the invocation/tool target that produced the lookup | Malformed, oversized, cross-invocation, normalization, and memoization fixtures |
| ER-F-018 | Provider failures MUST follow the configured open/closed behavior, remain visible, and MUST NOT fabricate matches | Missing-key, timeout/error, and failure-mode contract tests |
| ER-F-019 | Threat-driven evidence MUST identify provider results without leaking API keys, complete responses, URL credentials, queries, or fragments | Evidence-field and secret-canary assertions |

### 4.3 Policy compiler and engine

| ID | Requirement | Verification |
|---|---|---|
| ER-F-020 | Human-readable policy MUST compile ahead of enforcement into a versioned vendor-neutral IR | Compiler golden tests and IR schema validation |
| ER-F-021 | The compiler MUST reject unknown fields, invalid field/operator pairs, malformed literals, invalid regex, duplicate IDs, unsupported Boolean constructs, and configured bound violations | Negative compiler corpus with source-line assertions |
| ER-F-022 | Compilation MUST be deterministic and generated policy activation MUST be atomic | Repeated-build hash test and interrupted-write test |
| ER-F-023 | The engine MUST implement precedence as: any matching deny wins; otherwise matching allow; otherwise configured default; audit never changes the decision | Complete precedence matrix |
| ER-F-024 | The engine MUST distinguish absent values from present null values and MUST NOT let absent values satisfy negative comparisons | Truth-table and end-to-end hook tests |
| ER-F-025 | Evaluation MUST be bounded by supported rule, condition, literal, collection, input, evidence, and recursion limits | Boundary tests at limit and limit plus one |
| ER-F-026 | Runtime loading MUST validate IR version and structure before evaluation | Corrupt, stale, and incompatible policy fixtures |
| ER-F-027 | Policy errors on protected paths MUST fail closed by default and return a non-sensitive reason | Failure-injection tests |
| ER-F-028 | Regex behavior MUST have a documented complexity control before production use | Static validation plus pathological-pattern performance test |

### 4.4 Correlation and execution-chain tracking

| ID | Requirement | Verification |
|---|---|---|
| ER-F-030 | A session MUST receive a stable trace ID and opaque trace token; a registered actor MUST receive a stable actor ID and distinct actor token | Session/subagent lifecycle tests |
| ER-F-031 | Each evaluated action MUST receive an exact action ID and tool-call identity where available | Pre/post equality and cross-action inequality tests |
| ER-F-032 | Allowed subprocesses SHOULD inherit correlation context through documented adapter mechanisms | Parent, child, grandchild, background, and detached fixtures |
| ER-F-033 | Denied actions MUST NOT receive executable trace injection because they MUST NOT be dispatched | Deny response inspection and sentinel test |
| ER-F-034 | Stored telemetry MUST contain token fingerprints, never raw trace or actor tokens | Secret-scanning assertions over every local output |
| ER-F-035 | Future endpoint correlation MUST combine trace hints with UID, PID, PPID, process start time, executable identity, and platform lineage where available | Sensor integration conformance suite |
| ER-F-036 | Removal, replacement, or conflict of correlation hints SHOULD generate a local tamper observation and MAY contribute to a detection rule | Controlled environment-clearing and spoofing fixtures |

### 4.5 Detection and response

| ID | Requirement | Verification |
|---|---|---|
| ER-F-040 | Durable product output MUST be emitted only for policy detections, not for every observation | Allowed-action test produces no detection |
| ER-F-041 | Every emitted detection MUST validate against a supported schema version and contain the rule, response, enforcement point, correlations, and relevant evidence | JSON Schema and required-semantic assertions |
| ER-F-042 | Every evidence and relationship reference MUST resolve, and evidence chains MUST be ordered and bounded | Graph-integrity validator |
| ER-F-043 | Deny response and detection creation MUST refer to the same evaluated action and matched rule set | Action/rule identity assertions |
| ER-F-044 | A detection MUST NOT contain raw correlation credentials, prompts, model responses, arbitrary vendor payloads, or known secrets | Prohibited-field and canary-secret scanners |
| ER-F-045 | Failure to export to an optional remote sink MUST NOT change the inline decision | Network-failure injection |
| ER-F-046 | Response actions beyond application-level deny MUST be explicitly enumerated, authorized, idempotent where possible, and tested for reversibility | Response-specific safety review and fixtures |

### 4.6 Installation, configuration, and health

| ID | Requirement | Verification |
|---|---|---|
| ER-F-050 | Installation MUST show what hook files and commands will be trusted before activation | Clean-environment install test and reviewable diff |
| ER-F-051 | Runtime state and detection files MUST use user-restricted permissions and safe file creation | Permission assertions on supported platforms |
| ER-F-052 | The system MUST report effective adapter, policy version/hash, enabled preventive hooks, last successful evaluation, and known unsupported paths | Health/status contract test |
| ER-F-053 | Policy upgrades MUST support preflight validation and rollback to the last known valid bundle | Invalid-upgrade and rollback test |
| ER-F-054 | Policy scope precedence MUST be deterministic and the effective rule origin MUST be explainable | Organization/user/repository/session conflict matrix |

## 5. Non-functional requirements

| ID | Area | Requirement |
|---|---|---|
| ER-N-001 | Performance | On declared reference hardware, engine evaluation at the supported maximum policy size MUST meet p95 ≤ 10 ms; adapter end-to-end overhead MUST be measured separately and SHOULD meet p95 ≤ 50 ms |
| ER-N-002 | Availability | Inline evaluation MUST have no remote runtime dependency; optional sinks and update services MUST be off the decision path |
| ER-N-003 | Determinism | Identical normalized request, context snapshot, and policy MUST produce the same decision and matched rule ordering |
| ER-N-004 | Resource bounds | CPU, memory, file size, recursion, regex, collection, and evidence limits MUST be explicit, tested, and configurable only within safe hard maxima |
| ER-N-005 | Compatibility | Each release MUST publish a harness/OS/runtime compatibility matrix and MUST NOT claim coverage outside tested combinations |
| ER-N-006 | Portability | Common policy semantics and detection schema MUST not contain vendor-specific fields except within namespaced, minimized extensions |
| ER-N-007 | Maintainability | Every supported field/operator combination MUST have compiler, engine, and end-to-end coverage; generated artifacts MUST have stale checks |
| ER-N-008 | Diagnostics | User-facing failures MUST name the failing stage and safe corrective action without including secrets or raw payloads |
| ER-N-009 | Upgrade safety | Format versions MUST follow explicit compatibility rules; unsupported major versions MUST fail validation before activation |
| ER-N-010 | Reproducibility | Release evidence MUST be reproducible from a tagged revision with pinned fixtures and documented host/runtime metadata |

## 6. Security requirements

| ID | Requirement |
|---|---|
| ER-S-001 | Threat modeling MUST cover prompt injection, malicious tool output, policy bypass, parser differentials, command indirection, environment tampering, hook removal, TOCTOU, resource exhaustion, and sensitive-data leakage |
| ER-S-002 | Agent Runtime Security MUST evaluate the exact input the harness will dispatch. A post-decision mutation MUST cause re-evaluation or rejection |
| ER-S-003 | Policy and adapter code MUST never execute untrusted content for parsing, expansion, validation, or testing |
| ER-S-004 | Rule bundles SHOULD be integrity protected for beta and MUST be authenticated for managed production deployment |
| ER-S-005 | Local state MUST resist symlink/path substitution, partial writes, permissive file modes, and cross-user access on supported platforms |
| ER-S-006 | Detection construction MUST apply field allowlists, size bounds, redaction, and secret scanning before persistence or export |
| ER-S-007 | The product MUST distinguish preventive evidence from post-execution evidence and MUST NOT claim that observation reversed a completed side effect |
| ER-S-008 | Bypass discoveries MUST receive a severity, affected coverage statement, regression test, and release/disclosure decision |
| ER-S-009 | Application-layer enforcement claims MUST name uncovered paths and privilege assumptions; endpoint-boundary claims require independent controls |
| ER-S-010 | Safe test fixtures MUST replace real destructive commands, malicious infrastructure, secrets, and valuable files in CI and documentation |

## 7. Data requirements

### 7.1 Data classes

| Class | Examples | Retention/export rule |
|---|---|---|
| Correlation credentials | Trace token, actor token | Memory/environment only as required; never detection output; persist only fingerprints |
| Internal observations | Raw hook event, raw command, tool result | Memory or explicitly enabled bounded diagnostic store; never product export |
| Correlation metadata | Trace ID, action ID, actor ID, timestamps | May appear in detections when needed and non-secret |
| Detection evidence | Sanitized command summary, executable, target, policy match | Bounded by schema and policy; may be stored/exported |
| Configuration and policy | Source rule, generated IR, bundle hash | Local/version-controlled; integrity metadata retained |

### 7.2 Entity relationships

The canonical evidence model is a graph, not a relational storage mandate:

```text
identity -> owns_session -> agent_session
agent_session -> contains -> agent_actor
agent_actor -> initiated -> tool_call
tool_call -> spawned/modified/contacted -> process/file/endpoint/integration
process -> parent_of -> process
detection -> supported_by -> evidence -> references -> entity
detection -> responded_with -> response_action
```

Entity IDs must be stable within a detection and globally unique where the schema promises it. Process identity must use host, PID, and start time rather than PID alone. Evidence-chain steps must reference existing evidence and graph edges.

## 8. Engineering methodology

Agent Runtime Security development follows a control-first, evidence-driven loop.

### Step 1: Inventory the control surface

For each harness release, enumerate lifecycle events, tool families, response shapes, trust/approval behavior, timeout behavior, and known bypass paths. Record whether a hook is preventive, mutating, observational, or advisory. Do not infer support from event names alone.

### Step 2: Threat-model one action class

Define assets, attacker/control assumptions, entry points, parsing ambiguities, direct and indirect execution paths, failure modes, and expected safe behavior. Give each requirement a fixture before implementation.

### Step 3: Normalize before detecting

Map vendor data to a small canonical action taxonomy. Separate supplied values from locally verified enrichment. Add fields only when their semantics, missing-value behavior, privacy class, and adapter availability are documented.

### Step 4: Compile and validate policy ahead of time

Parse authoring language into a typed model, reject unsupported semantics, lower to bounded versioned IR, and activate atomically. Keep rich parsing and dependencies out of the inline path. Preserve source identity for explanation and debugging.

### Step 5: Enforce on the exact pre-execution object

Evaluate the object the harness intends to dispatch, return the native response contract, and verify non-dispatch with a harmless sentinel. Any semantics-changing rewrite creates a new object that must be re-evaluated.

### Step 6: Correlate locally and minimize output

Use lifecycle IDs and locally generated tokens to join internal observations. Build a bounded graph only when a rule matches. Remove credentials and prohibited payloads before schema validation and persistence.

### Step 7: Test by layer and by attack

The required test pyramid is:

1. Parser/compiler unit tests and operator truth tables.
2. Engine precedence, missing-value, bounds, and deterministic replay tests.
3. Adapter contract tests for every lifecycle event and response shape.
4. End-to-end compiler-to-hook tests for every field/operator family.
5. Safe non-dispatch tests using sentinels.
6. Live harness tests on the declared compatibility matrix.
7. Adversarial tests for quoting, nesting, indirection, malformed data, races, resource exhaustion, hook tampering, and secret leakage.
8. Performance tests that separate compile, evaluate, adapter, and harness latency.

### Step 8: Convert every defect into evidence

A fixed escape, false deny, privacy leak, correlation mismatch, or compatibility failure must add a minimized permanent regression fixture. Document whether the defect changes the claimed boundary or supported matrix.

### Step 9: Release against gates

Generate a conformance report from a tagged revision. It includes requirement results, corpus versions, compatibility matrix, latency distributions, known uncovered paths, schema version, policy/IR versions, and unresolved risks. Release stage is determined by evidence, not feature count.

## 9. Verification matrix

| Product outcome | Engineering controls | Primary evidence |
|---|---|---|
| No dispatch after deny | ER-F-002, ER-F-033, ER-S-002 | Sentinel and live harness tests |
| Complete advertised preventive coverage | ER-F-001, ER-F-004, ER-F-052 | Adapter manifest and coverage report |
| Understandable static policy | ER-F-020 through ER-F-028 | Compiler corpus, IR validation, precedence matrix |
| Execution-chain attribution | ER-F-030 through ER-F-036 | Session, subagent, process, and tamper fixtures |
| Detection-only telemetry | ER-F-040 through ER-F-045, ER-S-006 | Allowed-action absence test, schema and leakage scans |
| Low-latency local decision | ER-N-001, ER-N-002, ER-N-004 | Reproducible performance report with remote services disabled |
| Vendor-neutral semantics | ER-N-005, ER-N-006 | Second-adapter common conformance suite |
| Honest security boundary | ER-S-007, ER-S-009 | Coverage diagnostics and release threat model |

## 10. Current implementation assessment

| Area | Current state | Gap to alpha/beta |
|---|---|---|
| Codex pre-execution blocking | Implemented and safely smoke-tested | Versioned adapter manifest and broader live compatibility corpus |
| Rule compiler | Bounded ARSQuery predicates with 14 operators, runtime IR schema/version validation, atomic activation, canonical hashing, and LKG recovery | Complexity-safe regex strategy, authenticated bundles, richer Boolean model if justified |
| Correlation | Session, actor, tool-call, action, request, and ordinary descendant propagation | Trusted process sensor, tamper detections, platform coverage |
| Detection model | Schema v1.2 detection with typed target entities and evidence chains | Target canonicalization, secret scanning, and correlation-window implementation |
| Threat intelligence | Optional policy-gated VirusTotal domain/IP lookup, bounded responses, per-event memoization, configurable thresholds and open/closed failure behavior | Quota governance, provider abstraction, latency SLO, privacy review, and numeric-count policy fields |
| Telemetry boundary | Detection-only product contract; diagnostic raw-event file remains in prototype | Disable raw diagnostics by default and enforce retention/size bounds |
| Test evidence | 112 automated tests, isolated smoke test, and bounded 1,000-rule plus matcher benchmarks | Structured conformance report, broader adversarial corpora, adapter/provider latency distributions, live matrix |
| Deployment | Reversible project/user Codex installer, backups, health/status commands, and explicit project-hook trust review | Packaged signed adapter, managed deployment, compatibility matrix, and release rollback |
| Shell interpretation | Bounded non-executing subset AST with nested substitution, redirection, wrapper, dynamic-value, known indirect-dispatch, typed-target, provenance, and malformed-input tests | Mature grammar, differential corpus, additional dispatchers and embedded interpreters, and cross-shell compatibility before production claim |

## 11. Milestones and exit criteria

### M1 — Codex alpha

- All P0 product requirements and corresponding `ER-F`, `ER-N`, and `ER-S` requirements applicable to alpha pass.
- Codex adapter manifest and compatibility matrix are published.
- Detection leakage scan and evidence graph validation pass for the complete corpus.
- Engine latency meets its budget; adapter overhead has a published baseline.
- Raw diagnostic observation storage is off by default or clearly isolated with bounded retention.

### M2 — Multi-harness beta

- Two harness adapters pass the same semantic conformance suite.
- Shell AST, policy layering, health/tamper reporting, policy rollback, and authenticated bundles are implemented.
- Adversarial corpus shows zero known escapes on advertised preventive paths.
- False-deny target is met on the reviewed benign corpus.

### M3 — Production candidate

- Independent threat-model and code review are complete.
- Release artifacts and managed policies are authenticated.
- Platform-specific failure, update, rollback, incident, and vulnerability-disclosure procedures are exercised.
- Any endpoint-level security claim is backed by an independent sensor or enforcement control, not environment propagation alone.

## 12. Open decisions

- Select a production-safe regex strategy: restricted syntax, linear-time engine, timeout isolation, or removal from inline rules.
- Choose the shell AST implementation and define cross-shell compatibility.
- Define organization/user/repository/session policy precedence and exception authorization.
- Decide which failure classes deny, abstain to native approval, or permit with a health alert.
- Define bounded observation retention needed for multi-event correlation without creating a raw-event lake.
- Choose the trusted process sensor and identity primitives for macOS, Linux, and Windows.
- Define the packaging boundary: plugin, user service, managed hook, endpoint agent, or a layered combination.

## 13. Related decisions and specifications

- [ADR-0001: Codex pre-tool enforcement](decisions/0001-codex-pretooluse-enforcement.md)
- [ADR-0006: Detection-only events](decisions/0006-emit-detections-not-raw-observations.md)
- [ADR-0010: Human-readable policy compilation](decisions/0010-compile-human-readable-policies-to-ir.md)
- [ADR-0011: Bounded predicate-list IR](decisions/0011-bounded-predicate-list-ir.md)
- [Detection event schema](detection-event-schema.md)
- [Policy compiler](policy-compiler.md)
- [Trace propagation](trace-propagation.md)
- [Tool response contract](tool-response.md)
