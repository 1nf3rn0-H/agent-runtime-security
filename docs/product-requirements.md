# AiDR product requirements document

Status: Draft for alignment  
Owner: AiDR project  
Last updated: September 21, 2026  
Target: Codex alpha, followed by a second agent-harness adapter

## 1. Product definition

AiDR is a local runtime security layer for AI coding agents. It evaluates proposed agent actions before execution, attaches user and execution-chain context, applies understandable static policies, prevents disallowed actions on supported paths, and emits a minimized detection with the evidence needed to explain each response.

AiDR is not a SIEM, a data lake, or a classifier of model intent. Its first responsibility is deterministic control of observable actions at the agent/tool boundary. Operating-system controls may later provide defense in depth for actions that bypass that boundary.

## 2. Problem

AI coding agents can invoke shells, edit files, contact integrations, delegate to subagents, and create descendant processes. Existing telemetry usually arrives after an action and therefore cannot prevent it. Native approval systems are useful but are vendor-specific, may cover only privileged actions, and generally lack a portable detection language or a correlated evidence model.

Users need a control that can answer, locally and before execution:

1. What action is this agent attempting?
2. Which user, session, agent, tool call, and process chain does it belong to?
3. Does it violate an explicit policy?
4. Can it be stopped without dispatching the underlying tool?
5. What bounded evidence explains the decision?

## 3. Product hypothesis

If AiDR provides low-latency pre-execution policy enforcement with clear, portable rules and detection-only output, developers and security teams can allow useful agent autonomy while reducing the risk of unsafe shell, filesystem, network, integration, and delegation activity.

This hypothesis is validated when users can install AiDR, run a supplied safety test, author a policy without editing harness-specific JSON, observe a prohibited action being blocked before dispatch, and understand the resulting detection without inspecting raw agent telemetry.

## 4. Users and jobs to be done

| User | Primary job | Required experience |
|---|---|---|
| Developer using an agent | Prevent obviously unsafe actions without breaking normal workflows | Install locally, see concise block reasons, understand how to proceed safely |
| Detection engineer | Express agent-action detections in a readable language | Use stable fields and operators, compile and test rules, inspect evidence |
| Security/platform engineer | Apply consistent controls across repositories and harnesses | Deploy adapters, layer policies, verify coverage and health |
| Incident responder | Understand what was attempted and how related activity was connected | Follow a bounded evidence chain across agent, tool, and process entities |

## 5. Product principles

- **Prevent before observing later.** A supported deny decision must occur before the underlying tool is dispatched.
- **Local decisions are independent.** Enforcement must not depend on a network service, SIEM, or collector.
- **Deterministic policy beats inferred intent.** Policies match observable actions and context, not unverified claims about model intent.
- **Detection-only output.** Raw observations are transient correlation inputs; durable product output is limited to policy detections.
- **Explain every response.** A deny identifies the rule, enforcement point, relevant entities, and evidence chain.
- **Vendor adapters, common semantics.** Harness-specific events map to a vendor-neutral action, correlation, policy, and detection model.
- **State the boundary honestly.** Application hooks are preventive control points, not an operating-system security boundary.
- **Secure failure is explicit.** Fail-open, fail-closed, and user-prompt behavior is chosen per failure class and documented.

## 6. Scope

### 6.1 Alpha scope

- Codex lifecycle integration for session, subagent, pre-tool, permission, and post-tool events.
- Pre-execution evaluation for supported shell, file-edit, MCP, delegation, and local tool requests.
- Session and actor correlation across registered subagents and ordinary descendant processes.
- AiDRQL compilation to bounded runtime policy IR.
- Static `ALLOW`, `DENY`, and `AUDIT` rules over normalized action and context fields.
- Local, schema-versioned detection events with response information and evidence chains.
- Network-free installation, validation, and smoke tests.

### 6.2 Beta scope

- User-level installation independent of a single repository.
- Policy layering for organization, user, repository, and temporary session scopes.
- Non-executing shell AST parsing and semantic target extraction.
- A second agent harness using the same normalized action and policy contracts.
- Health and tamper signals for missing, changed, bypassed, or failed hooks.
- Bounded local correlation storage with retention and privacy controls.
- Signed or integrity-verified policy bundles.
- Optional policy-gated remote threat-intelligence enrichment with explicit privacy, timeout, quota, and failure behavior.

### 6.3 Out of scope through beta

- Natural-language malicious-intent classification as an enforcement dependency.
- Centralized raw-event collection or full session replay.
- Automatic termination of unrelated user processes.
- A guarantee against a local administrator, compromised harness binary, or activity outside all instrumented paths.
- Autonomous remediation that modifies user data without a narrowly defined, reversible response contract.

## 7. Core user journeys

### 7.1 Install and verify

The user installs or enables the adapter, reviews its hook registration, runs a network-free conformance test, and receives proof that a prohibited stand-in action did not reach execution. Failure identifies whether registration, trust, policy compilation, policy loading, or enforcement caused the problem.

### 7.2 Author and deploy a rule

The user writes a readable policy, compiles it, receives line-specific validation errors if needed, runs positive and negative fixtures, and activates the generated policy atomically. Generated runtime JSON is not the authoring interface.

### 7.3 Block an action

The harness proposes a tool action. AiDR normalizes the request, enriches it with local context, evaluates policy, and returns a deny before dispatch. The user sees a safe, actionable reason. AiDR emits one detection for each denying rule according to the documented precedence model.

### 7.4 Allow and correlate an action

AiDR permits an action and attaches correlation context where the adapter can do so safely. Pre/post tool events, subagent actions, and observable descendant processes retain a stable trace and exact action identity. No durable detection is emitted unless a rule matches.

### 7.5 Investigate a detection

The responder opens one self-contained detection, identifies the policy and response, and follows the ordered evidence chain across the initiating agent, tool call, process, file, or endpoint without requiring access to a raw telemetry lake.

## 8. Product requirements

Priority uses `P0` for release-blocking, `P1` for required beta capability, and `P2` for a planned enhancement.

| ID | Priority | Requirement | Acceptance outcome |
|---|---:|---|---|
| PR-01 | P0 | AiDR evaluates every action exposed by an enabled supported pre-execution hook | Adapter conformance tests account for every advertised preventive tool path |
| PR-02 | P0 | A deny prevents the evaluated tool input from being dispatched | Sentinel and harness tests show zero execution side effects after deny |
| PR-03 | P0 | Policy evaluation is deterministic for identical normalized input, context, and policy | Repeated and cross-process fixtures produce byte-equivalent decisions, excluding timestamps and IDs |
| PR-04 | P0 | Rules are authored independently of Codex response JSON | AiDRQL source compiles to validated IR consumed by the Codex adapter |
| PR-05 | P0 | Core decisions do not require a remote dependency; rules using the optional reputation add-on declare that dependency explicitly | Baseline allow/deny conformance tests pass with network disabled; provider rules have separate failure-mode tests |
| PR-06 | P0 | Each deny has an actionable reason and a schema-valid detection | The response names the matched policy; all emitted detections pass schema validation |
| PR-07 | P0 | Raw tokens, prompts, model responses, and arbitrary hook payloads are not emitted as product telemetry | Secret and prohibited-field tests find no leakage in detection output |
| PR-08 | P0 | Missing or malformed security-critical policy fails according to an explicit policy | Default protected-path behavior is fail-closed and produces a safe error reason |
| PR-09 | P1 | Execution chains correlate root agents, subagents, tool lifecycles, and observable descendants | Correlation fixtures resolve all expected parent/child and action relationships |
| PR-10 | P1 | Policy authors can test a rule before activation | Compiler check, fixture evaluation, and stale-output detection are documented and automated |
| PR-11 | P1 | Users can distinguish coverage from security boundary | Status and diagnostics report enabled hooks, unsupported paths, and missing defense-in-depth controls |
| PR-12 | P1 | Policies can be layered with deterministic precedence | Organization, user, repository, and session conflicts have tested resolution rules |
| PR-13 | P1 | A second harness can reuse the action, policy, decision, and detection contracts | The new adapter passes the common conformance suite without changing rule semantics |
| PR-14 | P2 | AiDR can correlate endpoint observations without trusting environment tokens as identity | Process records combine trace hints with OS identity and ancestry evidence |
| PR-15 | P1 | Policies can request remote reputation only for domains/IPs selected by an explicit regex gate | Non-matches make zero provider calls; matching process/tool targets use the configured verdict and failure mode |

## 9. Key areas of success

Targets below are release gates, not claims about current production performance. Measurements must name the adapter version, policy corpus, host profile, sample size, and whether process startup is included.

| Area | Metric | Alpha exit target | Beta exit target |
|---|---|---:|---:|
| Preventive efficacy | Known-deny fixtures that reach the underlying tool | 0 across the Codex conformance corpus | 0 across all supported adapters and adversarial corpora |
| Preventive coverage | Advertised preventive action types evaluated before dispatch | 100% | 100%, with unsupported paths reported explicitly |
| Safe-action compatibility | Benign corpus incorrectly denied | 0 in release corpus | False-deny rate below 0.5% in a representative, versioned corpus |
| Detection quality | Denies with schema-valid rule, response, and resolvable evidence references | 100% | 100% |
| Privacy | Raw correlation tokens, prompts, model responses, or known fixture secrets in detection output | 0 | 0 |
| Determinism | Divergent decisions for identical replay inputs | 0 | 0 across supported platforms |
| Engine latency | Policy-engine p95 for the maximum supported policy bundle on reference hardware | ≤ 10 ms | ≤ 10 ms |
| Adapter overhead | End-to-end pre-tool p95, measured separately from tool execution | Baseline and publish | ≤ 50 ms on each reference platform, or an approved platform-specific budget |
| Resilience | Malformed input/policy cases that crash or silently bypass enforcement | 0 | 0 |
| Rule usability | Supplied policy examples that compile and produce expected positive/negative decisions | 100% | 100%; median first-rule validation task ≤ 10 minutes in usability testing |
| Portability | Harnesses passing the common contract suite | 1 | At least 2 |
| Operability | Test failures that identify actionable cause and component | 100% of release tests | 100% plus adapter health reporting |

## 10. Measurement methodology

1. Maintain versioned **malicious**, **benign**, **ambiguous**, and **malformed** corpora. A fixture records its expected decision, required coverage point, and prohibited side effects.
2. Measure prevention with harmless sentinels that make dispatch observable without contacting real malicious infrastructure or modifying valuable data.
3. Separate compiler time, engine evaluation time, adapter process/startup overhead, and complete harness round-trip latency.
4. Run cold and warm samples; report p50, p95, p99, maximum, sample count, host, OS, Python/runtime, harness version, and policy size.
5. Mutation-test rules and adapters by changing fields, operators, nesting, casing, command structure, and lifecycle ordering. Every fixed bypass becomes a permanent regression fixture.
6. Validate every emitted detection against its JSON Schema, check reference integrity in the evidence graph, and scan prohibited content and fixture secrets.
7. Report coverage by action type and hook point. Never calculate “100% coverage” over only events that happened to be observed.
8. Track false denials only against a reviewed benign corpus; production user overrides are a supplemental signal, not ground truth by themselves.

## 11. Release methodology and gates

| Stage | Purpose | Required evidence to exit |
|---|---|---|
| Prototype | Prove the local control point and data contracts | One safely blocked live action, automated regression suite, documented boundary |
| Alpha | Stabilize Codex behavior and policy authoring | All P0 requirements; version-pinned conformance report; zero known corpus escapes or prohibited detection leakage |
| Beta | Validate portability and operating model | P1 requirements; second adapter; policy layering; shell AST; health/tamper reporting; documented upgrade/rollback |
| Production candidate | Establish defensible security and reliability | Independent threat-model review; red-team corpus; signed release artifacts; performance budgets; compatibility matrix; incident and disclosure process |

No stage advances solely because a feature exists. It advances when the stated evidence is reproducible from a tagged revision.

## 12. Risks and product decisions still required

- Harnesses can change or omit hook behavior. AiDR needs versioned compatibility claims and negative coverage reporting.
- Application hooks can be disabled by a sufficiently privileged local actor. Positioning must not imply endpoint-enforcement strength until an independent control exists.
- Shell syntax, generated scripts, indirect interpreters, and delayed execution can defeat shallow command parsing. Production shell policy requires a non-executing AST and adversarial corpus.
- Environment correlation can be removed or spoofed. It is a hint until joined with trusted OS observations.
- Fail-closed behavior protects security but can disrupt development. Failure-class policy and recovery UX require explicit product ownership.
- Detection minimization can conflict with forensic usefulness. Schema evolution must preserve a reviewed evidence budget.
- Policy precedence and exceptions can create hidden gaps. The product needs a visible explanation of the effective policy and why a rule won.

## 13. Dependencies

- Stable preventive lifecycle hooks and response contracts from each supported harness.
- A normalized action taxonomy and versioned runtime policy IR.
- Safe local state, atomic policy activation, and permission-restricted storage.
- A test fixture framework that proves non-dispatch without harmful side effects.
- Platform-specific process ancestry support for defense-in-depth correlation.

## 14. Related documents

- [Engineering requirements](engineering-requirements.md)
- [Engineering direction](engineering-direction.md)
- [Policy compiler](policy-compiler.md)
- [Detection event schema](detection-event-schema.md)
- [Tool response contract](tool-response.md)
- [Trace propagation](trace-propagation.md)
- [Testing guide](testing.md)
