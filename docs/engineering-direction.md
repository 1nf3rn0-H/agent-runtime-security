# AiDR engineering direction

Status: Living document  
Last updated: September 22, 2026

## Product statement

AiDR is application-level runtime security for AI coding agents. It observes agent actions, enriches them with user and process context, evaluates lightweight detection policies, and prevents disallowed actions before they reach the underlying tool or operating system.

The first supported harness is Codex. The current alpha intercepts every supported local tool event, assigns a session trace, registers subagent actors, normalizes tool actions, parses proposed shell commands, evaluates local rules, injects trace context into allowed commands, emits a synchronous allow-or-deny decision, records diagnostic JSONL observations, and emits schema-versioned detection events for denials. A local CLI installs and removes the adapter, diagnoses health, compiles policy, safely simulates actions, and exposes status and detections.

## Goals

- Make an enforcement decision before a supported agent action executes.
- Normalize observations from multiple agent harnesses into one internal correlation model.
- Attribute events to an agent session, user, process, repository, and tool call.
- Support understandable static rules with deterministic outcomes.
- Record sufficient evidence to explain every decision.
- Keep the inline decision path local, fast, and available without a remote service.
- Add defense-in-depth controls for actions that bypass harness hooks.

## Current non-goals

- Treating an application hook as an operating-system security boundary.
- Detecting arbitrary malicious intent from natural language alone.
- Building a centralized management console before the local enforcement model is sound.
- Supporting every shell grammar and evasion technique in the initial prototype.
- Automatically terminating unrelated user processes.

## Threat model

AiDR currently assumes that an AI agent may propose or invoke an unsafe action because of prompt injection, compromised context, malicious tool output, a model error, or an overly broad user instruction.

Actions of interest include:

- shell and process execution;
- file reads, writes, and deletion;
- MCP, plugin, and connector calls;
- network access and data exfiltration;
- credential and secret access;
- source-control and package-manager operations;
- subagent creation; and
- delayed execution through generated scripts or background processes.

The current prototype does not defend against a local administrator, a user intentionally disabling the hook, a compromised Codex binary, or execution paths that do not emit a supported hook event.

## Current architecture

```text
Codex server response
        |
        v
Local tool request
        |
        v
Codex PreToolUse hook
        |
        +--> Normalize and enrich event
        |
        +--> Normalize the proposed tool action
        |
        +--> Evaluate local rules
        |       |
        |       +--> allow: Codex continues
        |       +--> deny: tool call is rejected
        |
        +--> Append decision telemetry
```

The enforcement decision is synchronous. Telemetry export and downstream analytics are separate from the critical path.

Allowed shell calls receive an environment-based correlation context that is inherited by ordinary descendants. See [Trace-token propagation](trace-propagation.md) and [ADR-0005](decisions/0005-session-trace-environment-propagation.md).

Every supported local tool call uses the same pre-execution evaluation contract: deny blocks, unchanged allow preserves the normal harness permission flow, and safe adapter-specific rewrites return updated input. See [Tool-agnostic response layer](tool-response.md) and [ADR-0007](decisions/0007-uniform-response-for-supported-tools.md).

## Codex hook surface

Codex currently exposes these lifecycle events:

| Hook | AiDR role | Preventive capability |
|---|---|---|
| `UserPromptSubmit` | Inspect prompts and secret leakage | Can reject a prompt before submission |
| `SessionStart` | Establish session context and load policy | Context and limited continuation control |
| `SubagentStart` | Record parent-child agent identity | Cannot prevent subagent startup |
| `PreToolUse` | Inspect shell, edit, MCP, and local tool calls | Can deny or rewrite supported calls |
| `PermissionRequest` | Inspect escalation and approval requests | Can allow or deny the request |
| `PostToolUse` | Record result and detect completed violations | Cannot undo side effects |
| `PreCompact` | Preserve context before compaction | Can stop compaction |
| `PostCompact` | Assess compacted context | Can stop subsequent processing |
| `SubagentStop` | Validate subagent completion | Can request continued subagent work |
| `Stop` | Validate completion of a main turn | Can request another agent pass |
| `Interrupt` | Record interruption and clean up | Cannot prevent the interruption |
| `SessionEnd` | Flush final session telemetry | Advisory only |

`PreToolUse` and `PostToolUse` cover Bash/unified execution, `apply_patch`, MCP tools, and most local function tools. Hosted tools such as web search are not on the same hook path, and specialized tool paths may opt out. The official behavior reference is the [Codex hooks documentation](https://learn.chatgpt.com/docs/hooks).

## Engineering options and direction

### Enforcement integration

| Option | Strengths | Limitations | Direction |
|---|---|---|---|
| Vendor pre-execution hooks | Rich agent context; blocks before supported tools | Vendor-specific and incomplete coverage | **Use now** through adapters |
| Vendor approval hooks | Controls privilege and network escalations | Fires only when approval is requested | **In use** as a second preventive layer |
| OpenTelemetry/event export | Standard transport if a sink is later required | Asynchronous; too late for prevention | Detection events only; never raw observations |
| Agent launcher/wrapper | Adds session and user labels consistently | Environment values can be removed or spoofed | Add for correlation, not trusted identity |
| OS process/network controls | Strong boundary independent of the agent | Platform-specific and operationally heavier | Add after the application policy model stabilizes |

Decision: use vendor hooks for the first inline control plane while designing adapters around a vendor-neutral event and decision model. See [ADR-0001](decisions/0001-codex-pretooluse-enforcement.md).

### Policy engine

| Option | Strengths | Limitations | Direction |
|---|---|---|---|
| Purpose-built JSON rules | No dependencies; easy to test and embed | Poor authoring ergonomics | **Use as generated runtime IR** |
| YAML rules | Better human authoring | Adds parser dependency and YAML ambiguity | Consider after the schema stabilizes |
| CEL | Typed, bounded expression language | Runtime integration and learning cost | Strong candidate for production |
| Rego/OPA | Mature policy ecosystem | Heavier runtime and policy complexity | Evaluate for enterprise deployment |
| Sigma-like domain language | Familiar to detection engineers | Requires a compiler and well-defined action taxonomy | Add as a compiler frontend |

Decision: author rules in `aidrql/2` and compile ahead of time to deterministic JSON IR. The common authoring surface uses `IS`, `CONTAINS`, and `MATCHES`, while the compiler chooses scalar/list runtime operations. The current IR is a bounded conjunction of predicates over tool, action, session, agent, process, and direct tool-input fields. Keep the compiler frontend separate so Sigma-YAML, KQL-subset, or SQL-subset inputs can target the same IR later. See [ADR-0010](decisions/0010-compile-human-readable-policies-to-ir.md), [ADR-0011](decisions/0011-bounded-predicate-list-ir.md), [ADR-0019](decisions/0019-simplify-aidrql-matching.md), and the [policy compiler documentation](policy-compiler.md).

### Command interpretation

| Option | Strengths | Limitations | Direction |
|---|---|---|---|
| Regex over raw commands | Very fast to implement | Easy to evade and prone to false positives | Allow only as an explicit supplemental matcher |
| Python `shlex` plus semantic matching | Dependency-free; handled the initial demonstration | Missed substitutions, redirections, and wrapper semantics | Replaced by ADR-0013 |
| Bounded non-executing subset parser | Structural commands, substitutions, redirections, dynamics, and hard limits | Rejects valid control flow; cannot inspect embedded languages or external scripts | **Current prototype** |
| Shell AST parser | Understands pipelines, substitutions, redirections, and nesting | More dependencies and platform variance | Required before production shell enforcement |
| Execute shell in analysis mode | Potentially exact expansion behavior | Unsafe and can cause side effects | Reject |

Direction: never execute a command to understand it. The bounded parser recorded in [ADR-0013](decisions/0013-bounded-non-executing-shell-parser.md) replaces flat token splitting and fails closed on unsupported security-sensitive input. Adopt a mature grammar through differential testing before production shell coverage, and add typed extractors for indirect dispatchers and embedded interpreters.

### Telemetry path

| Option | Strengths | Limitations | Direction |
|---|---|---|---|
| Local JSONL | Transparent, append-only, easy to inspect | Weak querying and lifecycle management | **Use for prototype** |
| SQLite | Local queries, indexing, and correlation | Schema migrations and file contention | Likely next local store |
| OTLP collector | Standard remote pipeline | Network dependency and backpressure | Add asynchronously |
| Direct SaaS ingestion | Simple managed experience | Vendor lock-in and sensitive-data concerns | Defer |

Decision: keep the decision engine and correlation state local. Raw observations are internal inputs; only matched detections become durable product events. Remote telemetry must not determine whether the inline hook can respond on time. See [ADR-0002](decisions/0002-separate-enforcement-and-telemetry.md), [ADR-0006](decisions/0006-emit-detections-not-raw-observations.md), and the [detection event schema](detection-event-schema.md).

### Deployment model

| Option | Strengths | Limitations | Direction |
|---|---|---|---|
| Repository-local hook | Easy development and per-project policy | Requires trust; user can modify it | **Current prototype** |
| User-level hook | Covers multiple repositories | User-managed and still disableable | Near-term developer installation |
| Codex plugin | Portable packaging and data directory | Requires plugin installation and trust | Preferred product packaging candidate |
| Managed hook/requirements | Enforceable by organization policy | Enterprise administration required | Enterprise direction |
| Endpoint service | Cross-agent and harder to bypass | Installation privileges and platform work | Defense-in-depth direction |

Direction: develop locally, then package the Codex adapter cleanly while keeping the policy engine independent of Codex-specific paths.

The alpha now has a reversible local installer for project and user scopes. It merges handlers without deleting unrelated configuration, creates rollback backups, and leaves Codex project-hook trust to explicit user review. Its absolute checkout path is a known packaging limitation. See [ADR-0018](decisions/0018-local-cli-and-reversible-codex-installation.md).

### Failure behavior

| Failure | Current behavior | Direction |
|---|---|---|
| Policy cannot load or parse | Deny | Keep configurable fail-closed default for protected actions |
| Command cannot be parsed | Deny | Keep fail-closed; record parser reason |
| Regex-selected remote threat lookup fails | Allow in optional `open` mode or deny in `closed` mode | Tune by policy risk, provider quota, and latency SLO |
| Telemetry append fails | Deny because evaluation cannot complete cleanly | Separate evidence durability from policy availability before production |
| Hook times out or is skipped | Controlled by the harness, not AiDR | Add health checks and an OS-level backstop |
| Remote collector unavailable | Not used inline | Queue locally without affecting decisions |

The current fail-closed choice is recorded in [ADR-0004](decisions/0004-fail-closed-policy-errors.md).

## Near-term implementation direction

### Phase 1 — Strengthen the Codex proof of concept

- Normalize every Codex lifecycle event into an internal correlation envelope.
- Expand the implemented typed-target evidence with path canonicalization, CIDR semantics, and additional reviewed tool contracts while retaining bounded evidence graphs.
- Keep optional threat-intelligence enrichment isolated and disabled while the core control plane matures.
- Complete lifecycle adapter coverage beyond the six installed events and publish an explicit coverage matrix.
- Extend runtime-policy health reporting beyond the implemented schema validation, atomic activation, hashing, and last-known-good recovery.
- Expand the compiler IR from conjunctions to a bounded Boolean condition tree.
- Carry stable action IDs into future process-sensor observations and response actions.
- Redact or hash sensitive command fields according to telemetry policy.
- Replace the alpha installer's absolute checkout paths with a packaged adapter and signed release artifact.
- Add latency budgets and performance regression tests.
- Add process-level capture that combines the injected trace with PID/PPID ancestry.

### Phase 2 — Broaden action coverage

- Broaden the implemented semantic policies for file operations, MCP calls, package managers, Git, and network-capable tools with versioned compatibility fixtures.
- Extend the bounded parser beyond the implemented `xargs`, `find`, `watch`, and `eval` extractors with differential corpora and additional typed dispatch contracts before adopting a mature shell grammar.
- Add Claude Code and generic harness adapters.
- Introduce a local service so adapters share policy, state, and telemetry.
- Evaluate SQLite for local correlation and durable queues.

### Phase 3 — Defense in depth

- Correlate hooks with process ancestry and operating-system identity.
- Enforce network and filesystem boundaries outside the agent harness.
- Detect detached and delayed child processes.
- Add signed policy bundles and tamper detection.
- Add an optional asynchronous sink for detection events only; do not export raw observations.

## Open engineering questions

- Which internal observation fields are required for each cross-agent correlation strategy?
- Should production rules use CEL directly or compile a Sigma-like format into CEL?
- Which policy failures should fail closed versus prompt the user?
- Which canonicalization and matching semantics should extend the implemented exact hostname, minimized URL, path, Git, package, and tool-target lists—especially CIDR, DNS aliases, symlinks, and platform paths?
- What process or OS primitive provides reliable session attribution across macOS, Linux, and Windows?
- How will policy precedence work across organization, user, repository, and temporary session layers?
- What is the maximum acceptable inline latency at p50, p95, and p99?
- How should sensitive tool input and output be redacted without destroying forensic value?
- What response actions are safe at application level, and which require an endpoint service?

## Current evidence

- The prototype was initially verified on `codex-cli 0.147.0` on August 18, 2026.
- The hook feature was reconfirmed as stable and enabled on `codex-cli 0.153.4` on September 10, 2026.
- An end-to-end Codex test denied a proposed `ping evil.com` action before a harmless stand-in executable was reached.
- The recorded inline decision latency for that test was 479 microseconds.
- One hundred eight automated tests now pass, including reversible/idempotent installation, non-executing simulation, policy compilation and recovery, typed targets, evidence graphs, semantic uncertainty, indirect dispatch, execution-chain propagation, token isolation, and isolated optional-enrichment behavior.
- The September 22 development run measured a 1,000-rule base evaluation at 0.764 ms p95 and a single-rule regex-gated target evaluation at 0.029 ms p95 over 200 samples; these are separate workloads and not comparative throughput claims. Provider network time is excluded and is captured as per-event threat-intelligence latency when the optional add-on is enabled.
- A live `codex-cli 0.153.4` subagent test correlated `SessionStart`, `SubagentStart`, `PreToolUse`, the subagent process and child process, and `PostToolUse` under one trace. The tested build supplied `agent_id` on both tool hooks, and persisted telemetry contained no raw correlation token.
