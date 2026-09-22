# AiDR engineering documentation

This directory records the engineering options, decisions, constraints, and current direction for AiDR. It is intended to explain not only what is being built, but why the system has taken its present shape.

## Living documents

- [Product requirements](product-requirements.md) — users, scope, product outcomes, success metrics, and release gates.
- [Engineering requirements](engineering-requirements.md) — normative system requirements, trust boundaries, verification matrix, and engineering methodology.
- [Engineering direction](engineering-direction.md) — goals, architecture, evaluated options, risks, and phased direction.
- [Local CLI](cli.md) — installation, diagnostics, policy, simulation, status, and removal workflows.
- [Trace-token propagation](trace-propagation.md) — session, subagent, tool-call, and subprocess correlation model.
- [Detection event schema](detection-event-schema.md) — the versioned, detection-only output contract and evidence graph.
- [Tool-agnostic response layer](tool-response.md) — coverage, normalization, and response semantics across supported tools.
- [Testing guide](testing.md) — isolated, contract, and safe live-Codex verification.
- [Policy compiler](policy-compiler.md) — AiDRQL authoring, semantic validation, and runtime-IR generation.
- [Runtime policy lifecycle](runtime-policy.md) — IR schema, validation, atomic activation, hashing, and last-known-good recovery.
- [Bounded shell parser](shell-parser.md) — structural parsing, dynamic-value semantics, limits, and unsupported indirect execution paths.
- [ADR-0015](decisions/0015-extract-typed-semantic-targets.md) — typed semantic targets for policy and minimized detection evidence.
- [Remote threat intelligence](threat-intelligence.md) — policy-gated VirusTotal lookup, failure behavior, privacy, and evidence.
- [ADR-0018](decisions/0018-local-cli-and-reversible-codex-installation.md) — local control plane and reversible Codex hook installation.
- [Decision log](decisions/README.md) — accepted and proposed architecture decision records (ADRs).

## Documentation practice

Update the engineering direction when the product scope, architecture, threat model, or implementation sequence changes. Add an ADR when a decision:

- affects more than one component;
- introduces a meaningful security or operational tradeoff;
- constrains future implementations; or
- reverses or supersedes an earlier decision.

ADRs are immutable after acceptance except for minor clarification. A changed decision should receive a new ADR that supersedes the old one.
