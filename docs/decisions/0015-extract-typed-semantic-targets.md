# ADR-0015: Extract typed semantic targets before policy evaluation

Status: Accepted for prototype  
Date: 2026-09-21  
Extends: ADR-0011, ADR-0013, ADR-0014

## Context

Raw argument rules bind policy to each utility's spelling and option layout. The same destination can appear as a `ping` host, a `curl` URL, a Git remote, or a tool-input field. Raw matching also produces weak evidence because it cannot distinguish a file path from a network endpoint or package name.

AiDR needs a vendor-neutral target layer before adding reputation or threat-intelligence enrichment. The layer must not execute a command, resolve DNS, access files, or infer targets from unsupported syntax.

## Options considered

1. Continue authoring rules only against raw process arguments and tool inputs.
2. Infer targets with broad regular expressions over the complete command string.
3. Extract typed targets from bounded, recognized command and tool contracts, retain uncertainty, and expose normalized list fields to policy.

## Decision

Use option 3. Before policy evaluation, recognized invocation contracts produce bounded target lists for network destinations and URLs, file paths, Git operations and repositories, and package operations and names. Direct well-known tool-input keys produce a normalized `tool.targets` list across MCP and local tools.

Semantic process fields remain attached to the invocation that produced them. A rule combining `process.executable == "curl"` and `network.destinations HAS_ANY ["evil.com"]` must satisfy both predicates on one invocation.

Dynamic values and command layouts that can change a target mark that target field uncertain. If an otherwise viable rule depends on the uncertain result, preventive evaluation fails closed. A definitely false static predicate on the same invocation prevents unrelated dynamic data from causing a denial.

Runtime IR `1.2.0` adds these list fields:

- `network.destinations` and `network.urls`
- `file.paths`
- `git.operations` and `git.repositories`
- `package.operations` and `package.names`
- `tool.targets`

Denied detections include bounded typed target attributes and target entities connected to the proposed tool call. URL credentials, queries, and fragments are removed before the normalized URL enters policy or evidence. This is proposed pre-execution evidence; it does not claim that a connection or file access occurred.

## Consequences

- Policies can describe behavior independently of most raw CLI spelling.
- Target evidence becomes directly usable by later local threat-intelligence enrichment.
- False matches are reduced by command-aware positional parsing, but extractor compatibility still depends on utility versions and supported option layouts.
- Unrecognized commands produce no semantic targets; policy authors can still use raw fields or deny unsupported paths.
- Embedded programs, package lifecycle scripts, external scripts, filesystem resolution, DNS aliases, comprehensive URL canonicalization, CIDR matching, and nested tool-input objects remain outside this milestone.
