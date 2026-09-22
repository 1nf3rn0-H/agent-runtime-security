# AiDR policy compiler

Status: Alpha  
Language version: `aidrql/2`  
Last updated: September 22, 2026

## Architecture

Rule authors do not write Codex hook responses or the runtime JSON format directly.

```text
AiDRQL source
    |
    v
Parser -> typed source model -> semantic validator -> runtime policy IR
                                                        |
                                                        v
                                              harness adapters such as Codex
```

The checked-in authoring source is [`policies/default.aidrql`](../policies/default.aidrql). The compiler combines it with [`.aidr/runtime.json`](../.aidr/runtime.json) and produces [`.aidr/rules.json`](../.aidr/rules.json). The hook reads only the generated JSON, so compilation adds no dependency or parsing cost to the inline enforcement path.

The generated object declares runtime IR version `1.4.0` and is validated against the shared semantic contract before being activated with an atomic file replacement. The hook validates it again at load time and records its canonical SHA-256. See the [runtime policy lifecycle](runtime-policy.md).

## Example

```text
DEFAULT ALLOW

RULE block-ping-evil-domain
TITLE "Network probing of a prohibited domain"
DESCRIPTION "Prevent an agent from invoking ping against an explicitly prohibited domain."
SEVERITY high
CATEGORY network.prohibited_destination
VERSION "1"
WHEN tool.name IS "Bash"
AND process.executable IS ["ping", "ping6"]
AND network.destinations MATCHES "^evil\\.com$"
THEN DENY "Blocked by AiDR: ping destination matched a prohibited-domain policy."
END
```

Compile it with:

```bash
python3 .aidr/policy_compiler.py policies/default.aidrql \
  --settings .aidr/runtime.json \
  --output .aidr/rules.json
```

Check that the generated IR is current without modifying it:

```bash
python3 .aidr/policy_compiler.py policies/default.aidrql \
  --settings .aidr/runtime.json \
  --output .aidr/rules.json \
  --check
```

## Language statements

| Statement | Meaning |
|---|---|
| `DEFAULT ALLOW` / `DEFAULT DENY` | Decision when no allow or deny rule matches |
| `RULE id` ... `END` | Defines one rule |
| `TITLE`, `DESCRIPTION` | Detection and analyst-facing metadata |
| `SEVERITY` | `informational`, `low`, `medium`, `high`, or `critical` |
| `CATEGORY` | Namespaced detection category |
| `VERSION` | Quoted rule version |
| `WHEN` / `AND` | Conjunctive match conditions |
| `CASE SENSITIVE` / `CASE INSENSITIVE` | Controls comparisons in the rule; defaults to insensitive |
| `THEN` | `ALLOW`, `DENY`, or `AUDIT` |
| `THEN DENY "reason"` | Denies and supplies the required user-facing reason in one statement |

## Simple matching

Most rules need only three operators. They work without requiring the author to know whether a normalized field is represented as one string or a list:

| Operator | Meaning | Runtime strategy |
|---|---|---|
| `IS "value"` | Exact value | Scalar equality or exact list membership |
| `IS ["a", "b"]` | Any listed exact value | Scalar set membership or list intersection |
| `CONTAINS "text"` | Literal substring | Native substring search; list fields use an escaped regex |
| `MATCHES "pattern"` | Regular-expression search | Scalar or any-list regex search |
| `EXISTS` / `NOT_EXISTS` | Presence or absence | No value comparison |

Matching is case-insensitive by default. Add `CASE SENSITIVE` inside a rule only when case changes its meaning:

```text
RULE block-uppercase-secret-name
WHEN file.paths MATCHES "(^|/)SECRET$"
CASE SENSITIVE
THEN DENY "Blocked the case-sensitive protected path."
END
```

Use `IS` first, `CONTAINS` for literal fragments, and `MATCHES` only when the value is genuinely a pattern. Regex is more expressive, but it is not faster than exact or literal matching.

## Fields and operators

| Field | Value at the hook |
|---|---|
| `tool.name` | Canonical tool name, such as `Bash`, `apply_patch`, or `mcp__fetch` |
| `tool.family` | `shell`, `file_edit`, `mcp`, `agent`, or `local_function` |
| `action.type` | `process.exec`, `file.modify`, `integration.call`, `agent.delegate`, or `tool.call` |
| `session.cwd` | Working directory supplied by the harness |
| `agent.id` | Actor ID from the local trace registry (`root` or a registered subagent) |
| `action.command` | Proposed `tool_input.command`, if present; not shell-expanded |
| `process.executable` | Basename of one parsed shell invocation |
| `process.args` | Argument list for that same invocation, excluding the executable |
| `process.dispatch_chain` | Ordered wrappers and dispatchers leading to that invocation, such as `xargs`, `sh` |
| `network.destinations` | Hostnames or IP addresses extracted from a recognized network-capable invocation |
| `network.urls` | URLs extracted from a recognized network-capable invocation |
| `file.paths` | File operands and redirection paths extracted from a recognized invocation |
| `git.operations` | Git subcommands such as `clone`, `fetch`, or `push` |
| `git.repositories` | Repository/remotes supplied to recognized Git operations |
| `package.operations` | Qualified package action such as `npm.install` or `pip.install` |
| `package.names` | Package operands supplied to a recognized package action |
| `tool.targets` | Bounded values from well-known direct target keys across tool contracts |
| `tool.network.destinations` | Normalized domains/IPs from well-known direct tool target keys |
| `threat.indicator_ids` | Provider result IDs matching the same process invocation |
| `threat.verdicts` | Verdicts matching the same process invocation |
| `threat.labels` | Threat labels matching the same process invocation |
| `threat.sources` | Reputation providers matching the same process invocation |
| `threat.matched_targets` | Semantic values that produced threat matches on the same invocation |
| `tool.threat.<field>` | Equivalent threat fields for normalized tool-call targets |
| `tool.input.<key>` | One **direct** key of the tool input object, such as `tool.input.url` or `tool.input.targets` |

String fields accept `==`, `!=`, `IN`, `NOT_IN`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, and `MATCHES`. `IN` and `NOT_IN` take a non-empty list of strings; the other binary operators take a quoted string. `MATCHES` uses Python regular-expression search semantics.

List fields accept `HAS_ANY`, `HAS_ALL`, and `HAS_NONE` with exact-value lists, plus `ANY_MATCHES` with one quoted regular expression. Process argument, dispatch, semantic target, and tool target fields are lists. `tool.input.<key>` can be either a string or a list and accepts the corresponding operators. Every field also accepts `EXISTS` and `NOT_EXISTS`, which take no value. A missing value does **not** satisfy `!=`, `NOT_IN`, or `HAS_NONE`; use `NOT_EXISTS` to test absence. A present JSON `null` satisfies `EXISTS` but not string or list comparisons.

For example, a rule can distinguish an indirectly dispatched process:

```text
RULE audit-xargs-ping
WHEN process.executable == "ping"
AND process.dispatch_chain HAS_ANY ["xargs"]
THEN AUDIT
END
```

A semantic rule can block a destination across recognized network command layouts:

```text
RULE block-prohibited-network-target
WHEN network.destinations HAS_ANY ["evil.com", "203.0.113.10"]
THEN DENY
MESSAGE "Blocked a prohibited network destination."
END
```

Semantic process fields bind to the same invocation as `process.executable`, `process.args`, and `process.dispatch_chain`. Dynamic values that could alter an otherwise viable semantic match fail closed. `tool.targets` is global to the proposed tool call and is populated only from documented direct target-key names; it does not recursively traverse arbitrary input.

Threat fields are populated only when the optional provider is enabled and a viable rule's explicit `ANY_MATCHES` gate selects a domain/IP for remote lookup. Process threat fields preserve same-invocation binding; `tool.threat.*` fields refer only to the current tool call. The compiler rejects threat predicates without a corresponding regex gate. See [policy-gated remote threat intelligence](threat-intelligence.md).

All conditions in a rule use logical AND. Repeated conditions on the same field are allowed. Process conditions are tested together against one parsed invocation; for example, `curl safe.com && ping evil.com` will not satisfy `process.executable == "curl"` AND `process.args HAS_ANY ["evil.com"]`.

Values are typed Python-style literals: strings must be quoted, lists use bracket syntax, and regular expressions should be quoted. Comparisons default to case-insensitive. `tool.input.<key>` looks up only the exact, case-sensitive input key; it does not traverse nested objects. The compiler does not validate whether a given tool actually supplies that key.

For example, this rule blocks a proposed MCP upload before the call reaches the integration:

```text
RULE block-mcp-upload
WHEN tool.family == "mcp"
AND tool.input.url CONTAINS "evil.com"
AND tool.input.targets HAS_ANY ["private", "sensitive"]
THEN DENY
MESSAGE "Blocked upload to a prohibited destination."
END
```

The generated matcher is a bounded list of field/operator/value predicates, with `case_sensitive` set at the rule level. Older hand-written JSON matchers remain readable by the hook for compatibility, but new AiDRQL compilation uses this predicate-list IR. See [ADR-0011](decisions/0011-bounded-predicate-list-ir.md).

## Decision semantics

The compiled runtime evaluates every rule:

1. Any matching `DENY` wins.
2. Otherwise, a matching `ALLOW` allows the action.
3. Otherwise, the policy uses `DEFAULT`.
4. `AUDIT` records a match but does not change the decision.

One detection is emitted for each matching deny rule. Compiled title, description, severity, category, and version flow into that detection.

## Compile-time failures

The compiler rejects:

- unknown fields or field/operator combinations;
- invalid regular expressions;
- malformed or unquoted literals;
- duplicate rule IDs;
- rules without conditions or actions;
- deny rules without a response message; and
- generated output that is stale when `--check` is used.

Errors include the source line number whenever possible.

The current compiler caps source size at 256 KiB, rules at 1,000, conditions per rule at 32, list values at 128, and each condition literal at 4,096 characters. These bounds protect compilation but are not a guarantee of inline hook latency; production deployment still needs policy-load validation and latency budgets. Regular expressions are compiled for validity, not guaranteed linear-time, and should be used sparingly on bounded inputs.

## Extension model

AiDRQL is one frontend, not the runtime policy model. Future Sigma-YAML, KQL-subset, or SQL-subset frontends should produce the same typed source model and runtime IR. This prevents authoring syntax from leaking into Codex, Claude Code, or endpoint adapters.

The initial version deliberately excludes OR, NOT, parentheses, joins, aggregation, and time windows. Those features require a richer runtime condition tree rather than ad hoc source rewriting.
