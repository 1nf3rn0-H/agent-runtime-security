# Policy-gated remote threat intelligence

Status: Implemented for the prototype
Provider: VirusTotal API v3
Last updated: September 22, 2026

## Boundary

Threat intelligence is an optional add-on. Agent Runtime Security stores no local indicator feed and does not persist provider responses. The inline evaluator contacts VirusTotal only when all non-threat conditions in a rule match and a domain or IP matches that rule's explicit regex gate.

The API key is read from an environment variable and is never accepted in policy, written to telemetry, or copied into a detection. VirusTotal necessarily receives every selected domain or IP; policy authors must therefore make lookup regexes as narrow as their privacy and quota requirements demand.

## Runtime configuration

The checked-in configuration is disabled:

```json
{
  "threat_intelligence": {
    "enabled": false,
    "provider": "virustotal",
    "api_key_env": "VIRUSTOTAL_API_KEY",
    "timeout_ms": 1500,
    "failure_mode": "open",
    "malicious_threshold": 1,
    "suspicious_threshold": 1,
    "max_lookups": 4
  }
}
```

To enable it, export `VIRUSTOTAL_API_KEY`, change `enabled` to `true`, and recompile the policy. `failure_mode: "open"` records provider failures but does not fabricate a match. `failure_mode: "closed"` denies the proposed action when a required lookup cannot complete. The timeout is per request; `max_lookups` bounds calls for one hook event.

The provider origin is fixed to `https://www.virustotal.com/api/v3`. Policy cannot redirect the API key to another server.

## Policy gating

A process threat predicate requires exactly one `network.destinations ANY_MATCHES` condition in the same rule:

```text
RULE block-vt-malicious-destination
WHEN process.executable IN ["curl", "ping", "ping6", "wget"]
AND network.destinations ANY_MATCHES "^(?:example\\.com|203\\.0\\.113\\.[0-9]+)$"
AND threat.verdicts HAS_ANY ["malicious"]
THEN DENY
MESSAGE "Blocked: VirusTotal classified the destination as malicious."
END
```

For normalized MCP or local-tool inputs, use `tool.network.destinations ANY_MATCHES` with `tool.threat.*` predicates. A threat predicate without its corresponding gate is rejected during compilation and runtime validation.

Agent Runtime Security first checks the other rule conditions. It then queries only matching domains/IPs, memoizes duplicate lookups for that one event, and evaluates the threat predicate. It never performs remote enrichment for `PostToolUse` observations.

## Verdict mapping

Agent Runtime Security consumes VirusTotal's `last_analysis_stats`:

- `malicious` when the malicious-engine count reaches `malicious_threshold`;
- otherwise `suspicious` when the suspicious-engine count reaches `suspicious_threshold`;
- otherwise `benign` when at least one engine reports harmless;
- otherwise `unknown`, including a VirusTotal 404.

Available policy fields remain:

- `threat.indicator_ids`, `threat.verdicts`, `threat.labels`, `threat.sources`, and `threat.matched_targets` for one process invocation;
- equivalent `tool.threat.*` fields for the current tool call.

## Evidence and telemetry

A threat-driven detection includes bounded verdict, provider, matched-target, tag, and detection-ratio evidence. The extension records provider availability, lookup count, measured lookup latency, and failure mode. API keys, complete provider responses, URL credentials, query parameters, and fragments are prohibited.

## Operational limitations

- Inline decisions now depend on provider latency, availability, quota, and terms of service when the add-on is enabled.
- No cross-event cache is kept, so repeated actions consume repeated API quota.
- A low malicious threshold can create false positives; deployments should tune it against their own acceptance criteria.
- Regexes are selection gates, not evidence of maliciousness.
- VirusTotal's report is reputation evidence, not proof of current behavior.
- DNS resolution is not performed, so a domain lookup does not automatically evaluate every resolved IP.

See [ADR-0017](decisions/0017-policy-gated-remote-threat-intelligence.md).
