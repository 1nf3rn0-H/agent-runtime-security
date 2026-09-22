# Agent Runtime Security runtime policy lifecycle

Status: Implemented for prototype
Runtime IR version: `1.4.0`
Last updated: September 22, 2026

## Boundary

ARSQuery is the authoring format. The generated runtime policy is an immutable, versioned bundle consumed by the inline hook. The normative structural contract is [`schemas/agent-runtime-security-runtime-policy.schema.json`](../schemas/agent-runtime-security-runtime-policy.schema.json); the dependency-free runtime validator in [`.agent-runtime-security/policy_ir.py`](../.agent-runtime-security/policy_ir.py) additionally enforces semantic constraints that JSON Schema cannot conveniently express, including unique rule IDs and field/operator compatibility.

The runtime IR is not intended for manual authoring.

## Activation flow

```text
ARSQuery + runtime settings
          |
          v
parse -> type-check -> lower to IR -> validate IR
                                      |
                                      v
                         write temporary file (0600)
                                      |
                         flush + fsync + atomic replace
                                      |
                                      v
                              active rules.json
```

Compilation refuses to activate a generated bundle that fails runtime validation. The temporary file is created in the destination directory, so `os.replace` does not cross filesystems. The file and containing-directory updates are flushed before activation returns where the platform supports it.

Compile and activate:

```bash
python3 .agent-runtime-security/policy_compiler.py policies/default.arsq \
  --settings .agent-runtime-security/runtime.json \
  --output .agent-runtime-security/rules.json
```

Verify that the active output is current:

```bash
python3 .agent-runtime-security/policy_compiler.py policies/default.arsq \
  --settings .agent-runtime-security/runtime.json \
  --output .agent-runtime-security/rules.json --check
```

## Load and recovery flow

For each hook process, Agent Runtime Security:

1. Rejects an active file larger than 1 MiB before parsing it.
2. Reads one byte snapshot and rejects invalid UTF-8, invalid JSON, and duplicate JSON keys.
3. Validates the IR version, top-level configuration, rules, predicates, bounds, and regular expressions.
4. Computes SHA-256 over canonical, sorted, compact JSON for the validated object.
5. Evaluates that same in-memory object; it does not reopen the active file during the decision.
6. Refreshes `<rules-path>.lkg` when a different active bundle loads successfully.

If the active bundle cannot be read or validated, the loader attempts the permission-restricted last-known-good snapshot. The recovered decision record contains:

```json
{
  "policy": {
    "ir_version": "1.4.0",
    "sha256": "...",
    "source": "policies/default.arsq",
    "language": "arsquery/2",
    "used_last_known_good": true,
    "load_warning": "invalid JSON in active policy ..."
  }
}
```

When a deny detection is emitted, `policy.bundle_sha256` and `policy.ir_version` are evidence attributes. The same provenance appears under `extensions.com.agent_runtime_security.policy`; the load warning is retained only in local diagnostic telemetry to avoid leaking local paths or parser details into product detections.

## Failure semantics

| Active bundle | LKG snapshot | Result |
|---|---|---|
| Valid and supported | Any | Use active bundle; repair or refresh LKG when its validated hash differs |
| Missing, malformed, oversized, or incompatible | Valid and supported | Use LKG and mark recovery metadata |
| Missing, malformed, oversized, or incompatible | Missing or invalid | Hook fails closed for `PreToolUse` and `PermissionRequest` |
| Valid but more permissive | Any | Use active bundle; schema validation does not establish authorization or publisher identity |

The final row is important: a canonical hash identifies the effective bundle but does not authenticate it. Signed or managed policy bundles remain a beta requirement.

## Validated constraints

- Exact runtime IR version `1.4.0`.
- Only documented top-level and nested keys.
- `allow` or `deny` default action.
- At most 1,000 rules, 32 compiled conditions per rule, 128 values per list, 4,096 characters per condition literal, and 1 MiB serialized policy size.
- Unique rule IDs and valid rule metadata.
- A message for every deny rule.
- At least one matcher per rule.
- Known fields and operators with compatible scalar/list semantics.
- Unary predicates without values and binary predicates with correctly typed values.
- Syntactically valid regular expressions.
- Only `deny` in the current detection-emission action configuration.

The JSON Schema captures the portable structural contract. Runtime validation remains authoritative for security-sensitive semantic constraints.

## Versioning

Runtime IR uses semantic versioning:

- Patch releases may tighten validation or clarify behavior without changing accepted semantics.
- Minor releases may add optional compatible fields or operators.
- Major releases may change required structure or evaluation semantics.

The prototype loader currently accepts exactly `1.4.0`. It rejects rather than guesses about forward compatibility. A future loader may accept a declared compatible minor range after conformance tests cover it. Version `1.1.0` added `process.dispatch_chain`, `1.2.0` added typed semantic targets, `1.3.0` added the now-superseded local snapshot model, and `1.4.0` adds policy-gated remote enrichment and `ANY_MATCHES` as recorded in [ADR-0017](decisions/0017-policy-gated-remote-threat-intelligence.md).

## Performance check

Run the bounded local benchmark:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benchmark_policy.py \
  --rules 1000 --samples 200
```

The report separates compilation, validation, base engine evaluation, and regex-gated target evaluation. It intentionally excludes Python process startup, provider network latency, and the complete harness round trip, which require separate measurements. Provider latency is recorded per evaluated hook event. Development results are recorded in the [engineering direction](engineering-direction.md); they are not cross-platform performance claims.

## Security limitations

- Atomic replacement prevents partial activation; it does not prevent an authorized local process from replacing the active bundle.
- The LKG snapshot provides availability, not authenticity. A process with write access to both files can change both.
- The canonical hash provides provenance and comparison, not a digital signature.
- Python regular-expression validation confirms syntax, not linear-time execution.
- A successfully validated policy can still express an undesired organizational decision. Policy review and authenticated distribution are separate controls.

See [ADR-0012](decisions/0012-validate-and-atomically-activate-runtime-policy.md) for the decision record.
