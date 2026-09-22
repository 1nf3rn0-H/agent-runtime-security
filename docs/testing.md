# Testing AiDR

Status: Current prototype  
Last updated: September 22, 2026

## 1. Run the isolated smoke test

From the repository root:

```bash
python3 scripts/smoke_test.py
```

The smoke test uses a temporary directory and makes no network request. It verifies:

- a proposed `ping evil.com` action is denied;
- exactly one schema-v1.2 detection is generated;
- the detection contains an evidence chain but not the raw command;
- an allowed Python process and its child inherit identical trace context; and
- `PreToolUse` and `PostToolUse` share one exact `action_id`.

The equivalent product health workflow is:

```bash
./aidr doctor --deep
```

Temporary policy, state, observations, and detections are deleted automatically.

## 2. Run the regression suite

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s tests -v
```

All tests should report `OK`.

The compiler suite also stress-checks 500-rule compilation, bounded literals and condition counts, invalid operator/field combinations, and end-to-end pre-tool enforcement of newly compiled fields and operators. To check that the generated runtime policy matches its source, run:

```bash
python3 .aidr/policy_compiler.py policies/default.aidrql \
  --settings .aidr/runtime.json \
  --output .aidr/rules.json --check
```

The CLI equivalents are `./aidr policy check` and `./aidr policy compile`.

Runtime-policy tests additionally cover unknown fields, incompatible versions, duplicate JSON keys and rule IDs, invalid predicates, oversized bundles, deterministic hashes, permission-restricted atomic activation, last-known-good recovery, and fail-closed behavior when both active and recovery bundles are invalid.

Threat-intelligence tests use injected transports and make no real network requests. They cover domain/IP normalization, fixed VirusTotal endpoints, API-key secrecy, response bounds and validation, verdict thresholds, per-event memoization, open/closed failure behavior, regex-gated process and MCP lookup, zero calls for non-matches, and zero calls from post-tool observations.

Shell-parser tests cover command and process substitutions, subshells, combined shell flags, execution prefixes, known indirect dispatchers, dispatch provenance, typed network/file/Git/package targets, redirections, quoting, comments, dynamic values, resource bounds, unsupported control flow, and 500 deterministic randomized malformed inputs. End-to-end compiler tests also cover normalized tool targets and semantic fail-closed behavior. See the [parser coverage and limitations](shell-parser.md).

Run the maximum-rule policy benchmark separately from the regression suite:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/benchmark_policy.py \
  --rules 1000 --samples 200
```

This reports compilation, validation, base engine evaluation, and regex-gated target evaluation. It does not measure provider network latency, Python startup, or the complete harness round trip.

## 3. Exercise individual hook contracts

These commands send JSON directly to the hook. They do not execute the command inside `tool_input`:

```bash
python3 .aidr/codex_hook.py --explain < examples/pretooluse-ping-evil.json
python3 .aidr/codex_hook.py --explain < examples/permissionrequest-ping-evil.json
```

The first response should contain `permissionDecision: "deny"`. The second should contain `decision.behavior: "deny"` under the `PermissionRequest` response shape.

Direct contract tests use the configured repository-local state and diagnostic files. Prefer the isolated smoke test when you do not want to create local runtime artifacts.

## 4. Run a safe live Codex test

Start a new Codex session in this repository. Open `/hooks`, review the changed project hook definition, and trust it. Changed non-managed hooks are skipped until their current definition is trusted.

Before the test, remove only the old sentinel if it exists:

```bash
rm -f .aidr/SHELL_WAS_REACHED
```

Ask Codex to run this exact command without substitution:

```text
Run `PATH=/Users/harshmehta/Desktop/Projects/AiDR/tests/fixtures:$PATH ping evil.com` exactly as written. Do not substitute another command.
```

The prepended path selects `tests/fixtures/ping`, a harmless executable that only creates the sentinel and exits. No real `ping` program or network request can run through that command.

Expected result:

- Codex reports that `PreToolUse` blocked the command.
- `.aidr/SHELL_WAS_REACHED` does not exist.
- `.aidr/detections.jsonl` gains one `blocked` detection.

Verify:

```bash
test ! -e .aidr/SHELL_WAS_REACHED && echo "PASS: shell was not reached"
tail -n 1 .aidr/detections.jsonl | python3 -m json.tool
```

In the detection, check `schema_version`, `correlation`, `evidence_chains`, and `response`. The response action should be `blocked` with enforcement point `pre_execution`.

## 5. Test an allowed control

Ask Codex to run:

```text
Run `printf '%s\n' evil.com` exactly as written.
```

This mentions the domain but does not invoke `ping`, so the semantic rule should allow it. The command should execute, diagnostic observations should contain matching pre/post `action_id` values, and the detection file should not gain a new event.

## Troubleshooting

- If no hook status appears, start a new session and inspect `/hooks`.
- If the hook is marked changed or untrusted, review and trust its current hash.
- If the smoke test fails, run the full regression suite for the precise failing contract.
- If the live sentinel exists, enforcement failed and the result should be treated as a security defect.
