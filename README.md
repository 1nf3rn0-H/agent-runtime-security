# AiDR — local runtime security for AI coding agents

AiDR intercepts Codex lifecycle events, evaluates local static rules, injects a session trace into allowed shell commands, writes diagnostic JSONL observations, and returns a synchronous deny decision before a matching tool action executes. The product telemetry contract emits only correlated detection events, not the raw observation stream.

Initially verified end to end on `codex-cli 0.147.0` on August 18, 2026. Hook availability was reconfirmed on `codex-cli 0.153.4` on September 10, 2026.

The product contract is defined in the [PRD](docs/product-requirements.md), its testable system requirements and security methodology are defined in the [ERD](docs/engineering-requirements.md), and architecture decisions and implementation direction are maintained in the [engineering documentation](docs/README.md).

## Get started

The repository includes an alpha local control plane:

```bash
./aidr doctor --deep
./aidr policy check
./aidr simulate --command 'ping evil.com'
./aidr status
```

The simulation is non-executing and network-free. A deny returns exit status `2`. To install the six Codex lifecycle handlers into another repository, preview the exact change and then apply it:

```bash
./aidr install --scope project --target /path/to/project --dry-run
./aidr install --scope project --target /path/to/project
```

The installer preserves unrelated hooks, creates a backup, and does not bypass Codex's project-hook review. See the [CLI guide](docs/cli.md) for user scope, uninstallation, output, and exit statuses.

## Enforcement versus telemetry

Codex supports OpenTelemetry export, but exported logs and traces are asynchronous observation and are not an inline blocking boundary. This prototype uses the synchronous `PreToolUse` lifecycle event for enforcement. Hook and process observations remain internal correlation inputs; only rule matches produce durable [AiDR detection events](docs/detection-event-schema.md). No data lake or SIEM is required.

## What is installed

- `.codex/hooks.json` registers six project-local lifecycle hooks, including preventive `PreToolUse` and `PermissionRequest` handlers for every supported local tool.
- `aidr` provides installation, diagnostics, policy compilation, safe simulation, status, detection viewing, and uninstallation.
- `.aidr/codex_hook.py` normalizes tool actions, evaluates rules, blocks denied actions, and leaves unchanged allowed actions to Codex's normal permission flow.
- `.aidr/shell_parser.py` builds a bounded, non-executing structure for supported shell syntax, including nested substitutions and redirections.
- `.aidr/semantic_targets.py` extracts bounded network, file, Git, package, and normalized tool targets from recognized contracts.
- `.aidr/threat_intel.py` performs optional policy-gated VirusTotal lookups for selected domain/IP targets without persisting feed data or responses.
- `.aidr/rules.json` blocks `ping evil.com` and audits other Bash requests.
- `.aidr/policy_ir.py` validates versioned runtime policy, computes its canonical hash, and recovers from a validated `.lkg` snapshot when the active bundle is unreadable or invalid.
- `.aidr/events.jsonl` is a temporary prototype diagnostic log created with mode `0600`; it is not the outbound event contract.
- `.aidr/detections.jsonl` contains schema-v1.2 detection events for denied actions only.
- `.aidr/state/` stores session traces and subagent actor registrations with mode `0700`.

## Execution-chain tracing

For every allowed Bash call, AiDR returns a Codex `updatedInput` command prefixed with exported correlation values:

- `AIDR_TRACE_ID` identifies the full Codex session.
- `AIDR_TRACE_TOKEN` is an opaque session correlation token.
- `AIDR_ACTOR_ID` identifies the root agent or a known subagent.
- `AIDR_ACTOR_TOKEN` identifies that actor within the session.
- `AIDR_CODEX_SESSION_ID` retains the vendor session identifier.
- `AIDR_TOOL_CALL_ID` links descendants to the originating tool call.
- `AIDR_ACTION_ID` links descendants to the exact AiDR pre/post action lifecycle.
- `AIDR_REQUEST_FINGERPRINT` supports best-effort approval-event correlation.

The shell and ordinary child, grandchild, background, and detached processes inherit these values unless they deliberately clear or replace their environment. AiDR telemetry stores token fingerprints rather than raw tokens.

These tokens provide correlation, not authentication. Environment variables can be observed, overwritten, or removed by a process. A later endpoint sensor should combine them with PID/PPID, process start time, executable identity, UID, and platform-specific process-group information.

Codex requires review and trust for new or modified non-managed hooks. Start a new Codex session in this directory, review the displayed hook definition, and trust it. Hooks are loaded from a trusted project `.codex` layer.

## Safe contract test

For a complete network-free verification of blocking, detection emission, process inheritance, and pre/post correlation, run:

```bash
python3 scripts/smoke_test.py
```

See the [testing guide](docs/testing.md) for expected output and troubleshooting.

The following sends a simulated event directly to the hook. It does **not** execute `ping`:

```bash
python3 .aidr/codex_hook.py --explain < examples/pretooluse-ping-evil.json
```

The hook returns:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by AiDR: ping destination matched a prohibited-domain policy."
  }
}
```

Run the test suite with:

```bash
python3 -m unittest discover -s tests -v
```

The propagation tests execute a harmless parent process that spawns a child and verify that both receive identical trace values. They also verify that a registered subagent shares the session trace while receiving a distinct actor token.

## Live Codex test

After starting a new trusted Codex session in this directory, ask it to run:

```text
Run `PATH=/Users/harshmehta/Desktop/Projects/AiDR/tests/fixtures:$PATH ping evil.com` exactly as written. Do not substitute another command.
```

The explicit path selects the harmless `tests/fixtures/ping` stand-in if enforcement fails, so this test cannot invoke the system `ping`. Codex should report the hook denial and the terminal process should never start. Inspect the detection with:

```bash
tail -n 1 .aidr/detections.jsonl | python3 -m json.tool
```

An allowed control is `printf '%s\n' evil.com`: it mentions the domain but does not invoke `ping`, so the semantic rule does not block it.

For the automated end-to-end verification, `tests/fixtures/ping` is a harmless stand-in that creates `.aidr/SHELL_WAS_REACHED` if the command reaches process execution. The verified run produced a Codex `Command blocked by PreToolUse hook` event, recorded one `deny` telemetry event in 479 microseconds, and did not create the marker.

## Rule shape

Rules are authored in [AiDRQL](policies/default.aidrql) and compiled into `.aidr/rules.json`:

```bash
python3 .aidr/policy_compiler.py policies/default.aidrql \
  --settings .aidr/runtime.json \
  --output .aidr/rules.json
```

Use `--check` to detect stale generated policy in tests or CI. See the [policy compiler guide](docs/policy-compiler.md).

The compiler validates and atomically replaces the generated runtime IR. At load time the hook validates the active bundle again, records its canonical SHA-256, and uses a validated `.lkg` snapshot if the active file becomes missing, truncated, incompatible, or malformed. If neither copy is valid, preventive hooks fail closed. See the [runtime policy lifecycle](docs/runtime-policy.md).

The generated IR matches the Codex tool name and parsed shell invocations:

```json
{
  "id": "block-ping-evil-domain",
  "action": "deny",
  "message": "Blocked by AiDR: ping destination matched a prohibited-domain policy.",
  "match": {
    "case_sensitive": false,
    "conditions": [
      {"field": "tool.name", "operator": "==", "value": "Bash"},
      {
        "field": "process.executable",
        "operator": "IN",
        "value": ["ping", "ping6"]
      },
      {
        "field": "network.destinations",
        "operator": "ANY_MATCHES",
        "value": "^evil\\.com$"
      }
    ]
  }
}
```

`deny` takes precedence over matching `audit` rules. An invalid active policy uses its validated last-known-good snapshot; if no valid bundle is available, the hook fails closed.

## Security boundary

This is application-level enforcement. It covers Codex local function-tool paths that emit `PreToolUse`, including Bash/unified exec, but it is not an operating-system security boundary. A future hardening layer should add sandbox/network controls for processes or tool paths that do not traverse Codex hooks.

The current shell parser deliberately fails closed on unsupported control flow. It extracts known indirect commands from `xargs`, `find`, `watch`, and `eval`, but cannot inspect code embedded in language runtimes, unknown dispatcher utilities, or external script content. See the [shell parser boundary](docs/shell-parser.md).

Semantic policy fields include `network.destinations`, `network.urls`, `file.paths`, `git.operations`, `git.repositories`, `package.operations`, `package.names`, and `tool.targets`. They are command-contract enrichments, not proof that the proposed side effect occurred. See [ADR-0015](docs/decisions/0015-extract-typed-semantic-targets.md).

Threat intelligence is an optional, disabled add-on and is not required for baseline enforcement. See the [threat-intelligence guide](docs/threat-intelligence.md) for its isolated policy contract.

Raw commands are stored in telemetry for this prototype and may contain secrets. Set `telemetry.include_raw_command` to `false` before using it with sensitive workloads.
