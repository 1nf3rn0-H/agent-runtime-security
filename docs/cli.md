# Agent Runtime Security local CLI

Status: Alpha
Last updated: September 22, 2026

The repository-root `agent-runtime-security` command is the local control plane for the Codex adapter. It does not require installation into Python and its baseline commands make no network requests.

## Quick start

From this repository:

```bash
./agent-runtime-security doctor --deep
./agent-runtime-security policy check
./agent-runtime-security simulate --command 'ping evil.com'
./agent-runtime-security status
./agent-runtime-security detections
```

`simulate` evaluates a proposed action without starting a shell, executing the command, or invoking an optional remote enrichment provider. Exit status `2` means the simulated action was denied; `0` means it was allowed.

## Install the Codex adapter

Preview a project installation:

```bash
./agent-runtime-security install --scope project --target /path/to/project --dry-run
```

Install it:

```bash
./agent-runtime-security install --scope project --target /path/to/project
```

For all repositories using the current user configuration:

```bash
./agent-runtime-security install --scope user
```

Installation merges six Agent Runtime Security lifecycle handlers into `hooks.json`: `SessionStart`, `SubagentStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, and `SessionEnd`. Existing non-Agent Runtime Security handlers are preserved. Repeated installation is idempotent. An existing file is copied to a timestamped `hooks.json.agent-runtime-security-backup-*` file before replacement, and the resulting configuration uses mode `0600`.

Project hooks must be reviewed and trusted in Codex. Start a fresh session, open `/hooks`, and confirm that the command and policy paths are expected. The alpha installer intentionally does not bypass that trust step.

The installed hook command points to this checkout's absolute `.agent-runtime-security/codex_hook.py` path. Keep the checkout in place; reinstall after moving it. Packaging the adapter independently of a checkout is a later milestone.

## Remove the adapter

Preview or remove only the Agent Runtime Security-owned handlers:

```bash
./agent-runtime-security uninstall --scope project --target /path/to/project --dry-run
./agent-runtime-security uninstall --scope project --target /path/to/project
```

Unrelated handlers and hook groups remain intact, and an existing file is backed up before replacement.

## Policy workflow

ARSQuery is the authoring format; the generated JSON file is the runtime policy:

```bash
./agent-runtime-security policy check
./agent-runtime-security policy compile
```

`check` fails if the generated IR differs from the source and runtime settings. `compile` validates the source and atomically activates the generated bundle while maintaining the last-known-good policy.

Custom paths are supported with `--source`, `--settings`, and `--output`.

## Diagnostics and output

- `doctor` checks Python, Codex availability, policy validity and freshness, file permissions, local storage, and hook registration. `--deep` adds the isolated sentinel smoke test; `--json` provides structured output.
- `status` prints the policy hash and rule count, adapter health, optional-enrichment state, and local observation/detection counts as JSON.
- `detections --limit 20` prints recent detection summaries. Add `--json` for the full local records.
- `simulate --event event.json` evaluates a complete synthetic hook payload instead of a single shell command.

Common exit statuses are:

| Status | Meaning |
|---:|---|
| `0` | Command completed, or simulation allowed |
| `1` | Validation, configuration, health, or I/O failure |
| `2` | Simulation produced a deny decision |

Threat-intelligence enrichment remains an optional, disabled policy feature. It is not contacted by `doctor`, `status`, policy compilation, or simulation.
