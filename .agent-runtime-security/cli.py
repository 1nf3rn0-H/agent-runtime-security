"""Agent Runtime Security local control plane: install, validate, simulate, and inspect."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codex_hook import evaluate
from policy_compiler import CompileError, compile_policy
from policy_ir import PolicyValidationError, load_policy, policy_sha256, write_policy_atomic


PRODUCT_VERSION = "0.3.0-alpha"
ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / ".agent-runtime-security"
DEFAULT_SOURCE = ROOT / "policies" / "default.arsq"
DEFAULT_SETTINGS = CORE / "runtime.json"
DEFAULT_RULES = CORE / "rules.json"
DEFAULT_HOOKS = ROOT / ".codex" / "hooks.json"
HOOK = CORE / "codex_hook.py"
SMOKE_TEST = ROOT / "scripts" / "smoke_test.py"
MANAGED_EVENTS = {
    "SessionStart": (None, "Agent Runtime Security is starting session tracing"),
    "SubagentStart": (None, "Agent Runtime Security is linking the subagent trace"),
    "PreToolUse": ("*", "Agent Runtime Security is checking the pending tool action"),
    "PermissionRequest": ("*", "Agent Runtime Security is checking the permission request"),
    "PostToolUse": ("*", "Agent Runtime Security is recording tool completion"),
    "SessionEnd": (None, "Agent Runtime Security is finalizing session telemetry"),
}


class CliError(RuntimeError):
    pass


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"status": self.status, "name": self.name, "detail": self.detail}


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid JSON in {path}: {exc}") from exc


def _runtime_path(value: Any, default: str) -> Path:
    path = Path(str(value or default))
    return path if path.is_absolute() else ROOT / path


def _load_settings(path: Path) -> dict[str, Any]:
    value = _read_json(path)
    if not isinstance(value, dict):
        raise CliError(f"runtime settings must be a JSON object: {path}")
    return value


def _compile(source_path: Path, settings_path: Path, output_path: Path, *, check: bool) -> dict[str, Any]:
    try:
        source = source_path.read_text(encoding="utf-8")
        settings = _load_settings(settings_path)
        try:
            source_name = str(source_path.resolve().relative_to(ROOT))
        except ValueError:
            source_name = str(source_path)
        compiled = compile_policy(source, settings, source_name)
    except (OSError, CompileError) as exc:
        raise CliError(str(exc)) from exc
    if check:
        existing = _read_json(output_path)
        if existing != compiled:
            raise CliError(f"compiled policy is stale: run `./agent-runtime-security policy compile`")
        return compiled
    try:
        write_policy_atomic(output_path, compiled)
    except (OSError, PolicyValidationError) as exc:
        raise CliError(f"cannot activate policy: {exc}") from exc
    return compiled


def _hook_command() -> str:
    return " ".join(
        shlex.quote(value)
        for value in (sys.executable, str(HOOK), "--rules", str(DEFAULT_RULES))
    )


def _hook_group(event: str) -> dict[str, Any]:
    matcher, message = MANAGED_EVENTS[event]
    group: dict[str, Any] = {
        "hooks": [
            {
                "type": "command",
                "command": _hook_command(),
                "timeout": 3,
                "statusMessage": message,
            }
        ]
    }
    if matcher is not None:
        group["matcher"] = matcher
    return group


def _is_agent_runtime_security_handler(handler: Any) -> bool:
    if not isinstance(handler, dict):
        return False
    command = handler.get("command")
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return any(
        Path(token).name == "codex_hook.py"
        and Path(token).parent.name == ".agent-runtime-security"
        for token in tokens
    )


def _remove_agent_runtime_security_groups(document: dict[str, Any]) -> int:
    hooks = document.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    removed = 0
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        retained_groups: list[Any] = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                retained_groups.append(group)
                continue
            handlers = group["hooks"]
            retained_handlers = [item for item in handlers if not _is_agent_runtime_security_handler(item)]
            removed += len(handlers) - len(retained_handlers)
            if retained_handlers:
                retained = dict(group)
                retained["hooks"] = retained_handlers
                retained_groups.append(retained)
        if retained_groups:
            hooks[event] = retained_groups
        else:
            hooks.pop(event, None)
    return removed


def _merged_hooks(existing: Any) -> dict[str, Any]:
    if existing is None:
        document: dict[str, Any] = {}
    elif isinstance(existing, dict):
        document = json.loads(json.dumps(existing))
    else:
        raise CliError("hooks.json must contain a JSON object")
    document.setdefault("description", "Lifecycle hooks for this Codex configuration layer.")
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise CliError("hooks.json field `hooks` must be an object")
    _remove_agent_runtime_security_groups(document)
    for event in MANAGED_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise CliError(f"hooks.json event {event!r} must be an array")
        groups.append(_hook_group(event))
    return document


def _atomic_json(path: Path, document: dict[str, Any]) -> Path | None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    if path.exists():
        # Microseconds keep consecutive install/uninstall operations from
        # selecting the same backup name.
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = path.with_name(f"{path.name}.agent-runtime-security-backup-{timestamp}")
        shutil.copy2(path, backup)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".agent-runtime-security-hooks-", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return backup


def _hooks_path(scope: str, target: Path | None) -> Path:
    if scope == "user":
        if target is not None:
            raise CliError("--target is valid only with --scope project")
        return Path.home() / ".codex" / "hooks.json"
    project = (target or Path.cwd()).resolve()
    if not project.is_dir():
        raise CliError(f"project target is not a directory: {project}")
    return project / ".codex" / "hooks.json"


def command_install(args: argparse.Namespace) -> int:
    path = _hooks_path(args.scope, args.target)
    existing = _read_json(path) if path.exists() else None
    document = _merged_hooks(existing)
    if args.dry_run:
        print(json.dumps({"path": str(path), "configuration": document}, indent=2))
        return 0
    backup = _atomic_json(path, document)
    print(f"installed Agent Runtime Security Codex hooks: {path}")
    if backup is not None:
        print(f"backup: {backup}")
    if args.scope == "project":
        print("next: start a new Codex session, review /hooks, and trust this project hook definition")
    return 0


def command_uninstall(args: argparse.Namespace) -> int:
    path = _hooks_path(args.scope, args.target)
    if not path.exists():
        print(f"no hooks file: {path}")
        return 0
    document = _read_json(path)
    if not isinstance(document, dict):
        raise CliError("hooks.json must contain a JSON object")
    removed = _remove_agent_runtime_security_groups(document)
    if args.dry_run:
        print(json.dumps({"path": str(path), "removed_handlers": removed, "configuration": document}, indent=2))
        return 0
    if removed == 0:
        print(f"Agent Runtime Security hooks were not installed in {path}")
        return 0
    backup = _atomic_json(path, document)
    print(f"removed {removed} Agent Runtime Security hook handlers from {path}")
    if backup is not None:
        print(f"backup: {backup}")
    return 0


def _policy_checks() -> list[Check]:
    checks: list[Check] = []
    try:
        loaded = load_policy(DEFAULT_RULES)
        checks.append(Check("pass", "runtime policy", f"IR {loaded.document['policy_ir_version']} sha256={loaded.sha256[:16]}…"))
    except Exception as exc:
        checks.append(Check("fail", "runtime policy", str(exc)))
        return checks
    try:
        compiled = _compile(DEFAULT_SOURCE, DEFAULT_SETTINGS, DEFAULT_RULES, check=True)
        checks.append(Check("pass", "compiled policy", f"{len(compiled['rules'])} rules are current"))
    except CliError as exc:
        checks.append(Check("fail", "compiled policy", str(exc)))
    mode = stat.S_IMODE(DEFAULT_RULES.stat().st_mode)
    status = "pass" if mode & 0o022 == 0 else "fail"
    checks.append(Check(status, "policy permissions", f"mode {mode:04o}"))
    return checks


def _hook_checks(path: Path) -> list[Check]:
    if not path.exists():
        return [Check("fail", "Codex hooks", f"not installed at {path}")]
    try:
        document = _read_json(path)
    except CliError as exc:
        return [Check("fail", "Codex hooks", str(exc))]
    hooks = document.get("hooks", {}) if isinstance(document, dict) else {}
    installed: set[str] = set()
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            if any(
                isinstance(group, dict)
                and isinstance(group.get("hooks"), list)
                and any(_is_agent_runtime_security_handler(handler) for handler in group["hooks"])
                for group in groups
            ):
                installed.add(event)
    missing = set(MANAGED_EVENTS) - installed
    if missing:
        return [Check("fail", "Codex hooks", f"missing Agent Runtime Security events: {', '.join(sorted(missing))}")]
    return [Check("pass", "Codex hooks", f"{len(installed)} lifecycle events installed at {path}")]


def _storage_checks(policy: dict[str, Any]) -> list[Check]:
    checks: list[Check] = []
    paths = {
        "diagnostic observations": _runtime_path(policy.get("telemetry", {}).get("path"), ".agent-runtime-security/events.jsonl"),
        "detections": _runtime_path(policy.get("detections", {}).get("path"), ".agent-runtime-security/detections.jsonl"),
        "trace state": _runtime_path(policy.get("trace", {}).get("state_dir"), ".agent-runtime-security/state"),
    }
    for name, path in paths.items():
        parent = path if name == "trace state" else path.parent
        writable = parent.exists() and os.access(parent, os.W_OK)
        checks.append(Check("pass" if writable else "fail", name, f"{'writable' if writable else 'not writable'}: {path}"))
    return checks


def command_doctor(args: argparse.Namespace) -> int:
    checks: list[Check] = []
    version = sys.version_info
    checks.append(Check("pass" if version >= (3, 10) else "fail", "Python", sys.version.split()[0]))
    codex = shutil.which("codex")
    if codex:
        try:
            result = subprocess.run([codex, "--version"], capture_output=True, text=True, timeout=3, check=False)
            detail = (result.stdout or result.stderr).strip() or codex
            checks.append(Check("pass" if result.returncode == 0 else "warn", "Codex CLI", detail))
        except (OSError, subprocess.TimeoutExpired) as exc:
            checks.append(Check("warn", "Codex CLI", str(exc)))
    else:
        checks.append(Check("warn", "Codex CLI", "not found on PATH; hook files can still be validated"))
    checks.extend(_policy_checks())
    try:
        policy = load_policy(DEFAULT_RULES).document
        checks.extend(_storage_checks(policy))
        threat = policy.get("threat_intelligence", {})
        checks.append(Check("pass", "threat intelligence", "optional add-on disabled" if not threat.get("enabled") else "optional add-on enabled"))
    except Exception:
        pass
    hooks_path = args.hooks or DEFAULT_HOOKS
    checks.extend(_hook_checks(hooks_path.resolve()))
    if args.deep:
        result = subprocess.run(
            [sys.executable, str(SMOKE_TEST)], capture_output=True, text=True, check=False
        )
        detail = "isolated smoke test passed" if result.returncode == 0 else (result.stderr or result.stdout).strip()
        checks.append(Check("pass" if result.returncode == 0 else "fail", "deep self-test", detail))
    checks.append(Check("warn", "hook trust", "project hook trust is verified interactively with Codex /hooks"))
    if args.json:
        print(json.dumps({"version": PRODUCT_VERSION, "checks": [item.as_dict() for item in checks]}, indent=2))
    else:
        for item in checks:
            print(f"{item.status.upper():4}  {item.name}: {item.detail}")
    return 1 if any(item.status == "fail" for item in checks) else 0


def command_policy(args: argparse.Namespace) -> int:
    policy = _compile(args.source, args.settings, args.output, check=args.policy_command == "check")
    verb = "current" if args.policy_command == "check" else "compiled"
    print(f"{verb}: {len(policy['rules'])} rules, IR {policy['policy_ir_version']}, sha256={policy_sha256(policy)}")
    return 0


def _simulation_event(args: argparse.Namespace) -> dict[str, Any]:
    if args.event is not None:
        value = _read_json(args.event)
        if not isinstance(value, dict):
            raise CliError("simulation event must be a JSON object")
        return value
    return {
        "hook_event_name": "PreToolUse",
        "session_id": "agent-runtime-security-simulation",
        "turn_id": "simulation-turn",
        "tool_use_id": "simulation-tool",
        "cwd": str(Path.cwd()),
        "tool_name": "Bash",
        "tool_input": {"command": args.command},
    }


def command_simulate(args: argparse.Namespace) -> int:
    policy = load_policy(args.rules).document
    event = _simulation_event(args)
    result = evaluate(event, policy)
    output = {
        "decision": result["action"],
        "reason": result["reason"],
        "matched_rules": result["matched_rules"],
        "semantic_targets": result["semantic_targets"],
        "invocations": result["invocations"],
        "network_requests": 0,
        "side_effects": 0,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 2 if result["action"] == "deny" else 0


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CliError(f"invalid JSONL at {path}:{line_number}: {exc}") from exc
            if isinstance(value, dict):
                records.append(value)
    except OSError as exc:
        raise CliError(f"cannot read {path}: {exc}") from exc
    return records


def command_detections(args: argparse.Namespace) -> int:
    policy = load_policy(args.rules).document
    path = _runtime_path(policy.get("detections", {}).get("path"), ".agent-runtime-security/detections.jsonl")
    records = _read_jsonl(path)[-args.limit :]
    if args.json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return 0
    if not records:
        print(f"no detections in {path}")
        return 0
    for record in records:
        detection = record.get("detection", {})
        response = record.get("response", {})
        print(
            f"{record.get('emitted_at', '?')}  {detection.get('severity', '?').upper():8}  "
            f"{response.get('action', '?'):7}  {detection.get('title', '?')}  "
            f"event={record.get('event_id', '?')}"
        )
    return 0


def command_status(args: argparse.Namespace) -> int:
    loaded = load_policy(args.rules)
    policy = loaded.document
    detection_path = _runtime_path(policy.get("detections", {}).get("path"), ".agent-runtime-security/detections.jsonl")
    telemetry_path = _runtime_path(policy.get("telemetry", {}).get("path"), ".agent-runtime-security/events.jsonl")
    detections = _read_jsonl(detection_path)
    observations = _read_jsonl(telemetry_path)
    hooks = _hook_checks((args.hooks or DEFAULT_HOOKS).resolve())[0]
    status = {
        "version": PRODUCT_VERSION,
        "policy": {
            "ir_version": policy["policy_ir_version"],
            "sha256": loaded.sha256,
            "rule_count": len(policy["rules"]),
            "used_last_known_good": loaded.used_last_known_good,
        },
        "adapter": {"name": "codex", "hooks": hooks.as_dict()},
        "threat_intelligence": {
            "enabled": bool(policy.get("threat_intelligence", {}).get("enabled", False))
        },
        "storage": {
            "observation_count": len(observations),
            "detection_count": len(detections),
            "last_observation_at": observations[-1].get("timestamp_unix_ns") if observations else None,
            "last_detection_at": detections[-1].get("emitted_at") if detections else None,
        },
    }
    print(json.dumps(status, indent=2, sort_keys=True))
    return 1 if hooks.status == "fail" else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-runtime-security", description=__doc__)
    parser.add_argument("--version", action="version", version=f"Agent Runtime Security {PRODUCT_VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)

    install = commands.add_parser("install", help="merge Agent Runtime Security into Codex hooks.json")
    install.add_argument("--scope", choices=("project", "user"), default="project")
    install.add_argument("--target", type=Path)
    install.add_argument("--dry-run", action="store_true")
    install.set_defaults(function=command_install)

    uninstall = commands.add_parser("uninstall", help="remove only Agent Runtime Security hook handlers")
    uninstall.add_argument("--scope", choices=("project", "user"), default="project")
    uninstall.add_argument("--target", type=Path)
    uninstall.add_argument("--dry-run", action="store_true")
    uninstall.set_defaults(function=command_uninstall)

    doctor = commands.add_parser("doctor", help="check adapter, policy, storage, and runtime health")
    doctor.add_argument("--hooks", type=Path)
    doctor.add_argument("--deep", action="store_true", help="also run the isolated smoke test")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(function=command_doctor)

    policy = commands.add_parser("policy", help="compile or verify ARSQuery")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    for name in ("compile", "check"):
        item = policy_commands.add_parser(name)
        item.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
        item.add_argument("--settings", type=Path, default=DEFAULT_SETTINGS)
        item.add_argument("--output", type=Path, default=DEFAULT_RULES)
        item.set_defaults(function=command_policy)

    simulate = commands.add_parser("simulate", help="evaluate without executing a tool or contacting providers")
    source = simulate.add_mutually_exclusive_group(required=True)
    source.add_argument("--command")
    source.add_argument("--event", type=Path)
    simulate.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    simulate.set_defaults(function=command_simulate)

    detections = commands.add_parser("detections", help="show recent detection events")
    detections.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    detections.add_argument("--limit", type=_positive_integer, default=20)
    detections.add_argument("--json", action="store_true")
    detections.set_defaults(function=command_detections)

    status = commands.add_parser("status", help="show machine-readable local product status")
    status.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    status.add_argument("--hooks", type=Path)
    status.set_defaults(function=command_status)
    return parser


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.function(args))
    except (CliError, PolicyValidationError, OSError) as exc:
        print(f"agent-runtime-security: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
