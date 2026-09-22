#!/usr/bin/env python3
"""Codex lifecycle hook with policy enforcement and trace propagation."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import shlex
import socket
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from correlation import ActionCorrelation, correlate_action, new_observation_id
from detection_event import build_detection_event
from policy_ir import INVOCATION_FIELDS, load_policy
from semantic_targets import (
    SemanticTargets,
    extract_process_targets,
    extract_tool_targets,
    extract_typed_tool_targets,
)
from shell_parser import (
    MAX_COMMANDS,
    Redirection,
    ShellParseError,
    ShellWord,
    parse_shell,
    walk_commands,
)
from trace_context import TraceContext, TraceRegistry
from threat_intel import (
    ThreatIntelError,
    ThreatMatches,
    VirusTotalEnricher,
    build_enricher,
    disabled_metadata,
)


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES = ROOT / ".agent-runtime-security" / "rules.json"
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
WRAPPERS = {"command", "builtin", "exec", "nohup", "time"}
UNSUPPORTED_INDIRECT_EXECUTORS = {"parallel"}
ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.DOTALL)
MISSING = object()
PREDICATE_OPERATORS = {
    "==", "!=", "IN", "NOT_IN", "CONTAINS", "STARTS_WITH", "ENDS_WITH",
    "MATCHES", "ANY_MATCHES", "HAS_ANY", "HAS_ALL", "HAS_NONE", "EXISTS", "NOT_EXISTS",
}


class PolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Invocation:
    executable: str
    argv: tuple[str, ...]
    dynamic_arguments: bool = False
    dispatch_chain: tuple[str, ...] = ()
    targets: SemanticTargets = SemanticTargets()
    threat: ThreatMatches = ThreatMatches()

    def as_dict(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "argv": list(self.argv),
            "dynamic_arguments": self.dynamic_arguments,
            "dispatch_chain": list(self.dispatch_chain),
            "targets": self.targets.as_dict(),
            "uncertain_target_fields": list(self.targets.uncertain_fields),
            "threat": self.threat.as_dict(),
        }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str).encode("utf-8")


def _classify_tool(tool_name: str) -> tuple[str, str]:
    if tool_name == "Bash":
        return "shell", "process.exec"
    if tool_name == "apply_patch":
        return "file_edit", "file.modify"
    if tool_name.startswith("mcp__"):
        return "mcp", "integration.call"
    if tool_name in {"Agent", "spawn_agent"}:
        return "agent", "agent.delegate"
    return "local_function", "tool.call"


def normalize_tool_action(event: dict[str, Any]) -> dict[str, Any]:
    """Describe a supported tool call without persisting its complete input."""
    tool_name = str(event.get("tool_name") or "unknown")
    family, action_type = _classify_tool(tool_name)

    tool_input = event.get("tool_input")
    serialized = _canonical_json(tool_input)
    if isinstance(tool_input, dict):
        input_kind = "object"
        input_keys = sorted(str(key) for key in tool_input)
    elif isinstance(tool_input, list):
        input_kind = "array"
        input_keys = []
    elif tool_input is None:
        input_kind = "null"
        input_keys = []
    else:
        input_kind = type(tool_input).__name__
        input_keys = []

    return {
        "type": action_type,
        "family": family,
        "tool_name": tool_name,
        "input": {
            "kind": input_kind,
            "keys": input_keys,
            "size_bytes": len(serialized),
            "sha256": hashlib.sha256(serialized).hexdigest(),
        },
    }


def event_for_action_correlation(
    event: dict[str, Any], context: TraceContext
) -> dict[str, Any]:
    """Remove hook-only and injected values before computing action fingerprints."""
    normalized = dict(event)
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return normalized

    normalized_input = dict(tool_input)
    if event.get("hook_event_name") == "PermissionRequest":
        normalized_input.pop("description", None)
    command = normalized_input.get("command")
    if event.get("tool_name") == "Bash" and isinstance(command, str):
        normalized_input["command"] = sanitize_injected_command(command, context)
    normalized["tool_input"] = normalized_input
    return normalized


def _strip_prefixes(
    tokens: list[ShellWord], removed_prefixes: list[str] | None = None
) -> list[ShellWord]:
    current = list(tokens)
    while current:
        while current and ENV_ASSIGNMENT.match(current[0].value):
            current.pop(0)
        if not current:
            return []

        executable = os.path.basename(current[0].value)
        if executable in WRAPPERS:
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if executable == "exec" and option == "-a" and current:
                    current.pop(0)
                elif executable == "time" and option in {"-f", "-o"} and current:
                    current.pop(0)
            continue
        if executable == "env":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current:
                value = current[0].value
                if ENV_ASSIGNMENT.match(value):
                    current.pop(0)
                    continue
                if not value.startswith("-"):
                    break
                option = current.pop(0).value
                if option == "--":
                    break
                if option in {"-S", "--split-string"}:
                    raise PolicyError("env split-string command construction is unsupported")
                if option in {"-u", "--unset", "-C", "--chdir"} and current:
                    current.pop(0)
            continue
        if executable == "sudo":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            options_with_values = {
                "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
                "-C", "--close-from", "-T", "--command-timeout", "-R", "--chroot",
                "-D", "--chdir",
            }
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option in options_with_values and current:
                    current.pop(0)
            continue
        if executable == "timeout":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            options_with_values = {"-s", "--signal", "-k", "--kill-after"}
            options_without_values = {"--preserve-status", "--foreground", "-v", "--verbose"}
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option in options_with_values:
                    if not current:
                        raise PolicyError(f"timeout option {option} requires a value")
                    current.pop(0)
                elif option in options_without_values or option.startswith(
                    ("--signal=", "--kill-after=")
                ):
                    continue
                else:
                    raise PolicyError(f"unsupported timeout option {option!r}")
            if not current:
                raise PolicyError("timeout requires a duration and command")
            current.pop(0)
            continue
        if executable == "nice":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option in {"-n", "--adjustment"}:
                    if not current:
                        raise PolicyError(f"nice option {option} requires a value")
                    current.pop(0)
                elif option.startswith("--adjustment=") or option[1:].lstrip("+").isdigit():
                    continue
                else:
                    raise PolicyError(f"unsupported nice option {option!r}")
            continue
        if executable == "setsid":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option not in {"-c", "--ctty", "-f", "--fork", "-w", "--wait"}:
                    raise PolicyError(f"unsupported setsid option {option!r}")
            continue
        if executable == "stdbuf":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option in {"-i", "--input", "-o", "--output", "-e", "--error"}:
                    if not current:
                        raise PolicyError(f"stdbuf option {option} requires a value")
                    current.pop(0)
                elif option.startswith(("-i", "-o", "-e", "--input=", "--output=", "--error=")):
                    continue
                else:
                    raise PolicyError(f"unsupported stdbuf option {option!r}")
            continue
        if executable == "chroot":
            if removed_prefixes is not None:
                removed_prefixes.append(executable)
            current.pop(0)
            while current and current[0].value.startswith("-"):
                option = current.pop(0).value
                if option == "--":
                    break
                if option == "--skip-chdir" or option.startswith(("--userspec=", "--groups=")):
                    continue
                raise PolicyError(f"unsupported chroot option {option!r}")
            if not current:
                raise PolicyError("chroot requires a new root and command")
            current.pop(0)
            continue
        break
    return current


def _xargs_command(words: list[ShellWord]) -> list[ShellWord]:
    options_with_values = {
        "-E", "--eof", "-I", "--replace", "-J", "--replace-str", "-L", "--max-lines",
        "-n", "--max-args", "-P", "--max-procs", "-R", "--max-replacements",
        "-S", "--max-chars", "-s", "--max-chars", "-d", "--delimiter", "-a", "--arg-file",
    }
    options_without_values = {
        "-0", "--null", "-o", "--open-tty", "-p", "--interactive", "-r", "--no-run-if-empty",
        "-t", "--verbose", "-x", "--exit",
    }
    index = 1
    while index < len(words):
        option = words[index].value
        if option == "--":
            return words[index + 1:]
        if not option.startswith("-") or option == "-":
            return words[index:]
        if option in options_with_values:
            index += 2
            if index > len(words):
                raise PolicyError(f"xargs option {option} requires a value")
            continue
        if option in options_without_values or option.startswith(
            ("--eof=", "--replace=", "--max-lines=", "--max-args=", "--max-procs=", "--delimiter=", "--arg-file=")
        ):
            index += 1
            continue
        if len(option) > 2 and option[:2] in {"-E", "-I", "-J", "-L", "-n", "-P", "-R", "-S", "-s", "-d"}:
            index += 1
            continue
        raise PolicyError(f"unsupported xargs option {option!r}")
    return []


def _find_exec_commands(words: list[ShellWord]) -> list[list[ShellWord]]:
    commands: list[list[ShellWord]] = []
    index = 1
    markers = {"-exec", "-execdir", "-ok", "-okdir"}
    while index < len(words):
        if words[index].value not in markers:
            index += 1
            continue
        marker = words[index].value
        start = index + 1
        end = start
        while end < len(words) and words[end].value not in {";", "+"}:
            end += 1
        if end == len(words):
            raise PolicyError(f"find {marker} action has no terminator")
        if end == start:
            raise PolicyError(f"find {marker} action has no command")
        commands.append(words[start:end])
        index = end + 1
    return commands


def _watch_command(words: list[ShellWord]) -> tuple[list[ShellWord], bool]:
    options_with_values = {"-n", "--interval"}
    options_without_values = {
        "-d", "--differences", "-g", "--chgexit", "-t", "--no-title", "-b", "--beep",
        "-e", "--errexit", "-p", "--precise", "-c", "--color",
    }
    direct = False
    index = 1
    while index < len(words):
        option = words[index].value
        if option == "--":
            index += 1
            break
        if not option.startswith("-") or option == "-":
            break
        if option in {"-x", "--exec"}:
            direct = True
            index += 1
        elif option in options_with_values:
            index += 2
            if index > len(words):
                raise PolicyError(f"watch option {option} requires a value")
        elif option in options_without_values or option.startswith("--interval="):
            index += 1
        else:
            raise PolicyError(f"unsupported watch option {option!r}")
    if index >= len(words):
        raise PolicyError("watch requires a command")
    return words[index:], direct


def _collect_command_words(
    raw_words: list[ShellWord],
    depth: int,
    invocations: list[Invocation],
    *,
    redirections: tuple[Redirection, ...] = (),
    force_dynamic_arguments: bool = False,
    dispatch_chain: tuple[str, ...] = (),
) -> None:
    if depth > 8:
        raise PolicyError("indirect execution nesting exceeds 8")
    if len(invocations) >= MAX_COMMANDS:
        raise PolicyError(f"shell input exceeds {MAX_COMMANDS} total invocations")
    removed_prefixes: list[str] = []
    words = _strip_prefixes(raw_words, removed_prefixes)
    if not words:
        return
    if words[0].dynamic or not words[0].value:
        raise PolicyError("dynamic shell executable prevents deterministic policy evaluation")
    executable = os.path.basename(words[0].value)
    argv = tuple(word.value for word in words)
    dynamic_arguments = force_dynamic_arguments or any(word.dynamic for word in words[1:])
    effective_dispatch_chain = dispatch_chain + tuple(removed_prefixes)
    targets = extract_process_targets(
        executable,
        tuple(words[1:]),
        redirections,
        force_dynamic=force_dynamic_arguments,
    )
    invocations.append(
        Invocation(
            executable=executable,
            argv=argv,
            dynamic_arguments=dynamic_arguments,
            dispatch_chain=effective_dispatch_chain,
            targets=targets,
        )
    )

    if executable in SHELLS:
        command_index: int | None = None
        for option_index, option in enumerate(argv[1:], start=1):
            if option == "--":
                break
            if option == "-c" or (
                option.startswith("-")
                and not option.startswith("--")
                and "c" in option[1:]
            ):
                command_index = option_index + 1
                break
        if command_index is not None and command_index < len(argv):
            if words[command_index - 1].dynamic:
                raise PolicyError("dynamic shell options prevent deterministic evaluation")
            if words[command_index].dynamic:
                raise PolicyError("dynamic shell -c payload prevents deterministic evaluation")
            _collect_command_string(
                argv[command_index],
                depth + 1,
                invocations,
                dispatch_chain=effective_dispatch_chain + (executable,),
            )
    elif executable == "xargs":
        indirect = _xargs_command(words)
        if indirect:
            _collect_command_words(
                indirect,
                depth + 1,
                invocations,
                force_dynamic_arguments=True,
                dispatch_chain=effective_dispatch_chain + (executable,),
            )
    elif executable == "find":
        for indirect in _find_exec_commands(words):
            expanded = [
                ShellWord(word.value, True, word.substitutions)
                if word.value == "{}"
                else word
                for word in indirect
            ]
            _collect_command_words(
                expanded,
                depth + 1,
                invocations,
                dispatch_chain=effective_dispatch_chain + (executable,),
            )
    elif executable == "watch":
        indirect, direct = _watch_command(words)
        if direct:
            _collect_command_words(
                indirect,
                depth + 1,
                invocations,
                dispatch_chain=effective_dispatch_chain + (executable,),
            )
        else:
            if any(word.dynamic for word in indirect):
                raise PolicyError("dynamic watch command prevents deterministic evaluation")
            _collect_command_string(
                " ".join(word.value for word in indirect),
                depth + 1,
                invocations,
                dispatch_chain=effective_dispatch_chain + (executable,),
            )
    elif executable == "eval":
        indirect = words[1:]
        if not indirect:
            return
        if any(word.dynamic for word in indirect):
            raise PolicyError("dynamic eval command prevents deterministic evaluation")
        _collect_command_string(
            " ".join(word.value for word in indirect),
            depth + 1,
            invocations,
            dispatch_chain=effective_dispatch_chain + (executable,),
        )
    elif executable in UNSUPPORTED_INDIRECT_EXECUTORS:
        raise PolicyError(f"indirect executor {executable!r} is unsupported")


def _collect_command_string(
    command: str,
    depth: int,
    invocations: list[Invocation],
    *,
    dispatch_chain: tuple[str, ...] = (),
) -> None:
    if depth > 8:
        raise PolicyError("shell interpreter nesting exceeds 8")
    try:
        program = parse_shell(command, depth)
    except ShellParseError as exc:
        raise PolicyError(f"cannot parse shell command: {exc}") from exc
    for parsed_command in walk_commands(program):
        _collect_command_words(
            list(parsed_command.words),
            depth,
            invocations,
            redirections=parsed_command.redirections,
            dispatch_chain=dispatch_chain,
        )


def extract_invocations(command: str, depth: int = 0) -> list[Invocation]:
    """Extract direct and known indirect invocations without executing input."""
    invocations: list[Invocation] = []
    _collect_command_string(command, depth, invocations)
    return invocations


def _semantic_target_summary(
    invocations: list[Invocation], tool_targets: list[str]
) -> dict[str, list[str]]:
    """Build a bounded, deterministic union for telemetry and detection evidence."""
    summary: dict[str, list[str]] = {}
    for invocation in invocations:
        for field_name, values in invocation.targets.as_dict().items():
            destination = summary.setdefault(field_name, [])
            for value in values:
                if value not in destination and len(destination) < 64:
                    destination.append(value)
    if tool_targets:
        summary["tool.targets"] = tool_targets[:64]
    return {field_name: values for field_name, values in summary.items() if values}


def _normal(value: str, case_sensitive: bool) -> str:
    return value if case_sensitive else value.casefold()


def _invocation_matches(invocation: Invocation, spec: dict[str, Any]) -> bool:
    case_sensitive = bool(spec.get("case_sensitive", False))
    executable = _normal(invocation.executable, case_sensitive)
    argv = [_normal(arg, case_sensitive) for arg in invocation.argv[1:]]

    executables = spec.get("executables")
    if executables is not None:
        expected = {_normal(str(item), case_sensitive) for item in executables}
        if executable not in expected:
            return False

    args_any = spec.get("args_any")
    if args_any is not None:
        expected = {_normal(str(item), case_sensitive) for item in args_any}
        if not any(arg in expected for arg in argv):
            if invocation.dynamic_arguments:
                raise PolicyError(
                    "dynamic arguments prevent deterministic policy evaluation for "
                    f"{invocation.executable}"
                )
            return False

    args_all = spec.get("args_all")
    if args_all is not None:
        expected = {_normal(str(item), case_sensitive) for item in args_all}
        if not expected.issubset(set(argv)):
            if invocation.dynamic_arguments:
                raise PolicyError(
                    "dynamic arguments prevent deterministic policy evaluation for "
                    f"{invocation.executable}"
                )
            return False
    return True


def _field_value(
    field_name: str,
    event: dict[str, Any],
    command: str,
    context: TraceContext | None,
    invocation: Invocation | None,
    tool_threat: ThreatMatches | None = None,
) -> Any:
    tool_name = event.get("tool_name")
    if field_name == "tool.name":
        return tool_name if isinstance(tool_name, str) else MISSING
    if field_name in {"tool.family", "action.type"}:
        if not isinstance(tool_name, str):
            return MISSING
        family, action_type = _classify_tool(tool_name)
        return family if field_name == "tool.family" else action_type
    if field_name == "session.cwd":
        return event.get("cwd", MISSING)
    if field_name == "agent.id":
        return context.actor_id if context is not None else event.get("agent_id", "root")
    if field_name == "action.command":
        tool_input = event.get("tool_input")
        if isinstance(tool_input, dict) and isinstance(tool_input.get("command"), str):
            return command
        return MISSING
    if field_name == "process.executable":
        return invocation.executable if invocation is not None else MISSING
    if field_name == "process.args":
        return list(invocation.argv[1:]) if invocation is not None else MISSING
    if field_name == "process.dispatch_chain":
        return list(invocation.dispatch_chain) if invocation is not None else MISSING
    if field_name in {
        "network.destinations",
        "network.urls",
        "file.paths",
        "git.operations",
        "git.repositories",
        "package.operations",
        "package.names",
    }:
        if invocation is None:
            return MISSING
        return invocation.targets.as_dict()[field_name]
    if field_name == "tool.targets":
        return list(extract_tool_targets(event))
    if field_name == "tool.network.destinations":
        return [
            value for indicator_type, value in extract_typed_tool_targets(event)
            if indicator_type in {"domain", "ip"}
        ]
    if field_name.startswith("threat."):
        if invocation is None:
            return MISSING
        return invocation.threat.as_dict()[field_name]
    if field_name.startswith("tool.threat."):
        if tool_threat is None:
            return MISSING
        process_field = field_name[len("tool."):]
        return tool_threat.as_dict()[process_field]
    if field_name.startswith("tool.input."):
        tool_input = event.get("tool_input")
        if isinstance(tool_input, dict):
            return tool_input.get(field_name[len("tool.input."):], MISSING)
        return MISSING
    raise PolicyError(f"unsupported compiled field {field_name!r}")


def _predicate_matches(predicate: dict[str, Any], actual: Any, case_sensitive: bool) -> bool:
    operator = predicate.get("operator")
    if operator not in PREDICATE_OPERATORS:
        raise PolicyError(f"unsupported compiled operator {operator!r}")
    if operator == "EXISTS":
        return actual is not MISSING
    if operator == "NOT_EXISTS":
        return actual is MISSING
    if actual is MISSING:
        return False
    expected = predicate.get("value", MISSING)
    if expected is MISSING:
        raise PolicyError(f"compiled predicate {operator} has no value")

    def normalize(item: Any) -> Any:
        return item if case_sensitive or not isinstance(item, str) else item.casefold()

    if operator in {"==", "!="}:
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        equal = normalize(actual) == normalize(expected)
        return equal if operator == "==" else not equal
    if operator in {"IN", "NOT_IN"}:
        if not isinstance(actual, str) or not isinstance(expected, list):
            return False
        contained = normalize(actual) in {normalize(item) for item in expected}
        return contained if operator == "IN" else not contained
    if operator in {"CONTAINS", "STARTS_WITH", "ENDS_WITH"}:
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        actual_string, expected_string = normalize(actual), normalize(expected)
        if operator == "CONTAINS":
            return expected_string in actual_string
        if operator == "STARTS_WITH":
            return actual_string.startswith(expected_string)
        return actual_string.endswith(expected_string)
    if operator == "MATCHES":
        if not isinstance(actual, str) or not isinstance(expected, str):
            return False
        try:
            pattern = re.compile(expected, 0 if case_sensitive else re.IGNORECASE)
            return pattern.search(actual) is not None
        except re.error as exc:
            raise PolicyError(f"invalid compiled regex: {exc}") from exc
    if operator == "ANY_MATCHES":
        if not isinstance(actual, list) or not isinstance(expected, str):
            return False
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            pattern = re.compile(expected, flags)
            return any(
                isinstance(item, str) and pattern.search(item) is not None
                for item in actual
            )
        except re.error as exc:
            raise PolicyError(f"invalid compiled regex: {exc}") from exc
    if not isinstance(actual, list) or not isinstance(expected, list):
        return False
    actual_values = {normalize(item) for item in actual if isinstance(item, str)}
    expected_values = {normalize(item) for item in expected if isinstance(item, str)}
    if operator == "HAS_ANY":
        return bool(actual_values & expected_values)
    if operator == "HAS_ALL":
        return expected_values.issubset(actual_values)
    return actual_values.isdisjoint(expected_values)


def _compiled_conditions_match(
    conditions: list[dict[str, Any]],
    event: dict[str, Any],
    command: str,
    invocations: list[Invocation],
    context: TraceContext | None,
    case_sensitive: bool,
    tool_threat: ThreatMatches,
) -> tuple[bool, Invocation | None]:
    process_conditions = []
    for condition in conditions:
        if not isinstance(condition, dict) or not isinstance(condition.get("field"), str):
            raise PolicyError("compiled condition must be an object with a field")
        field_name = condition["field"]
        if field_name in INVOCATION_FIELDS:
            process_conditions.append(condition)
        else:
            actual = _field_value(
                field_name, event, command, context, None, tool_threat
            )
            if not _predicate_matches(condition, actual, case_sensitive):
                return False, None
    if process_conditions:
        for invocation in invocations:
            results: list[bool] = []
            uncertainties: list[bool] = []
            for condition in process_conditions:
                field_name = condition["field"]
                matched = _predicate_matches(
                    condition,
                    _field_value(field_name, event, command, context, invocation),
                    case_sensitive,
                )
                results.append(matched)
                uncertain = (
                    field_name == "process.args" and invocation.dynamic_arguments
                ) or field_name in invocation.targets.uncertain_fields or (
                    field_name.startswith("threat.") and invocation.threat.uncertain
                )
                uncertainties.append(uncertain)
            if all(results):
                for condition, uncertain in zip(process_conditions, uncertainties):
                    if uncertain and condition["operator"] == "HAS_NONE":
                        subject = (
                            "arguments" if condition["field"] == "process.args"
                            else condition["field"]
                        )
                        raise PolicyError(
                            f"dynamic {subject} prevent deterministic policy evaluation for "
                            f"{invocation.executable}"
                        )
                return True, invocation
            if any(
                not matched and not uncertain
                for matched, uncertain in zip(results, uncertainties)
            ):
                continue
            for condition, matched, uncertain in zip(
                process_conditions, results, uncertainties
            ):
                if (
                    not matched
                    and uncertain
                    and condition["operator"] not in {"EXISTS", "NOT_EXISTS"}
                ):
                    subject = (
                        "arguments" if condition["field"] == "process.args"
                        else condition["field"]
                    )
                    raise PolicyError(
                        f"dynamic {subject} prevent deterministic policy evaluation for "
                        f"{invocation.executable}"
                    )
        return False, None
    return True, None


def rule_matches(
    rule: dict[str, Any],
    event: dict[str, Any],
    command: str,
    invocations: list[Invocation],
    context: TraceContext | None = None,
    tool_threat: ThreatMatches = ThreatMatches(),
) -> tuple[bool, Invocation | None]:
    match = rule.get("match")
    if not isinstance(match, dict):
        raise PolicyError(f"rule {rule.get('id', '<unknown>')} has no match object")

    conditions = match.get("conditions")
    matched_invocation: Invocation | None = None
    if conditions is not None:
        if not isinstance(conditions, list) or not conditions:
            raise PolicyError("compiled conditions must be a non-empty list")
        conditions_matched, matched_invocation = _compiled_conditions_match(
            conditions,
            event,
            command,
            invocations,
            context,
            bool(match.get("case_sensitive", False)),
            tool_threat,
        )
        if not conditions_matched:
            return False, None

    tool_names = match.get("tool_names")
    if tool_names is not None and event.get("tool_name") not in tool_names:
        return False, None

    raw_regex = match.get("command_regex")
    if raw_regex is not None:
        try:
            if re.search(str(raw_regex), command) is None:
                return False, None
        except re.error as exc:
            raise PolicyError(f"invalid regex in rule {rule.get('id')}: {exc}") from exc

    invocation_spec = match.get("invocation")
    if invocation_spec is not None:
        if not isinstance(invocation_spec, dict):
            raise PolicyError(f"rule {rule.get('id')} invocation must be an object")
        if not any(_invocation_matches(item, invocation_spec) for item in invocations):
            return False, None
    return True, matched_invocation


def _regex_selected(values: list[str], condition: dict[str, Any], case_sensitive: bool) -> list[str]:
    pattern = str(condition.get("value", ""))
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        compiled = re.compile(pattern, flags)
        return [value for value in values if compiled.search(value) is not None]
    except re.error as exc:
        raise PolicyError(f"invalid compiled regex: {exc}") from exc


def _typed_network_values(values: list[str]) -> list[tuple[str, str]]:
    typed: list[tuple[str, str]] = []
    for value in values:
        try:
            ipaddress.ip_address(value)
            typed.append(("ip", value))
        except ValueError:
            typed.append(("domain", value))
    return typed


def _enrich_policy_gated_targets(
    *,
    event: dict[str, Any],
    command: str,
    rules: list[dict[str, Any]],
    invocations: list[Invocation],
    context: TraceContext | None,
    enricher: VirusTotalEnricher,
) -> tuple[list[Invocation], ThreatMatches]:
    enriched_invocations: list[Invocation] = []
    for invocation in invocations:
        selected: list[str] = []
        for rule in rules:
            match = rule.get("match", {})
            conditions = match.get("conditions", []) if isinstance(match, dict) else []
            if not isinstance(conditions, list) or not any(
                isinstance(condition, dict)
                and str(condition.get("field", "")).startswith("threat.")
                for condition in conditions
            ):
                continue
            gate = next(
                (
                    condition for condition in conditions
                    if isinstance(condition, dict)
                    and condition.get("field") == "network.destinations"
                    and condition.get("operator") == "ANY_MATCHES"
                ),
                None,
            )
            if gate is None:
                continue
            non_threat = [
                condition for condition in conditions
                if not str(condition.get("field", "")).startswith("threat.")
            ]
            eligible, _ = _compiled_conditions_match(
                non_threat,
                event,
                command,
                [invocation],
                context,
                bool(match.get("case_sensitive", False)),
                ThreatMatches(),
            )
            if eligible:
                selected.extend(
                    _regex_selected(
                        list(invocation.targets.network_destinations),
                        gate,
                        bool(match.get("case_sensitive", False)),
                    )
                )
        threat = enricher.lookup(
            _typed_network_values(list(dict.fromkeys(selected))),
            uncertain="network.destinations" in invocation.targets.uncertain_fields,
        )
        enriched_invocations.append(replace(invocation, threat=threat))

    typed_tool_targets = [
        item for item in extract_typed_tool_targets(event) if item[0] in {"domain", "ip"}
    ]
    tool_destinations = [value for _, value in typed_tool_targets]
    selected_tool: list[str] = []
    for rule in rules:
        match = rule.get("match", {})
        conditions = match.get("conditions", []) if isinstance(match, dict) else []
        if not isinstance(conditions, list) or not any(
            isinstance(condition, dict)
            and str(condition.get("field", "")).startswith("tool.threat.")
            for condition in conditions
        ):
            continue
        gate = next(
            (
                condition for condition in conditions
                if isinstance(condition, dict)
                and condition.get("field") == "tool.network.destinations"
                and condition.get("operator") == "ANY_MATCHES"
            ),
            None,
        )
        if gate is None:
            continue
        non_threat = [
            condition for condition in conditions
            if not str(condition.get("field", "")).startswith("tool.threat.")
        ]
        eligible, _ = _compiled_conditions_match(
            non_threat,
            event,
            command,
            invocations,
            context,
            bool(match.get("case_sensitive", False)),
            ThreatMatches(),
        )
        if eligible:
            selected_tool.extend(
                _regex_selected(
                    tool_destinations,
                    gate,
                    bool(match.get("case_sensitive", False)),
                )
            )
    selected_set = set(selected_tool)
    tool_threat = enricher.lookup(
        [item for item in typed_tool_targets if item[1] in selected_set]
    )
    return enriched_invocations, tool_threat


def evaluate(
    event: dict[str, Any],
    policy: dict[str, Any],
    context: TraceContext | None = None,
    threat_enricher: VirusTotalEnricher | None = None,
) -> dict[str, Any]:
    tool_input = event.get("tool_input") or {}
    command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
    if not isinstance(command, str):
        raise PolicyError("tool_input.command must be a string")

    invocations = extract_invocations(command) if event.get("tool_name") == "Bash" else []
    tool_targets = list(extract_tool_targets(event))
    tool_threat = ThreatMatches()
    semantic_targets = _semantic_target_summary(invocations, tool_targets)
    if event.get("hook_event_name") not in {"PreToolUse", "PermissionRequest"}:
        return {
            "action": "allow",
            "matched_rules": [],
            "command": command,
            "invocations": [item.as_dict() for item in invocations],
            "tool_targets": tool_targets,
            "semantic_targets": semantic_targets,
            "tool_threat": tool_threat.as_dict(),
            "threat_intelligence": disabled_metadata(),
            "reason": "Observed by Agent Runtime Security.",
        }

    if threat_enricher is not None:
        try:
            invocations, tool_threat = _enrich_policy_gated_targets(
                event=event,
                command=command,
                rules=policy.get("rules", []),
                invocations=invocations,
                context=context,
                enricher=threat_enricher,
            )
        except ThreatIntelError as exc:
            raise PolicyError(f"remote threat intelligence failed: {exc}") from exc
    threat_metadata = (
        threat_enricher.metadata() if threat_enricher is not None else disabled_metadata()
    )

    matches: list[dict[str, Any]] = []
    for rule in policy.get("rules", []):
        matched, matched_invocation = rule_matches(
            rule, event, command, invocations, context, tool_threat
        )
        if matched:
            action = str(rule.get("action", "deny"))
            if action not in {"allow", "deny", "audit"}:
                raise PolicyError(f"unsupported action {action!r} in rule {rule.get('id')}")
            rule_target_summary: dict[str, list[str]] = {}
            if matched_invocation is not None:
                rule_target_summary = _semantic_target_summary([matched_invocation], [])
                rule_threat_matches = matched_invocation.threat.as_dict()
            else:
                rule_threat_matches = {}
            conditions = rule.get("match", {}).get("conditions", [])
            uses_tool_target_context = any(
                isinstance(condition, dict)
                and (
                    condition.get("field") == "tool.targets"
                    or condition.get("field") == "tool.network.destinations"
                    or str(condition.get("field", "")).startswith("tool.threat.")
                )
                for condition in conditions
            )
            if uses_tool_target_context:
                rule_target_summary.update(_semantic_target_summary([], tool_targets))
            if any(
                isinstance(condition, dict)
                and str(condition.get("field", "")).startswith("tool.threat.")
                for condition in conditions
            ):
                rule_threat_matches = tool_threat.as_dict()
            matches.append(
                {
                    "id": str(rule.get("id", "unnamed")),
                    "action": action,
                    "message": str(rule.get("message", "Matched Agent Runtime Security policy.")),
                    "title": str(rule.get("title", rule.get("id", "unnamed"))),
                    "description": str(rule.get("description", "")),
                    "severity": str(rule.get("severity", "medium")),
                    "category": str(rule.get("category", "policy.rule_match")),
                    "version": str(rule.get("version", "1")),
                    "semantic_targets": rule_target_summary,
                    "threat_matches": rule_threat_matches,
                }
            )

    denying = [item for item in matches if item["action"] == "deny"]
    allowing = [item for item in matches if item["action"] == "allow"]
    action = (
        "deny"
        if denying
        else "allow"
        if allowing
        else str(policy.get("default_action", "allow"))
    )
    if action not in {"allow", "deny"}:
        raise PolicyError("default_action must be allow or deny")
    return {
        "action": action,
        "matched_rules": matches,
        "command": command,
        "invocations": [item.as_dict() for item in invocations],
        "tool_targets": tool_targets,
        "semantic_targets": semantic_targets,
        "tool_threat": tool_threat.as_dict(),
        "threat_intelligence": threat_metadata,
        "reason": (
            denying[0]["message"]
            if denying
            else allowing[0]["message"]
            if allowing
            else "Allowed by Agent Runtime Security policy."
        ),
    }


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def _deny_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _permission_deny_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason,
            },
        }
    }


def _allow_with_command(command: str, original_input: Any) -> dict[str, Any]:
    updated_input = dict(original_input) if isinstance(original_input, dict) else {}
    updated_input["command"] = command
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated_input,
        }
    }


def _trace_state_dir(policy: dict[str, Any]) -> Path:
    configured = policy.get("trace", {}).get("state_dir", ".agent-runtime-security/state")
    path = Path(configured)
    return path if path.is_absolute() else ROOT / path


def _event_actor_id(event: dict[str, Any]) -> str | None:
    for field in ("agent_id", "subagent_id", "actor_id"):
        value = event.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def _trace_context(event: dict[str, Any], policy: dict[str, Any]) -> TraceContext:
    registry = TraceRegistry(_trace_state_dir(policy))
    session_id = str(event.get("session_id") or "")
    if event.get("hook_event_name") == "SubagentStart":
        return registry.register_subagent(
            session_id=session_id,
            agent_id=str(event.get("agent_id") or ""),
            agent_type=str(event.get("agent_type") or "subagent"),
            parent_actor_id=event.get("parent_agent_id"),
        )
    return registry.get(session_id=session_id, actor_id=_event_actor_id(event))


def inject_trace_environment(
    command: str,
    context: TraceContext,
    tool_call_id: str | None,
    action_correlation: ActionCorrelation,
) -> str:
    assignments = " ".join(
        f"{name}={shlex.quote(value)}"
        for name, value in context.environment(
            tool_call_id,
            action_correlation.action_id,
            action_correlation.request_fingerprint,
        ).items()
    )
    return f"export {assignments}; {command}"


def sanitize_injected_command(command: str, context: TraceContext) -> str:
    """Recover the original command and guarantee correlation tokens are redacted."""
    sanitized = command
    if command.startswith("export ARS_TRACE_ID="):
        prefix, separator, original = command.partition("; ")
        expected_names = (
            "ARS_TRACE_ID=",
            "ARS_TRACE_TOKEN=",
            "ARS_ACTOR_ID=",
            "ARS_ACTOR_TOKEN=",
            "ARS_CODEX_SESSION_ID=",
            "ARS_ACTION_ID=",
            "ARS_REQUEST_FINGERPRINT=",
        )
        if separator and all(name in prefix for name in expected_names):
            sanitized = original
    return sanitized.replace(context.trace_token, "[ARS_TRACE_TOKEN]").replace(
        context.actor_token, "[ARS_ACTOR_TOKEN]"
    )


def run(event: dict[str, Any], rules_path: Path) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    started = time.perf_counter_ns()
    loaded_policy = load_policy(rules_path)
    policy = loaded_policy.document
    policy_metadata = loaded_policy.metadata()
    hook_event_name = event.get("hook_event_name")
    context = _trace_context(event, policy)
    try:
        threat_enricher = build_enricher(policy.get("threat_intelligence"))
    except ThreatIntelError as exc:
        raise PolicyError(f"invalid threat-intelligence configuration: {exc}") from exc
    result = evaluate(event, policy, context, threat_enricher)
    observation_id = new_observation_id()
    normalized_action: dict[str, Any] | None = None
    action_correlation: ActionCorrelation | None = None
    if event.get("tool_name"):
        correlation_event = event_for_action_correlation(event, context)
        normalized_action = normalize_tool_action(correlation_event)
        action_correlation = correlate_action(correlation_event, context, normalized_action)

    output: dict[str, Any] | None = None
    injected_command: str | None = None
    if hook_event_name == "PreToolUse":
        if result["action"] == "deny":
            output = _deny_output(result["reason"])
        elif (
            event.get("tool_name") == "Bash"
            and bool(policy.get("trace", {}).get("inject_shell_environment", True))
        ):
            injected_command = inject_trace_environment(
                result["command"], context, event.get("tool_use_id"), action_correlation
            )
            output = _allow_with_command(injected_command, event.get("tool_input"))
    elif hook_event_name == "PermissionRequest" and result["action"] == "deny":
        output = _permission_deny_output(result["reason"])

    telemetry_config = policy.get("telemetry", {})
    telemetry_path = Path(telemetry_config.get("path", ".agent-runtime-security/events.jsonl"))
    if not telemetry_path.is_absolute():
        telemetry_path = ROOT / telemetry_path
    include_raw = bool(telemetry_config.get("include_raw_command", True))
    is_shell_action = event.get("tool_name") == "Bash"
    telemetry_command = (
        sanitize_injected_command(result["command"], context) if is_shell_action else ""
    )
    telemetry_invocations = (
        [item.as_dict() for item in extract_invocations(telemetry_command)]
        if is_shell_action
        else result["invocations"]
    )
    latency_us = (time.perf_counter_ns() - started) // 1000
    record = {
        "schema_version": "1.0",
        "observation_id": observation_id,
        "timestamp_unix_ns": time.time_ns(),
        "latency_us": latency_us,
        "policy": policy_metadata,
        "threat_intelligence": result["threat_intelligence"],
        "event": {
            "hook_event_name": hook_event_name,
            "session_id": event.get("session_id"),
            "turn_id": event.get("turn_id"),
            "tool_use_id": event.get("tool_use_id"),
            "tool_name": event.get("tool_name"),
            "cwd": event.get("cwd"),
            "model": event.get("model"),
            "permission_mode": event.get("permission_mode"),
            "agent_id": event.get("agent_id"),
            "agent_type": event.get("agent_type"),
        },
        "identity": {
            "username": getpass.getuser(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "hook_pid": os.getpid(),
            "parent_pid": os.getppid(),
            "hostname": socket.gethostname(),
            "platform": platform.system().lower(),
        },
        "command": telemetry_command if include_raw and is_shell_action else None,
        "trace": context.telemetry(),
        "trace_environment_injected": injected_command is not None,
        "action": normalized_action,
        "action_correlation": (
            action_correlation.telemetry() if action_correlation is not None else None
        ),
        "invocations": telemetry_invocations,
        "semantic_targets": result["semantic_targets"],
        "decision": (
            result["action"]
            if hook_event_name in {"PreToolUse", "PermissionRequest"}
            else "observe"
        ),
        "matched_rules": result["matched_rules"],
    }
    _append_jsonl(telemetry_path, record)

    detection_config = policy.get("detections", {})
    emitted_actions = detection_config.get("emit_actions", ["deny"])
    if (
        hook_event_name in {"PreToolUse", "PermissionRequest"}
        and result["action"] == "deny"
        and "deny" in emitted_actions
        and normalized_action is not None
        and action_correlation is not None
    ):
        detection_path = Path(detection_config.get("path", ".agent-runtime-security/detections.jsonl"))
        if not detection_path.is_absolute():
            detection_path = ROOT / detection_path
        for matched_rule in result["matched_rules"]:
            if matched_rule["action"] != result["action"]:
                continue
            detection = build_detection_event(
                event=event,
                context=context,
                action=normalized_action,
                action_correlation=action_correlation,
                rule=matched_rule,
                reason=result["reason"],
                latency_us=latency_us,
                policy_metadata=policy_metadata,
                semantic_targets=matched_rule.get("semantic_targets", {}),
                threat_intelligence=result["threat_intelligence"],
                threat_matches=matched_rule.get("threat_matches", {}),
            )
            _append_jsonl(detection_path, detection)
    return output, record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--explain", action="store_true", help="print the full decision for local replay")
    args = parser.parse_args()

    event: dict[str, Any] = {}
    try:
        event = json.load(sys.stdin)
        output, record = run(event, args.rules)
    except Exception as exc:  # A PreToolUse policy failure must not become an execution bypass.
        reason = f"Agent Runtime Security hook evaluation failed: {exc}"
        if event.get("hook_event_name") == "PreToolUse":
            print(json.dumps(_deny_output(f"{reason}; failed closed"), separators=(",", ":")))
        elif event.get("hook_event_name") == "PermissionRequest":
            print(
                json.dumps(
                    _permission_deny_output(f"{reason}; failed closed"),
                    separators=(",", ":"),
                )
            )
        else:
            print(json.dumps({"systemMessage": reason}, separators=(",", ":")))
        return 0

    if args.explain:
        print(json.dumps({"hook_output": output, "telemetry": record}, indent=2, sort_keys=True))
    elif output is not None:
        print(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
