"""Validation, hashing, and atomic activation for the Agent Runtime Security runtime policy IR."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


POLICY_IR_VERSION = "1.4.0"
MAX_POLICY_BYTES = 1_048_576
MAX_RULES = 1_000
MAX_CONDITIONS = 32
MAX_LIST_VALUES = 128
MAX_LITERAL_LENGTH = 4_096
MAX_PATH_LENGTH = 4_096

RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
CATEGORY = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")
TOOL_INPUT_FIELD = re.compile(r"^tool\.input\.[A-Za-z_][A-Za-z0-9_]*$")
SCALAR_FIELDS = {
    "tool.name",
    "tool.family",
    "action.type",
    "session.cwd",
    "agent.id",
    "process.executable",
    "action.command",
}
INVOCATION_FIELDS = {
    "process.executable",
    "process.args",
    "process.dispatch_chain",
    "network.destinations",
    "network.urls",
    "file.paths",
    "git.operations",
    "git.repositories",
    "package.operations",
    "package.names",
    "threat.indicator_ids",
    "threat.verdicts",
    "threat.labels",
    "threat.sources",
    "threat.matched_targets",
}
LIST_FIELDS = {
    "process.args",
    "process.dispatch_chain",
    "network.destinations",
    "network.urls",
    "file.paths",
    "git.operations",
    "git.repositories",
    "package.operations",
    "package.names",
    "tool.targets",
    "tool.network.destinations",
    "threat.indicator_ids",
    "threat.verdicts",
    "threat.labels",
    "threat.sources",
    "threat.matched_targets",
    "tool.threat.indicator_ids",
    "tool.threat.verdicts",
    "tool.threat.labels",
    "tool.threat.sources",
    "tool.threat.matched_targets",
}
SCALAR_OPERATORS = {
    "==",
    "!=",
    "IN",
    "NOT_IN",
    "CONTAINS",
    "STARTS_WITH",
    "ENDS_WITH",
    "MATCHES",
}
LIST_OPERATORS = {"HAS_ANY", "HAS_ALL", "HAS_NONE"}
LIST_REGEX_OPERATORS = {"ANY_MATCHES"}
UNARY_OPERATORS = {"EXISTS", "NOT_EXISTS"}
ALL_OPERATORS = SCALAR_OPERATORS | LIST_OPERATORS | LIST_REGEX_OPERATORS | UNARY_OPERATORS
SEVERITIES = {"informational", "low", "medium", "high", "critical"}


class PolicyValidationError(ValueError):
    """Raised when a runtime policy is malformed or incompatible."""


@dataclass(frozen=True)
class LoadedPolicy:
    document: dict[str, Any]
    sha256: str
    source_path: Path
    used_last_known_good: bool
    load_warning: str | None = None

    def metadata(self) -> dict[str, Any]:
        compiler = self.document.get("compiler", {})
        return {
            "ir_version": self.document["policy_ir_version"],
            "sha256": self.sha256,
            "source": compiler.get("source"),
            "language": compiler.get("language"),
            "used_last_known_good": self.used_last_known_good,
            "load_warning": self.load_warning,
        }


def _fail(location: str, message: str) -> None:
    raise PolicyValidationError(f"{location}: {message}")


def _object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(location, "must be an object")
    return value


def _keys(value: dict[str, Any], location: str, allowed: set[str], required: set[str]) -> None:
    missing = required - value.keys()
    if missing:
        _fail(location, f"missing required keys: {', '.join(sorted(missing))}")
    unknown = value.keys() - allowed
    if unknown:
        _fail(location, f"unknown keys: {', '.join(sorted(str(key) for key in unknown))}")


def _string(value: Any, location: str, *, max_length: int = MAX_LITERAL_LENGTH) -> str:
    if not isinstance(value, str) or not value:
        _fail(location, "must be a non-empty string")
    if len(value) > max_length:
        _fail(location, f"exceeds {max_length} characters")
    return value


def _string_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(location, "must be a non-empty array")
    if len(value) > MAX_LIST_VALUES:
        _fail(location, f"exceeds {MAX_LIST_VALUES} values")
    for index, item in enumerate(value):
        _string(item, f"{location}[{index}]")
    return value


def _validate_regex(value: Any, location: str) -> str:
    pattern = _string(value, location)
    try:
        re.compile(pattern)
    except re.error as exc:
        _fail(location, f"invalid regular expression: {exc}")
    return pattern


def _validate_condition(value: Any, location: str) -> None:
    condition = _object(value, location)
    _keys(condition, location, {"field", "operator", "value"}, {"field", "operator"})
    field_name = _string(condition["field"], f"{location}.field", max_length=128)
    operator = _string(condition["operator"], f"{location}.operator", max_length=32)
    is_tool_input = TOOL_INPUT_FIELD.fullmatch(field_name) is not None
    if field_name not in SCALAR_FIELDS and field_name not in LIST_FIELDS and not is_tool_input:
        _fail(f"{location}.field", f"unsupported field {field_name!r}")
    if operator not in ALL_OPERATORS:
        _fail(f"{location}.operator", f"unsupported operator {operator!r}")

    if field_name in LIST_FIELDS:
        allowed = LIST_OPERATORS | LIST_REGEX_OPERATORS | UNARY_OPERATORS
    elif is_tool_input:
        allowed = ALL_OPERATORS
    else:
        allowed = SCALAR_OPERATORS | UNARY_OPERATORS
    if operator not in allowed:
        _fail(f"{location}.operator", f"{operator} is not valid for {field_name}")

    has_value = "value" in condition
    if operator in UNARY_OPERATORS:
        if has_value:
            _fail(location, f"{operator} must not define value")
        return
    if not has_value:
        _fail(location, f"{operator} requires value")
    if operator in {"IN", "NOT_IN", "HAS_ANY", "HAS_ALL", "HAS_NONE"}:
        _string_list(condition["value"], f"{location}.value")
    elif operator in {"MATCHES", "ANY_MATCHES"}:
        _validate_regex(condition["value"], f"{location}.value")
    else:
        _string(condition["value"], f"{location}.value")


def _validate_invocation(value: Any, location: str) -> None:
    invocation = _object(value, location)
    allowed = {"executables", "args_any", "args_all", "case_sensitive"}
    _keys(invocation, location, allowed, set())
    if not invocation.keys() - {"case_sensitive"}:
        _fail(location, "must define an executable or argument matcher")
    for key in ("executables", "args_any", "args_all"):
        if key in invocation:
            _string_list(invocation[key], f"{location}.{key}")
    if "case_sensitive" in invocation and not isinstance(invocation["case_sensitive"], bool):
        _fail(f"{location}.case_sensitive", "must be a boolean")


def _validate_match(value: Any, location: str) -> None:
    match = _object(value, location)
    allowed = {
        "case_sensitive",
        "conditions",
        "tool_names",
        "command_regex",
        "invocation",
    }
    _keys(match, location, allowed, set())
    if not match.keys() - {"case_sensitive"}:
        _fail(location, "must define at least one matcher")
    if "case_sensitive" in match and not isinstance(match["case_sensitive"], bool):
        _fail(f"{location}.case_sensitive", "must be a boolean")
    if "conditions" in match:
        conditions = match["conditions"]
        if not isinstance(conditions, list) or not conditions:
            _fail(f"{location}.conditions", "must be a non-empty array")
        if len(conditions) > MAX_CONDITIONS:
            _fail(f"{location}.conditions", f"exceeds {MAX_CONDITIONS} conditions")
        for index, condition in enumerate(conditions):
            _validate_condition(condition, f"{location}.conditions[{index}]")
    if "tool_names" in match:
        _string_list(match["tool_names"], f"{location}.tool_names")
    if "command_regex" in match:
        _validate_regex(match["command_regex"], f"{location}.command_regex")
    if "invocation" in match:
        _validate_invocation(match["invocation"], f"{location}.invocation")


def _validate_rule(value: Any, location: str) -> str:
    rule = _object(value, location)
    allowed = {
        "id",
        "title",
        "description",
        "severity",
        "category",
        "version",
        "action",
        "message",
        "match",
    }
    _keys(rule, location, allowed, {"id", "action", "match"})
    rule_id = _string(rule["id"], f"{location}.id", max_length=128)
    if RULE_ID.fullmatch(rule_id) is None:
        _fail(f"{location}.id", f"invalid rule id {rule_id!r}")
    action = rule["action"]
    if action not in ("allow", "deny", "audit"):
        _fail(f"{location}.action", "must be allow, deny, or audit")
    for key in ("title", "description", "version", "message"):
        if key in rule:
            _string(rule[key], f"{location}.{key}")
    if action == "deny" and "message" not in rule:
        _fail(location, "deny rule requires message")
    if "severity" in rule and rule["severity"] not in tuple(SEVERITIES):
        _fail(f"{location}.severity", f"unsupported severity {rule['severity']!r}")
    if "category" in rule:
        category = _string(rule["category"], f"{location}.category", max_length=256)
        if CATEGORY.fullmatch(category) is None:
            _fail(f"{location}.category", f"invalid category {category!r}")
    _validate_match(rule["match"], f"{location}.match")
    conditions = rule["match"].get("conditions", [])
    fields = {
        condition.get("field") for condition in conditions if isinstance(condition, dict)
    }
    if any(isinstance(field, str) and field.startswith("threat.") for field in fields):
        gates = [
            condition for condition in conditions
            if condition.get("field") == "network.destinations"
            and condition.get("operator") == "ANY_MATCHES"
        ]
        if len(gates) != 1:
            _fail(location, "process threat predicates require exactly one network.destinations ANY_MATCHES gate")
    if any(isinstance(field, str) and field.startswith("tool.threat.") for field in fields):
        gates = [
            condition for condition in conditions
            if condition.get("field") == "tool.network.destinations"
            and condition.get("operator") == "ANY_MATCHES"
        ]
        if len(gates) != 1:
            _fail(location, "tool threat predicates require exactly one tool.network.destinations ANY_MATCHES gate")
    return rule_id


def _validate_settings(policy: dict[str, Any]) -> None:
    if "trace" in policy:
        trace = _object(policy["trace"], "$.trace")
        _keys(trace, "$.trace", {"state_dir", "inject_shell_environment"}, set())
        if "state_dir" in trace:
            _string(trace["state_dir"], "$.trace.state_dir", max_length=MAX_PATH_LENGTH)
        if "inject_shell_environment" in trace and not isinstance(
            trace["inject_shell_environment"], bool
        ):
            _fail("$.trace.inject_shell_environment", "must be a boolean")
    if "telemetry" in policy:
        telemetry = _object(policy["telemetry"], "$.telemetry")
        _keys(telemetry, "$.telemetry", {"path", "include_raw_command"}, set())
        if "path" in telemetry:
            _string(telemetry["path"], "$.telemetry.path", max_length=MAX_PATH_LENGTH)
        if "include_raw_command" in telemetry and not isinstance(
            telemetry["include_raw_command"], bool
        ):
            _fail("$.telemetry.include_raw_command", "must be a boolean")
    if "detections" in policy:
        detections = _object(policy["detections"], "$.detections")
        _keys(detections, "$.detections", {"path", "emit_actions"}, set())
        if "path" in detections:
            _string(detections["path"], "$.detections.path", max_length=MAX_PATH_LENGTH)
        if "emit_actions" in detections:
            actions = _string_list(detections["emit_actions"], "$.detections.emit_actions")
            if any(action != "deny" for action in actions):
                _fail("$.detections.emit_actions", "currently supports only deny")
    if "threat_intelligence" in policy:
        threat_intelligence = _object(policy["threat_intelligence"], "$.threat_intelligence")
        allowed = {
            "enabled", "provider", "api_key_env", "timeout_ms", "failure_mode",
            "malicious_threshold", "suspicious_threshold", "max_lookups",
        }
        _keys(threat_intelligence, "$.threat_intelligence", allowed, {"enabled"})
        if not isinstance(threat_intelligence["enabled"], bool):
            _fail("$.threat_intelligence.enabled", "must be a boolean")
        if threat_intelligence["enabled"] and threat_intelligence.get("provider") != "virustotal":
            _fail("$.threat_intelligence.provider", "must be virustotal when enabled")
        if "provider" in threat_intelligence and threat_intelligence["provider"] != "virustotal":
            _fail("$.threat_intelligence.provider", "must be virustotal")
        if "api_key_env" in threat_intelligence:
            name = _string(threat_intelligence["api_key_env"], "$.threat_intelligence.api_key_env", max_length=128)
            if re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) is None:
                _fail("$.threat_intelligence.api_key_env", "must be an uppercase environment variable name")
        if "failure_mode" in threat_intelligence and threat_intelligence["failure_mode"] not in {"open", "closed"}:
            _fail("$.threat_intelligence.failure_mode", "must be open or closed")
        bounds = {
            "timeout_ms": (100, 10_000),
            "malicious_threshold": (1, 100),
            "suspicious_threshold": (1, 100),
            "max_lookups": (1, 16),
        }
        for key, (minimum, maximum) in bounds.items():
            if key not in threat_intelligence:
                continue
            number = threat_intelligence[key]
            if isinstance(number, bool) or not isinstance(number, int) or not minimum <= number <= maximum:
                _fail(f"$.threat_intelligence.{key}", f"must be an integer from {minimum} through {maximum}")


def validate_policy(policy: Any) -> dict[str, Any]:
    """Validate and return a runtime policy without mutating it."""
    document = _object(policy, "$")
    allowed = {
        "policy_ir_version",
        "trace",
        "telemetry",
        "detections",
        "threat_intelligence",
        "default_action",
        "compiler",
        "rules",
    }
    required = {"policy_ir_version", "default_action", "compiler", "rules"}
    _keys(document, "$", allowed, required)
    if document["policy_ir_version"] != POLICY_IR_VERSION:
        _fail(
            "$.policy_ir_version",
            f"unsupported version {document['policy_ir_version']!r}; expected {POLICY_IR_VERSION}",
        )
    if document["default_action"] not in ("allow", "deny"):
        _fail("$.default_action", "must be allow or deny")
    compiler = _object(document["compiler"], "$.compiler")
    _keys(compiler, "$.compiler", {"language", "source"}, {"language", "source"})
    _string(compiler["language"], "$.compiler.language", max_length=128)
    _string(compiler["source"], "$.compiler.source", max_length=MAX_PATH_LENGTH)
    _validate_settings(document)

    rules = document["rules"]
    if not isinstance(rules, list) or not rules:
        _fail("$.rules", "must be a non-empty array")
    if len(rules) > MAX_RULES:
        _fail("$.rules", f"exceeds {MAX_RULES} rules")
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        rule_id = _validate_rule(rule, f"$.rules[{index}]")
        if rule_id in seen:
            _fail(f"$.rules[{index}].id", f"duplicate rule id {rule_id!r}")
        seen.add(rule_id)
    return document


def canonical_policy_bytes(policy: dict[str, Any]) -> bytes:
    return json.dumps(policy, separators=(",", ":"), sort_keys=True).encode("utf-8")


def policy_sha256(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def last_known_good_path(path: Path) -> Path:
    return path.with_name(path.name + ".lkg")


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_policy_atomic(path: Path, policy: dict[str, Any]) -> str:
    """Validate and atomically replace a policy file with mode 0600."""
    validate_policy(policy)
    serialized = json.dumps(policy, indent=2, sort_keys=False).encode("utf-8") + b"\n"
    if len(serialized) > MAX_POLICY_BYTES:
        raise PolicyValidationError(f"$: serialized policy exceeds {MAX_POLICY_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".policy-", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(serialized)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return policy_sha256(policy)


def _read_policy(path: Path) -> tuple[dict[str, Any], str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PolicyValidationError(f"cannot stat policy {path}: {exc}") from exc
    if size > MAX_POLICY_BYTES:
        raise PolicyValidationError(f"policy {path} exceeds {MAX_POLICY_BYTES} bytes")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise PolicyValidationError(f"cannot read policy {path}: {exc}") from exc
    if len(payload) > MAX_POLICY_BYTES:
        raise PolicyValidationError(f"policy {path} exceeds {MAX_POLICY_BYTES} bytes")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PolicyValidationError(f"duplicate JSON key {key!r} in policy {path}")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyValidationError(f"invalid JSON in policy {path}: {exc}") from exc
    validate_policy(document)
    return document, policy_sha256(document)


def load_policy(path: Path, *, refresh_last_known_good: bool = True) -> LoadedPolicy:
    """Load a validated policy, falling back to its validated LKG snapshot."""
    active_error: PolicyValidationError | None = None
    try:
        document, digest = _read_policy(path)
    except PolicyValidationError as exc:
        active_error = exc
    else:
        if refresh_last_known_good:
            lkg_path = last_known_good_path(path)
            refresh = True
            try:
                _, lkg_digest = _read_policy(lkg_path)
                refresh = lkg_digest != digest
            except PolicyValidationError:
                pass
            if refresh:
                try:
                    write_policy_atomic(lkg_path, document)
                except (OSError, PolicyValidationError):
                    # A read-only policy directory must not invalidate an otherwise safe bundle.
                    pass
        return LoadedPolicy(document, digest, path, False)

    lkg_path = last_known_good_path(path)
    try:
        document, digest = _read_policy(lkg_path)
    except PolicyValidationError as lkg_error:
        raise PolicyValidationError(
            f"active policy rejected ({active_error}); last-known-good unavailable ({lkg_error})"
        ) from active_error
    return LoadedPolicy(
        document=document,
        sha256=digest,
        source_path=lkg_path,
        used_last_known_good=True,
        load_warning=str(active_error),
    )
