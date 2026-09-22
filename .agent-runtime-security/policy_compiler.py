"""Compiler from ARSQuery authoring rules to the deterministic runtime policy IR."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MODULE_DIR = str(Path(__file__).resolve().parent)
if MODULE_DIR not in sys.path:
    sys.path.insert(0, MODULE_DIR)

from policy_ir import (  # noqa: E402 - local script module path is established above
    LIST_FIELDS,
    LIST_OPERATORS,
    LIST_REGEX_OPERATORS,
    MAX_CONDITIONS,
    MAX_LIST_VALUES,
    MAX_LITERAL_LENGTH,
    MAX_RULES,
    POLICY_IR_VERSION,
    RULE_ID,
    SCALAR_FIELDS,
    SCALAR_OPERATORS,
    TOOL_INPUT_FIELD,
    UNARY_OPERATORS,
    PolicyValidationError,
    validate_policy,
    write_policy_atomic,
)


LANGUAGE_VERSION = "arsquery/2"
MAX_SOURCE_BYTES = 262_144
CONDITION = re.compile(
    r"^(WHEN|AND)\s+([a-z][a-z0-9_.]*)\s+"
    r"(NOT_EXISTS|STARTS_WITH|ENDS_WITH|NOT_IN|ANY_MATCHES|HAS_ANY|HAS_ALL|HAS_NONE|"
    r"CONTAINS|MATCHES|EXISTS|IS|==|!=|IN)(?:\s+(.+))?$",
    re.IGNORECASE,
)
class CompileError(ValueError):
    pass


@dataclass(frozen=True)
class SourceCondition:
    field_name: str
    operator: str
    value: Any
    line_number: int


@dataclass
class SourceRule:
    rule_id: str
    line_number: int
    title: str | None = None
    description: str | None = None
    severity: str = "medium"
    category: str = "policy.rule_match"
    version: str = "1"
    action: str | None = None
    message: str | None = None
    case_sensitive: bool = False
    conditions: list[SourceCondition] = field(default_factory=list)


@dataclass(frozen=True)
class SourcePolicy:
    default_action: str
    rules: tuple[SourceRule, ...]


def _error(line_number: int, message: str) -> CompileError:
    return CompileError(f"line {line_number}: {message}")


def _literal(raw: str, line_number: int) -> Any:
    try:
        return ast.literal_eval(raw)
    except (SyntaxError, ValueError) as exc:
        raise _error(line_number, f"invalid literal {raw!r}") from exc


def _string_value(raw: str, line_number: int, keyword: str) -> str:
    value = _literal(raw, line_number)
    if not isinstance(value, str) or not value:
        raise _error(line_number, f"{keyword} requires a non-empty quoted string")
    return value


def _boolean_value(raw: str, line_number: int) -> bool:
    normalized = raw.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise _error(line_number, "CASE_SENSITIVE must be true or false")


def _condition_value(operator: str, raw: str, line_number: int) -> Any:
    if operator in UNARY_OPERATORS:
        if raw:
            raise _error(line_number, f"{operator} does not accept a value")
        return None
    if not raw:
        raise _error(line_number, f"{operator} requires a value")
    if len(raw) > MAX_LITERAL_LENGTH:
        raise _error(line_number, "condition literal is too long")
    value = _literal(raw, line_number)
    if operator in {"IN", "NOT_IN", "HAS_ANY", "HAS_ALL", "HAS_NONE"}:
        if not isinstance(value, (list, tuple)) or not value:
            raise _error(line_number, f"{operator} requires a non-empty list")
        if len(value) > MAX_LIST_VALUES:
            raise _error(line_number, f"{operator} exceeds {MAX_LIST_VALUES} values")
        if not all(isinstance(item, str) and item for item in value):
            raise _error(line_number, f"{operator} accepts only non-empty strings")
        return list(value)
    if operator == "IS" and isinstance(value, (list, tuple)):
        if not value:
            raise _error(line_number, "IS requires a non-empty value or list")
        if len(value) > MAX_LIST_VALUES:
            raise _error(line_number, f"IS exceeds {MAX_LIST_VALUES} values")
        if not all(isinstance(item, str) and item for item in value):
            raise _error(line_number, "IS accepts only non-empty strings")
        return list(value)
    if not isinstance(value, str) or not value:
        raise _error(line_number, f"{operator} requires a non-empty quoted string")
    return value


def parse_policy(source: str) -> SourcePolicy:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise CompileError(f"policy exceeds {MAX_SOURCE_BYTES} bytes")
    default_action = "allow"
    default_seen = False
    rules: list[SourceRule] = []
    current: SourceRule | None = None

    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        keyword, _, remainder = line.partition(" ")
        upper = keyword.upper()

        if current is None:
            if upper == "DEFAULT":
                if default_seen or rules:
                    raise _error(line_number, "DEFAULT must appear once before all rules")
                value = remainder.strip().casefold()
                if value not in {"allow", "deny"}:
                    raise _error(line_number, "DEFAULT must be ALLOW or DENY")
                default_action = value
                default_seen = True
                continue
            if upper == "RULE":
                if len(rules) >= MAX_RULES:
                    raise _error(line_number, f"policy exceeds {MAX_RULES} rules")
                rule_id = remainder.strip()
                if not RULE_ID.fullmatch(rule_id):
                    raise _error(line_number, f"invalid rule id {rule_id!r}")
                current = SourceRule(rule_id=rule_id, line_number=line_number)
                continue
            raise _error(line_number, "expected DEFAULT or RULE")

        if upper == "END":
            if remainder.strip():
                raise _error(line_number, "END does not accept a value")
            if current.action is None:
                raise _error(current.line_number, f"rule {current.rule_id} has no THEN action")
            if not current.conditions:
                raise _error(current.line_number, f"rule {current.rule_id} has no conditions")
            if current.action == "deny" and not current.message:
                raise _error(current.line_number, f"deny rule {current.rule_id} requires MESSAGE")
            rules.append(current)
            current = None
            continue

        condition_match = CONDITION.fullmatch(line)
        if condition_match:
            conjunction, field_name, operator, raw_value = condition_match.groups()
            if conjunction.upper() == "AND" and not current.conditions:
                raise _error(line_number, "the first condition must start with WHEN")
            if conjunction.upper() == "WHEN" and current.conditions:
                raise _error(line_number, "subsequent conditions must start with AND")
            field_name = (
                "tool.input." + field_name[len("tool.input."):]
                if field_name.lower().startswith("tool.input.")
                else field_name.casefold()
            )
            operator = operator.upper()
            if (
                field_name not in SCALAR_FIELDS
                and field_name not in LIST_FIELDS
                and TOOL_INPUT_FIELD.fullmatch(field_name) is None
            ):
                raise _error(line_number, f"unsupported field {field_name!r}")
            if len(current.conditions) >= MAX_CONDITIONS:
                raise _error(line_number, f"rule exceeds {MAX_CONDITIONS} conditions")
            current.conditions.append(
                SourceCondition(
                    field_name=field_name,
                    operator=operator,
                    value=_condition_value(operator, raw_value or "", line_number),
                    line_number=line_number,
                )
            )
            continue

        if upper == "TITLE":
            current.title = _string_value(remainder, line_number, "TITLE")
        elif upper == "DESCRIPTION":
            current.description = _string_value(remainder, line_number, "DESCRIPTION")
        elif upper == "MESSAGE":
            current.message = _string_value(remainder, line_number, "MESSAGE")
        elif upper == "SEVERITY":
            severity = remainder.strip().casefold()
            if severity not in {"informational", "low", "medium", "high", "critical"}:
                raise _error(line_number, f"unsupported severity {severity!r}")
            current.severity = severity
        elif upper == "CATEGORY":
            category = remainder.strip()
            if not re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", category):
                raise _error(line_number, f"invalid category {category!r}")
            current.category = category
        elif upper == "VERSION":
            current.version = _string_value(remainder, line_number, "VERSION")
        elif upper == "CASE":
            mode = remainder.strip().casefold()
            if mode not in {"sensitive", "insensitive"}:
                raise _error(line_number, "CASE must be SENSITIVE or INSENSITIVE")
            current.case_sensitive = mode == "sensitive"
        elif upper == "CASE_SENSITIVE":
            current.case_sensitive = _boolean_value(remainder.strip(), line_number)
        elif upper == "THEN":
            action_text, separator, message_text = remainder.strip().partition(" ")
            action = action_text.casefold()
            if action not in {"allow", "deny", "audit"}:
                raise _error(line_number, f"unsupported action {action!r}")
            if separator:
                if action != "deny":
                    raise _error(line_number, "only THEN DENY accepts an inline message")
                if current.message is not None:
                    raise _error(line_number, "deny message is already defined")
                current.message = _string_value(message_text.strip(), line_number, "THEN DENY")
            current.action = action
        else:
            raise _error(line_number, f"unexpected statement {keyword!r}")

    if current is not None:
        raise _error(current.line_number, f"rule {current.rule_id} is missing END")
    if not rules:
        raise CompileError("policy contains no rules")
    seen: set[str] = set()
    duplicates: set[str] = set()
    for rule in rules:
        if rule.rule_id in seen:
            duplicates.add(rule.rule_id)
        seen.add(rule.rule_id)
    if duplicates:
        raise CompileError(f"duplicate rule ids: {', '.join(sorted(duplicates))}")
    return SourcePolicy(default_action=default_action, rules=tuple(rules))


def compile_rule(rule: SourceRule) -> dict[str, Any]:
    predicates: list[dict[str, Any]] = []

    for condition in rule.conditions:
        name, operator, value = condition.field_name, condition.operator, condition.value
        is_list = name in LIST_FIELDS
        is_tool_input = TOOL_INPUT_FIELD.fullmatch(name) is not None

        # ARSQuery/2 keeps authoring independent of runtime scalar/list details.
        # Legacy operators remain accepted so existing policies do not break.
        if operator == "IS":
            if is_list or (is_tool_input and isinstance(value, list)):
                operator = "HAS_ANY"
                value = value if isinstance(value, list) else [value]
            elif isinstance(value, list):
                operator = "IN"
            else:
                operator = "=="
        elif operator == "MATCHES" and is_list:
            operator = "ANY_MATCHES"
        elif operator == "CONTAINS" and is_list:
            operator = "ANY_MATCHES"
            value = re.escape(value)
        allowed = (
            SCALAR_OPERATORS | LIST_OPERATORS | UNARY_OPERATORS
            if is_tool_input
            else LIST_OPERATORS | LIST_REGEX_OPERATORS | UNARY_OPERATORS
            if is_list
            else SCALAR_OPERATORS | UNARY_OPERATORS
        )
        if operator not in allowed:
            raise _error(condition.line_number, f"operator {operator} is not valid for {name}")
        if operator in {"MATCHES", "ANY_MATCHES"}:
            try:
                re.compile(value)
            except re.error as exc:
                raise _error(condition.line_number, f"invalid regex: {exc}") from exc
        predicate = {"field": name, "operator": operator}
        if operator not in UNARY_OPERATORS:
            predicate["value"] = value
        predicates.append(predicate)

    compiled: dict[str, Any] = {
        "id": rule.rule_id,
        "title": rule.title or rule.rule_id,
        "severity": rule.severity,
        "category": rule.category,
        "version": rule.version,
        "action": rule.action,
        "match": {"case_sensitive": rule.case_sensitive, "conditions": predicates},
    }
    if rule.description:
        compiled["description"] = rule.description
    if rule.message:
        compiled["message"] = rule.message
    return compiled


def compile_policy(source: str, settings: dict[str, Any], source_name: str) -> dict[str, Any]:
    if not isinstance(settings, dict):
        raise CompileError("runtime settings must be a JSON object")
    reserved = {"policy_ir_version", "rules", "default_action", "compiler"}
    if reserved & settings.keys():
        raise CompileError(
            "runtime settings must not define rules, default_action, compiler, or policy_ir_version"
        )
    parsed = parse_policy(source)
    output = {"policy_ir_version": POLICY_IR_VERSION, **settings}
    output["default_action"] = parsed.default_action
    output["compiler"] = {
        "language": LANGUAGE_VERSION,
        "source": source_name,
    }
    output["rules"] = [compile_rule(rule) for rule in parsed.rules]
    try:
        validate_policy(output)
    except PolicyValidationError as exc:
        raise CompileError(f"generated runtime policy is invalid: {exc}") from exc
    return output


def _write_atomic(path: Path, policy: dict[str, Any]) -> None:
    try:
        write_policy_atomic(path, policy)
    except (OSError, PolicyValidationError) as exc:
        raise CompileError(f"cannot activate policy: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="fail if output is not current")
    args = parser.parse_args()

    try:
        source = args.source.read_text(encoding="utf-8")
        settings = json.loads(args.settings.read_text(encoding="utf-8"))
        compiled = compile_policy(source, settings, str(args.source))
    except (OSError, json.JSONDecodeError, CompileError) as exc:
        parser.error(str(exc))

    if args.check:
        try:
            existing = json.loads(args.output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            print(f"stale: {args.output} is missing or invalid", file=sys.stderr)
            return 1
        if existing != compiled:
            print(f"stale: recompile {args.source}", file=sys.stderr)
            return 1
        print(f"current: {args.output}")
        return 0

    try:
        _write_atomic(args.output, compiled)
    except CompileError as exc:
        parser.error(str(exc))
    print(f"compiled {len(compiled['rules'])} rules to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
