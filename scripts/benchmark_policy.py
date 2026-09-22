#!/usr/bin/env python3
"""Measure compiler, validator, and engine latency for a bounded policy bundle."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / ".agent-runtime-security"))

from codex_hook import evaluate  # noqa: E402
from policy_compiler import compile_policy  # noqa: E402
from policy_ir import MAX_RULES, validate_policy  # noqa: E402


def percentile(samples: list[float], percent: int) -> float:
    ordered = sorted(samples)
    index = min(len(ordered) - 1, max(0, (len(ordered) * percent + 99) // 100 - 1))
    return ordered[index]


def measure(operation: Callable[[], object], samples: int) -> dict[str, float]:
    for _ in range(10):
        operation()
    durations: list[float] = []
    for _ in range(samples):
        started = time.perf_counter_ns()
        operation()
        durations.append((time.perf_counter_ns() - started) / 1_000_000)
    return {
        "p50_ms": statistics.median(durations),
        "p95_ms": percentile(durations, 95),
        "p99_ms": percentile(durations, 99),
        "max_ms": max(durations),
    }


def policy_source(rule_count: int) -> str:
    return "DEFAULT ALLOW\n" + "".join(
        f'RULE benchmark-{index}\nWHEN tool.name == "tool-{index}"\nTHEN AUDIT\nEND\n'
        for index in range(rule_count)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=int, default=MAX_RULES)
    parser.add_argument("--samples", type=int, default=200)
    parser.add_argument("--engine-budget-ms", type=float, default=10.0)
    args = parser.parse_args()
    if not 1 <= args.rules <= MAX_RULES:
        parser.error(f"--rules must be between 1 and {MAX_RULES}")
    if args.samples < 20:
        parser.error("--samples must be at least 20")

    source = policy_source(args.rules)
    compile_started = time.perf_counter_ns()
    policy = compile_policy(source, {}, "benchmark.arsq")
    compile_ms = (time.perf_counter_ns() - compile_started) / 1_000_000
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "unmatched-tool",
        "tool_input": {},
        "cwd": str(ROOT),
    }
    regex_policy = compile_policy(
        'DEFAULT ALLOW\nRULE regex-gate\nWHEN network.destinations MATCHES "^evil\\\\.com$"\nTHEN AUDIT\nEND\n',
        {},
        "benchmark-regex.arsq",
    )
    regex_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "curl https://evil.com/example"},
        "cwd": str(ROOT),
    }
    matcher_event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf evil.com"},
        "cwd": str(ROOT),
    }
    matcher_policies = {
        "exact": compile_policy(
            'RULE exact\nWHEN action.command IS "printf evil.com"\nTHEN AUDIT\nEND\n',
            {},
            "benchmark-exact.arsq",
        ),
        "contains": compile_policy(
            'RULE contains\nWHEN action.command CONTAINS "evil.com"\nTHEN AUDIT\nEND\n',
            {},
            "benchmark-contains.arsq",
        ),
        "regex": compile_policy(
            'RULE regex\nWHEN action.command MATCHES "evil\\\\.com$"\nTHEN AUDIT\nEND\n',
            {},
            "benchmark-matches.arsq",
        ),
    }

    report = {
        "rule_count": args.rules,
        "condition_count": args.rules,
        "samples": args.samples,
        "compile_ms": compile_ms,
        "validation": measure(lambda: validate_policy(policy), args.samples),
        "evaluation": measure(lambda: evaluate(event, policy), args.samples),
        "regex_gated_evaluation": measure(
            lambda: evaluate(regex_event, regex_policy), args.samples
        ),
        "simple_match_evaluation": {
            name: measure(
                lambda selected=selected: evaluate(matcher_event, selected),
                args.samples,
            )
            for name, selected in matcher_policies.items()
        },
        "engine_budget_ms": args.engine_budget_ms,
    }
    report["engine_budget_passed"] = (
        report["evaluation"]["p95_ms"] <= args.engine_budget_ms
        and report["regex_gated_evaluation"]["p95_ms"] <= args.engine_budget_ms
        and all(
            result["p95_ms"] <= args.engine_budget_ms
            for result in report["simple_match_evaluation"].values()
        )
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["engine_budget_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
