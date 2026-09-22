from __future__ import annotations

import importlib.util
import json
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMPILER_PATH = ROOT / ".agent-runtime-security" / "policy_compiler.py"
SOURCE = ROOT / "policies" / "default.arsq"
SETTINGS = ROOT / ".agent-runtime-security" / "runtime.json"
OUTPUT = ROOT / ".agent-runtime-security" / "rules.json"

spec = importlib.util.spec_from_file_location("agent_runtime_security_policy_compiler", COMPILER_PATH)
compiler = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = compiler
spec.loader.exec_module(compiler)


class PolicyCompilerTests(unittest.TestCase):
    def test_default_policy_compiles_to_checked_in_runtime_ir(self) -> None:
        compiled = compiler.compile_policy(
            SOURCE.read_text(encoding="utf-8"),
            json.loads(SETTINGS.read_text(encoding="utf-8")),
            "policies/default.arsq",
        )
        self.assertEqual(compiled, json.loads(OUTPUT.read_text(encoding="utf-8")))

    def test_semantic_conditions_lower_to_runtime_matchers(self) -> None:
        compiled = compiler.compile_policy(
            SOURCE.read_text(encoding="utf-8"),
            json.loads(SETTINGS.read_text(encoding="utf-8")),
            "policies/default.arsq",
        )
        match = compiled["rules"][0]["match"]
        self.assertEqual(
            match["conditions"],
            [
                {"field": "tool.name", "operator": "==", "value": "Bash"},
                {"field": "process.executable", "operator": "IN", "value": ["ping", "ping6"]},
                {
                    "field": "network.destinations",
                    "operator": "ANY_MATCHES",
                    "value": "^evil\\.com$",
                },
            ],
        )
        self.assertFalse(match["case_sensitive"])

    def test_simple_operators_infer_scalar_and_list_runtime_operations(self) -> None:
        source = r'''RULE simple
WHEN tool.name IS "Bash"
AND process.executable IS ["curl", "wget"]
AND process.args CONTAINS "--upload.*"
AND network.destinations MATCHES "^evil\\.com$"
THEN DENY "blocked"
END
'''
        rule = compiler.compile_rule(compiler.parse_policy(source).rules[0])
        conditions = rule["match"]["conditions"]
        self.assertEqual(
            [condition["operator"] for condition in conditions],
            ["==", "IN", "ANY_MATCHES", "ANY_MATCHES"],
        )
        self.assertEqual(conditions[2]["value"], r"\-\-upload\.\*")
        self.assertEqual(rule["message"], "blocked")

    def test_simple_case_statement(self) -> None:
        sensitive = compiler.compile_rule(
            compiler.parse_policy(
                'RULE case\nWHEN tool.name IS "Bash"\nCASE SENSITIVE\nTHEN AUDIT\nEND\n'
            ).rules[0]
        )
        insensitive = compiler.compile_rule(
            compiler.parse_policy(
                'RULE case\nWHEN tool.name IS "Bash"\nCASE INSENSITIVE\nTHEN AUDIT\nEND\n'
            ).rules[0]
        )
        self.assertTrue(sensitive["match"]["case_sensitive"])
        self.assertFalse(insensitive["match"]["case_sensitive"])

    def test_simple_contains_escapes_regex_metacharacters_for_list_fields(self) -> None:
        source = (
            'RULE literal\nWHEN process.args CONTAINS "a.b*"\n'
            'THEN DENY "blocked"\nEND\n'
        )
        condition = compiler.compile_rule(compiler.parse_policy(source).rules[0])["match"]["conditions"][0]
        self.assertEqual(condition, {
            "field": "process.args",
            "operator": "ANY_MATCHES",
            "value": r"a\.b\*",
        })

    def test_unknown_field_fails_compilation(self) -> None:
        source = """\
RULE bad-field
WHEN model.intent == "malicious"
THEN DENY
MESSAGE "blocked"
END
"""
        with self.assertRaisesRegex(compiler.CompileError, "unsupported field"):
            compiler.parse_policy(source)

    def test_invalid_operator_for_field_fails_compilation(self) -> None:
        source = """\
RULE bad-operator
WHEN process.args STARTS_WITH "--"
THEN AUDIT
END
"""
        parsed = compiler.parse_policy(source)
        with self.assertRaisesRegex(compiler.CompileError, "not valid"):
            compiler.compile_rule(parsed.rules[0])

    def test_duplicate_rule_ids_fail_compilation(self) -> None:
        source = """\
RULE duplicate
WHEN tool.name == "Bash"
THEN AUDIT
END
RULE duplicate
WHEN tool.name == "apply_patch"
THEN AUDIT
END
"""
        with self.assertRaisesRegex(compiler.CompileError, "duplicate rule ids"):
            compiler.parse_policy(source)

    def test_deny_rule_requires_message(self) -> None:
        source = """\
RULE missing-message
WHEN tool.name == "Bash"
THEN DENY
END
"""
        with self.assertRaisesRegex(compiler.CompileError, "requires MESSAGE"):
            compiler.parse_policy(source)

    def test_extended_scalar_operators_and_fields(self) -> None:
        source = """\
RULE mcp-risk
WHEN tool.family == "mcp"
AND action.type IN ["integration.call", "tool.call"]
AND session.cwd STARTS_WITH "/workspace"
AND agent.id != "root"
AND tool.input.url CONTAINS "example.org"
AND tool.input.url ENDS_WITH "/upload"
AND tool.input.path NOT_IN ["/safe", "/public"]
AND tool.input.token EXISTS
AND tool.input.approval NOT_EXISTS
THEN DENY
MESSAGE "Blocked integration call"
END
"""
        conditions = compiler.compile_rule(compiler.parse_policy(source).rules[0])["match"]["conditions"]
        self.assertEqual(len(conditions), 9)
        self.assertEqual(conditions[3]["operator"], "!=")
        self.assertEqual(conditions[6]["value"], ["/safe", "/public"])
        self.assertNotIn("value", conditions[-1])

    def test_extended_list_operators(self) -> None:
        source = """\
RULE args-test
WHEN process.args HAS_ALL ["--upload", "evil.com"]
AND process.args HAS_NONE ["--dry-run"]
AND process.dispatch_chain HAS_ANY ["xargs", "find"]
AND tool.input.targets HAS_ANY ["private", "sensitive"]
THEN AUDIT
END
"""
        conditions = compiler.compile_rule(compiler.parse_policy(source).rules[0])["match"]["conditions"]
        self.assertEqual(
            [item["operator"] for item in conditions],
            ["HAS_ALL", "HAS_NONE", "HAS_ANY", "HAS_ANY"],
        )

    def test_semantic_target_fields_compile_as_lists(self) -> None:
        fields = (
            "network.destinations", "network.urls", "file.paths", "git.operations",
            "git.repositories", "package.operations", "package.names", "tool.targets",
            "tool.network.destinations",
            "threat.indicator_ids", "threat.verdicts", "threat.labels", "threat.sources",
            "threat.matched_targets", "tool.threat.verdicts",
        )
        clauses = "\n".join(
            ("WHEN" if index == 0 else "AND") + f' {name} HAS_ANY ["example"]'
            for index, name in enumerate(fields)
        )
        source = f"RULE semantic\n{clauses}\nTHEN AUDIT\nEND\n"
        conditions = compiler.compile_rule(compiler.parse_policy(source).rules[0])["match"]["conditions"]
        self.assertEqual([item["field"] for item in conditions], list(fields))

    def test_list_regex_operator(self) -> None:
        source = r"""RULE remote-gate
WHEN network.destinations ANY_MATCHES "^(?:example\\.com|203\\.0\\.113\\.[0-9]+)$"
AND threat.verdicts HAS_ANY ["malicious"]
THEN DENY
MESSAGE "blocked"
END
"""
        conditions = compiler.compile_rule(compiler.parse_policy(source).rules[0])["match"]["conditions"]
        self.assertEqual(conditions[0]["operator"], "ANY_MATCHES")

    def test_unary_operator_rejects_value_and_binary_requires_one(self) -> None:
        for clause in ('tool.input.key EXISTS "value"', 'tool.name =='):
            source = f"RULE malformed\nWHEN {clause}\nTHEN AUDIT\nEND\n"
            with self.subTest(clause=clause), self.assertRaises(compiler.CompileError):
                compiler.parse_policy(source)

    def test_rejects_duplicate_default_and_unexpected_settings(self) -> None:
        source = "DEFAULT ALLOW\nDEFAULT DENY\nRULE one\nWHEN tool.name == \"Bash\"\nTHEN AUDIT\nEND\n"
        with self.assertRaisesRegex(compiler.CompileError, "DEFAULT must appear once"):
            compiler.parse_policy(source)
        with self.assertRaisesRegex(compiler.CompileError, "must not define rules"):
            compiler.compile_policy(
                SOURCE.read_text(encoding="utf-8"), {"rules": []}, "test.arsq"
            )
        with self.assertRaisesRegex(compiler.CompileError, "unknown keys"):
            compiler.compile_policy(
                SOURCE.read_text(encoding="utf-8"), {"unexpected": True}, "test.arsq"
            )

    def test_bounded_lists_and_conditions(self) -> None:
        many_values = repr([f"v{i}" for i in range(compiler.MAX_LIST_VALUES + 1)])
        source = f"RULE many\nWHEN tool.name IN {many_values}\nTHEN AUDIT\nEND\n"
        with self.assertRaisesRegex(compiler.CompileError, "exceeds"):
            compiler.parse_policy(source)
        lines = ["RULE many", 'WHEN tool.name == "Bash"']
        lines += ['AND tool.name != "other"'] * compiler.MAX_CONDITIONS
        lines += ["THEN AUDIT", "END"]
        with self.assertRaisesRegex(compiler.CompileError, "conditions"):
            compiler.parse_policy("\n".join(lines))

    def test_source_rule_and_literal_limits(self) -> None:
        with self.assertRaisesRegex(compiler.CompileError, "policy exceeds"):
            compiler.parse_policy("#" + "x" * compiler.MAX_SOURCE_BYTES)
        many_rules = "".join(
            f'RULE r-{index}\nWHEN tool.name == "Bash"\nTHEN AUDIT\nEND\n'
            for index in range(compiler.MAX_RULES + 1)
        )
        with self.assertRaisesRegex(compiler.CompileError, "rules"):
            compiler.parse_policy(many_rules)
        long_literal = "x" * compiler.MAX_LITERAL_LENGTH
        with self.assertRaisesRegex(compiler.CompileError, "literal is too long"):
            compiler.parse_policy(
                f'RULE long\nWHEN tool.name == "{long_literal}"\nTHEN AUDIT\nEND\n'
            )

    def test_malformed_regex_fails_at_compile_time(self) -> None:
        source = 'RULE regex\nWHEN action.command MATCHES "[unterminated"\nTHEN AUDIT\nEND\n'
        with self.assertRaisesRegex(compiler.CompileError, "invalid regex"):
            compiler.compile_rule(compiler.parse_policy(source).rules[0])

    def test_input_prefix_is_case_insensitive_but_key_is_not_rewritten(self) -> None:
        source = (
            'RULE input-key\nWHEN TOOL.INPUT.URL == "blocked"\nTHEN DENY\n'
            'MESSAGE "blocked"\nEND\n'
        )
        compiled = compiler.compile_rule(compiler.parse_policy(source).rules[0])
        self.assertEqual(compiled["match"]["conditions"][0]["field"], "tool.input.URL")

    def test_large_policy_compiles_under_budget(self) -> None:
        source = "DEFAULT ALLOW\n" + "".join(
            f'RULE bulk-{index}\nWHEN tool.name == "tool-{index}"\nTHEN AUDIT\nEND\n'
            for index in range(500)
        )
        started = time.perf_counter()
        compiled = compiler.compile_policy(source, {}, "bulk.arsq")
        elapsed = time.perf_counter() - started
        self.assertEqual(len(compiled["rules"]), 500)
        self.assertLess(elapsed, 2.0, f"compile took {elapsed:.3f}s")

    def test_random_invalid_operator_field_pairs_fail_cleanly(self) -> None:
        randomizer = random.Random(20260919)
        fields = ["tool.name", "process.args", "session.cwd", "action.command"]
        for _ in range(100):
            field_name = randomizer.choice(fields)
            operator = "HAS_ANY" if field_name != "process.args" else "STARTS_WITH"
            source = (
                f'RULE fuzz\nWHEN {field_name} {operator} ["x"]\nTHEN AUDIT\nEND\n'
            )
            with self.assertRaises(compiler.CompileError):
                parsed = compiler.parse_policy(source)
                compiler.compile_rule(parsed.rules[0])

    def test_cli_check_reports_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules.json"
            output.write_text("{}", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(COMPILER_PATH),
                    str(SOURCE),
                    "--settings",
                    str(SETTINGS),
                    "--output",
                    str(output),
                    "--check",
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("stale", result.stderr)


if __name__ == "__main__":
    unittest.main()
