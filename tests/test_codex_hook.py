from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".aidr" / "codex_hook.py"
HOOKS_CONFIG = ROOT / ".codex" / "hooks.json"
RULES = ROOT / ".aidr" / "rules.json"
TRACE_FIXTURE = ROOT / "tests" / "fixtures" / "print_trace_chain.py"


def event(command: str, tool_name: str = "Bash") -> dict:
    return {
        "session_id": "test-session",
        "turn_id": "test-turn",
        "tool_use_id": "test-tool-use",
        "cwd": str(ROOT),
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command},
        "model": "test-model",
        "permission_mode": "default",
    }


def write_isolated_policy(directory: Path) -> Path:
    policy_path = directory / "rules.json"
    policy = json.loads(RULES.read_text(encoding="utf-8"))
    policy["telemetry"]["path"] = str(directory / "events.jsonl")
    policy["detections"]["path"] = str(directory / "detections.jsonl")
    policy["trace"]["state_dir"] = str(directory / "state")
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path


def invoke_event(payload: dict, rules: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(HOOK), "--rules", str(rules)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )


def trace_environment_from_output(output: str) -> tuple[dict, str]:
    hook_output = json.loads(output)
    specific = hook_output["hookSpecificOutput"]
    command = specific["updatedInput"]["command"]
    executed = subprocess.run(
        ["/bin/sh", "-c", command],
        text=True,
        capture_output=True,
        check=True,
    )
    records = [json.loads(line) for line in executed.stdout.splitlines()]
    return {record["level"]: record["environment"] for record in records}, command


class CodexHookTests(unittest.TestCase):
    def invoke(self, command: str, rules: Path = RULES) -> subprocess.CompletedProcess[str]:
        if rules != RULES:
            return subprocess.run(
                ["python3", str(HOOK), "--rules", str(rules)],
                input=json.dumps(event(command)),
                text=True,
                capture_output=True,
                check=False,
            )

        with tempfile.TemporaryDirectory() as directory:
            isolated_rules = write_isolated_policy(Path(directory))
            return invoke_event(event(command), isolated_rules)

    def assert_denied(self, command: str) -> None:
        result = self.invoke(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        decision = output["hookSpecificOutput"]
        self.assertEqual(decision["hookEventName"], "PreToolUse")
        self.assertEqual(decision["permissionDecision"], "deny")

    def test_blocks_direct_ping(self) -> None:
        self.assert_denied("ping evil.com")

    def test_blocks_ping_with_flags_and_absolute_path(self) -> None:
        self.assert_denied("/sbin/ping -c 1 EVIL.COM")

    def test_blocks_ping_in_compound_command(self) -> None:
        self.assert_denied("echo safe && ping evil.com")

    def test_blocks_ping_in_nested_shell(self) -> None:
        self.assert_denied("sh -c 'ping evil.com'")

    def test_blocks_ping_in_shell_expansions_and_wrappers(self) -> None:
        for command in (
            "echo $(ping evil.com)",
            "echo `ping evil.com`",
            "cat <(ping evil.com)",
            "sudo -u root -- ping evil.com",
            "bash -lc 'ping evil.com'",
            "timeout 5 ping evil.com",
            "printf x | xargs ping evil.com",
            "find . -exec ping evil.com {} \\;",
            "watch 'ping evil.com'",
            "eval 'ping evil.com'",
        ):
            with self.subTest(command=command):
                self.assert_denied(command)

    def test_runtime_supplied_indirect_arguments_fail_closed(self) -> None:
        for command in ("printf evil.com | xargs ping", "find . -exec ping {} \\;"):
            with self.subTest(command=command):
                result = self.invoke(command)
                output = json.loads(result.stdout)["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "deny")
                self.assertIn("dynamic", output["permissionDecisionReason"])
                self.assertIn("failed closed", output["permissionDecisionReason"])

    def test_dynamic_protected_arguments_fail_closed(self) -> None:
        result = self.invoke('ping "$HOST"')
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("dynamic", output["permissionDecisionReason"])
        self.assertIn("failed closed", output["permissionDecisionReason"])

    def test_dynamic_effective_destination_fails_closed_even_with_static_indicator_argument(self) -> None:
        result = self.invoke('ping evil.com "$EXTRA"')
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("failed closed", output["permissionDecisionReason"])

    def test_unrelated_dynamic_arguments_and_quoted_shell_text_are_allowed(self) -> None:
        for command in ('printf "%s" "$HOME"', "printf '%s' '$(ping evil.com)'"):
            with self.subTest(command=command):
                result = self.invoke(command)
                output = json.loads(result.stdout)["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "allow")

    def test_unsupported_shell_control_syntax_fails_closed(self) -> None:
        result = self.invoke("if true; then ping evil.com; fi")
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertIn("unsupported", output["permissionDecisionReason"])
        self.assertIn("failed closed", output["permissionDecisionReason"])

    def test_allows_unmatched_target(self) -> None:
        result = self.invoke("ping example.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertIn("AIDR_TRACE_TOKEN=", output["updatedInput"]["command"])
        self.assertTrue(output["updatedInput"]["command"].endswith("; ping example.com"))

    def test_allows_unmatched_program(self) -> None:
        result = self.invoke("printf '%s\\n' evil.com")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "allow")
        self.assertTrue(output["updatedInput"]["command"].endswith("; printf '%s\\n' evil.com"))

    def test_all_supported_tools_are_registered_with_wildcard_matchers(self) -> None:
        hooks = json.loads(HOOKS_CONFIG.read_text(encoding="utf-8"))["hooks"]
        self.assertEqual(hooks["PreToolUse"][0]["matcher"], "*")
        self.assertEqual(hooks["PermissionRequest"][0]["matcher"], "*")
        self.assertEqual(hooks["PostToolUse"][0]["matcher"], "*")

    def test_permission_request_deny_uses_permission_specific_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            payload = event("ping evil.com")
            payload["hook_event_name"] = "PermissionRequest"
            payload["tool_input"]["description"] = "Request broader network access"
            result = invoke_event(payload, rules)

            self.assertEqual(result.returncode, 0, result.stderr)
            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "PermissionRequest")
            self.assertEqual(output["decision"]["behavior"], "deny")
            self.assertIn("prohibited-domain policy", output["decision"]["message"])
            self.assertNotIn("updatedInput", output)

            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["decision"], "deny")
            self.assertEqual(record["event"]["hook_event_name"], "PermissionRequest")

    def test_permission_request_allow_abstains_to_preserve_user_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            payload = event("printf safe")
            payload["hook_event_name"] = "PermissionRequest"
            result = invoke_event(payload, rules)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["decision"], "allow")

    def test_permission_policy_error_fails_closed_with_permission_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            payload = event("printf safe")
            payload["hook_event_name"] = "PermissionRequest"
            result = invoke_event(payload, Path(temporary) / "missing.json")

            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "PermissionRequest")
            self.assertEqual(output["decision"]["behavior"], "deny")
            self.assertIn("failed closed", output["decision"]["message"])

    def test_allows_and_normalizes_apply_patch_without_rewriting_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            payload = event("*** Begin Patch\n*** End Patch", tool_name="apply_patch")
            result = invoke_event(payload, rules)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["action"]["family"], "file_edit")
            self.assertEqual(record["action"]["type"], "file.modify")
            self.assertEqual(record["action"]["input"]["keys"], ["command"])
            self.assertIsNone(record["command"])
            self.assertNotIn("*** Begin Patch", (directory / "events.jsonl").read_text())
            self.assertFalse(record["trace_environment_injected"])

    def test_allows_and_normalizes_mcp_tool_without_raw_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            payload = event("", tool_name="mcp__filesystem__read_file")
            payload["tool_input"] = {"path": "/tmp/example", "secret": "do-not-log"}
            result = invoke_event(payload, rules)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")

            serialized = (directory / "events.jsonl").read_text()
            record = json.loads(serialized.splitlines()[-1])
            self.assertEqual(record["action"]["family"], "mcp")
            self.assertEqual(record["action"]["type"], "integration.call")
            self.assertEqual(record["action"]["input"]["keys"], ["path", "secret"])
            self.assertEqual(record["semantic_targets"]["tool.targets"], ["/tmp/example"])
            self.assertNotIn("do-not-log", serialized)

    def test_generic_tool_rule_can_deny_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            policy = json.loads(rules.read_text(encoding="utf-8"))
            policy["rules"].append(
                {
                    "id": "block-example-mcp-tool",
                    "action": "deny",
                    "message": "Example MCP tool is prohibited.",
                    "match": {"tool_names": ["mcp__example__dangerous"]},
                }
            )
            rules.write_text(json.dumps(policy), encoding="utf-8")

            payload = event("", tool_name="mcp__example__dangerous")
            payload["tool_input"] = {"target": "resource-1"}
            result = invoke_event(payload, rules)

            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "deny")
            self.assertNotIn("updatedInput", output)
            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["decision"], "deny")
            self.assertEqual(record["action"]["family"], "mcp")

    def test_explicit_allow_rule_overrides_default_deny(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            policy = json.loads(rules.read_text(encoding="utf-8"))
            policy["default_action"] = "deny"
            policy["rules"] = [
                {
                    "id": "allow-safe-printf",
                    "action": "allow",
                    "message": "Safe printf is permitted.",
                    "match": {
                        "tool_names": ["Bash"],
                        "command_regex": "^printf safe$",
                    },
                }
            ]
            rules.write_text(json.dumps(policy), encoding="utf-8")

            allowed = invoke_event(event("printf safe"), rules)
            allowed_output = json.loads(allowed.stdout)["hookSpecificOutput"]
            self.assertEqual(allowed_output["permissionDecision"], "allow")

            denied = invoke_event(event("printf other"), rules)
            denied_output = json.loads(denied.stdout)["hookSpecificOutput"]
            self.assertEqual(denied_output["permissionDecision"], "deny")

    def test_post_tool_observes_non_shell_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            payload = event("", tool_name="update_plan")
            payload["hook_event_name"] = "PostToolUse"
            payload["tool_input"] = {"plan": [{"step": "test", "status": "completed"}]}
            payload["tool_response"] = {"ok": True}
            result = invoke_event(payload, rules)

            self.assertEqual(result.stdout, "")
            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(record["decision"], "observe")
            self.assertEqual(record["action"]["family"], "local_function")
            self.assertEqual(record["action"]["type"], "tool.call")

    def test_policy_error_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            broken = Path(directory) / "missing.json"
            result = self.invoke("printf safe", broken)
        output = json.loads(result.stdout)
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("failed closed", output["hookSpecificOutput"]["permissionDecisionReason"])

    def test_denied_command_never_reaches_runner(self) -> None:
        result = self.invoke("ping evil.com")
        hook_output = json.loads(result.stdout)
        shell_would_run = hook_output["hookSpecificOutput"]["permissionDecision"] != "deny"
        self.assertFalse(shell_would_run)

    def test_denied_action_emits_schema_versioned_detection_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            result = invoke_event(event("ping evil.com"), rules)
            self.assertEqual(
                json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny"
            )

            detections = (directory / "detections.jsonl").read_text().splitlines()
            self.assertEqual(len(detections), 1)
            detection = json.loads(detections[0])
            telemetry = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(detection["schema_version"], "1.2.0")
            self.assertEqual(
                detection["extensions"]["com.aidr.policy"]["ir_version"], "1.4.0"
            )
            self.assertEqual(
                detection["extensions"]["com.aidr.policy"]["bundle_sha256"],
                telemetry["policy"]["sha256"],
            )
            self.assertEqual(detection["event_type"], "detection")
            self.assertEqual(detection["response"]["action"], "blocked")
            self.assertEqual(detection["response"]["enforcement_point"], "pre_execution")
            self.assertEqual(detection["detection"]["severity"], "high")
            self.assertFalse(
                detection["extensions"]["com.aidr.threat_intelligence"]["enabled"]
            )
            self.assertEqual(
                detection["evidence"][0]["attributes"]["network.destinations"],
                ["evil.com"],
            )
            endpoints = [
                entity for entity in detection["entities"]
                if entity["type"] == "network_endpoint"
            ]
            self.assertTrue(
                any(entity["attributes"]["target.value"] == "evil.com" for entity in endpoints)
            )
            relationship_edges = {
                (
                    relationship["source_entity_id"],
                    relationship["relationship"],
                    relationship["target_entity_id"],
                )
                for relationship in detection["relationships"]
            }
            for step in detection["evidence_chains"][0]["steps"]:
                self.assertIn(
                    (
                        step["source_entity_id"],
                        step["relationship"],
                        step["target_entity_id"],
                    ),
                    relationship_edges,
                )
            self.assertEqual(
                detection["detection"]["category"], "network.prohibited_destination"
            )
            self.assertEqual(
                detection["detection"]["title"], "Network probing of a prohibited domain"
            )
            self.assertEqual(
                detection["correlation"]["trace_ids"][0], telemetry["trace"]["trace_id"]
            )
            self.assertEqual(
                detection["correlation"]["action_ids"][0],
                telemetry["action_correlation"]["action_id"],
            )
            self.assertEqual(detection["evidence_chains"][0]["steps"][0]["sequence"], 1)
            self.assertEqual(detection["data_handling"]["command_content"], "omitted")
            self.assertNotIn("AIDR_TRACE_TOKEN", detections[0])
            self.assertNotIn("ping evil.com", detections[0])

    def test_remote_threat_provider_failure_can_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            policy = json.loads(rules.read_text(encoding="utf-8"))
            policy["threat_intelligence"] = {
                "enabled": True,
                "provider": "virustotal",
                "api_key_env": "AIDR_TEST_MISSING_KEY",
                "failure_mode": "closed",
            }
            rules.write_text(json.dumps(policy), encoding="utf-8")
            result = invoke_event(event("curl https://evil.com"), rules)
            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "deny")
            self.assertIn(
                "remote threat intelligence failed",
                output["permissionDecisionReason"],
            )

    def test_remote_threat_provider_failure_can_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            policy = json.loads(rules.read_text(encoding="utf-8"))
            policy["threat_intelligence"] = {
                "enabled": True,
                "provider": "virustotal",
                "api_key_env": "AIDR_TEST_MISSING_KEY",
                "failure_mode": "open",
            }
            rules.write_text(json.dumps(policy), encoding="utf-8")
            result = invoke_event(event("curl https://evil.com"), rules)
            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["permissionDecision"], "allow")
            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertFalse(record["threat_intelligence"]["available"])
            self.assertIn("API key", record["threat_intelligence"]["warning"])

    def test_invalid_active_policy_uses_validated_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)

            initial = invoke_event(event("ping evil.com"), rules)
            self.assertEqual(
                json.loads(initial.stdout)["hookSpecificOutput"]["permissionDecision"], "deny"
            )
            self.assertTrue(Path(str(rules) + ".lkg").exists())

            rules.write_text('{"truncated":', encoding="utf-8")
            recovered = invoke_event(event("ping evil.com"), rules)
            self.assertEqual(
                json.loads(recovered.stdout)["hookSpecificOutput"]["permissionDecision"], "deny"
            )
            record = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertTrue(record["policy"]["used_last_known_good"])
            self.assertIn("invalid JSON", record["policy"]["load_warning"])
            detection = json.loads(
                (directory / "detections.jsonl").read_text().splitlines()[-1]
            )
            self.assertTrue(
                detection["extensions"]["com.aidr.policy"]["used_last_known_good"]
            )

    def test_allowed_action_does_not_emit_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            result = invoke_event(event("printf safe"), rules)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((directory / "detections.jsonl").exists())

    def test_pre_and_post_tool_observations_share_action_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            original = "printf lifecycle"

            pre_result = invoke_event(event(original), rules)
            rewritten = json.loads(pre_result.stdout)["hookSpecificOutput"]["updatedInput"][
                "command"
            ]
            post_event = event(rewritten)
            post_event["hook_event_name"] = "PostToolUse"
            post_event["tool_response"] = {"exit_code": 0}
            invoke_event(post_event, rules)

            records = [
                json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()
            ]
            pre_record, post_record = records[-2:]
            self.assertNotEqual(pre_record["observation_id"], post_record["observation_id"])
            self.assertEqual(
                pre_record["action_correlation"]["action_id"],
                post_record["action_correlation"]["action_id"],
            )
            self.assertEqual(
                pre_record["action_correlation"]["request_fingerprint"],
                post_record["action_correlation"]["request_fingerprint"],
            )
            self.assertEqual(pre_record["action_correlation"]["strength"], "exact")

    def test_permission_request_uses_matching_request_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            original = "printf approval"
            invoke_event(event(original), rules)

            permission_event = event(original)
            permission_event.pop("tool_use_id")
            permission_event["hook_event_name"] = "PermissionRequest"
            permission_event["tool_input"]["description"] = "Needs user approval"
            invoke_event(permission_event, rules)

            records = [
                json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()
            ]
            pre_record, permission_record = records[-2:]
            self.assertEqual(
                pre_record["action_correlation"]["request_fingerprint"],
                permission_record["action_correlation"]["request_fingerprint"],
            )
            self.assertEqual(permission_record["action_correlation"]["strength"], "best_effort")

    def test_trace_environment_reaches_child_process(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            result = invoke_event(event(f"python3 {TRACE_FIXTURE}"), rules)
            self.assertEqual(result.returncode, 0, result.stderr)
            environments, rewritten = trace_environment_from_output(result.stdout)

            self.assertIn("export AIDR_TRACE_ID=", rewritten)
            self.assertEqual(environments["parent"], environments["child"])
            self.assertEqual(environments["parent"]["AIDR_ACTOR_ID"], "root")
            self.assertEqual(environments["parent"]["AIDR_CODEX_SESSION_ID"], "test-session")
            self.assertEqual(environments["parent"]["AIDR_TOOL_CALL_ID"], "test-tool-use")
            self.assertTrue(environments["parent"]["AIDR_ACTION_ID"].startswith("act_"))
            self.assertTrue(
                environments["parent"]["AIDR_REQUEST_FINGERPRINT"].startswith("req_")
            )
            self.assertTrue(environments["parent"]["AIDR_TRACE_TOKEN"])

            telemetry = json.loads((directory / "events.jsonl").read_text().splitlines()[-1])
            self.assertEqual(telemetry["trace"]["trace_id"], environments["parent"]["AIDR_TRACE_ID"])
            self.assertEqual(
                telemetry["action_correlation"]["action_id"],
                environments["parent"]["AIDR_ACTION_ID"],
            )
            self.assertNotIn(environments["parent"]["AIDR_TRACE_TOKEN"], json.dumps(telemetry))

    def test_subagent_gets_actor_token_under_same_session_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)

            session_start = event("")
            session_start.update({"hook_event_name": "SessionStart", "source": "startup"})
            self.assertEqual(invoke_event(session_start, rules).stdout, "")

            subagent_start = event("")
            subagent_start.update(
                {
                    "hook_event_name": "SubagentStart",
                    "agent_id": "agent-child-1",
                    "agent_type": "reviewer",
                }
            )
            self.assertEqual(invoke_event(subagent_start, rules).stdout, "")

            root_result = invoke_event(event(f"python3 {TRACE_FIXTURE}"), rules)
            root_environments, _ = trace_environment_from_output(root_result.stdout)

            child_event = event(f"python3 {TRACE_FIXTURE}")
            child_event["agent_id"] = "agent-child-1"
            child_result = invoke_event(child_event, rules)
            child_environments, _ = trace_environment_from_output(child_result.stdout)

            root_environment = root_environments["parent"]
            child_environment = child_environments["parent"]
            self.assertEqual(root_environment["AIDR_TRACE_ID"], child_environment["AIDR_TRACE_ID"])
            self.assertEqual(root_environment["AIDR_TRACE_TOKEN"], child_environment["AIDR_TRACE_TOKEN"])
            self.assertNotEqual(root_environment["AIDR_ACTOR_TOKEN"], child_environment["AIDR_ACTOR_TOKEN"])
            self.assertEqual(child_environment["AIDR_ACTOR_ID"], "agent-child-1")

    def test_trace_is_stable_within_session_and_unique_between_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)

            first = invoke_event(event(f"python3 {TRACE_FIXTURE}"), rules)
            first_environment, _ = trace_environment_from_output(first.stdout)
            second = invoke_event(event(f"python3 {TRACE_FIXTURE}"), rules)
            second_environment, _ = trace_environment_from_output(second.stdout)

            other_event = event(f"python3 {TRACE_FIXTURE}")
            other_event["session_id"] = "another-session"
            other = invoke_event(other_event, rules)
            other_environment, _ = trace_environment_from_output(other.stdout)

            self.assertEqual(
                first_environment["parent"]["AIDR_TRACE_TOKEN"],
                second_environment["parent"]["AIDR_TRACE_TOKEN"],
            )
            self.assertNotEqual(
                first_environment["parent"]["AIDR_TRACE_TOKEN"],
                other_environment["parent"]["AIDR_TRACE_TOKEN"],
            )

    def test_denied_command_does_not_receive_trace_environment(self) -> None:
        result = self.invoke("ping evil.com")
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertNotIn("updatedInput", output)

    def test_post_tool_telemetry_strips_injected_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            rules = write_isolated_policy(directory)
            original = f"python3 {TRACE_FIXTURE}"

            pre_result = invoke_event(event(original), rules)
            pre_output = json.loads(pre_result.stdout)["hookSpecificOutput"]
            rewritten = pre_output["updatedInput"]["command"]
            trace_token = rewritten.split("AIDR_TRACE_TOKEN=", 1)[1].split(" ", 1)[0]

            post_event = event(rewritten)
            post_event["hook_event_name"] = "PostToolUse"
            post_event["tool_response"] = {"exit_code": 0}
            post_result = invoke_event(post_event, rules)
            self.assertEqual(post_result.stdout, "")

            records = [
                json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()
            ]
            post_record = records[-1]
            self.assertEqual(post_record["event"]["hook_event_name"], "PostToolUse")
            self.assertEqual(post_record["command"], original)
            self.assertNotIn(trace_token, json.dumps(post_record))
            self.assertEqual(post_record["invocations"][0]["executable"], "python3")


if __name__ == "__main__":
    unittest.main()
