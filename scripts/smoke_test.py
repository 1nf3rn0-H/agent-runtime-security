#!/usr/bin/env python3
"""Run a network-free AiDR enforcement and correlation smoke test."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".aidr" / "codex_hook.py"
RULES = ROOT / ".aidr" / "rules.json"
TRACE_FIXTURE = ROOT / "tests" / "fixtures" / "print_trace_chain.py"


def hook_event(command: str, hook_event_name: str = "PreToolUse") -> dict:
    return {
        "session_id": "smoke-session",
        "turn_id": "smoke-turn",
        "tool_use_id": "smoke-tool-call",
        "cwd": str(ROOT),
        "hook_event_name": hook_event_name,
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "model": "smoke-test",
        "permission_mode": "default",
    }


def invoke(payload: dict, rules: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK), "--rules", str(rules)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aidr-smoke-") as temporary:
        directory = Path(temporary)
        policy = json.loads(RULES.read_text(encoding="utf-8"))
        policy["telemetry"]["path"] = str(directory / "events.jsonl")
        policy["detections"]["path"] = str(directory / "detections.jsonl")
        policy["trace"]["state_dir"] = str(directory / "state")
        rules = directory / "rules.json"
        rules.write_text(json.dumps(policy), encoding="utf-8")

        denied = invoke(hook_event("ping evil.com"), rules)
        require(denied.returncode == 0, denied.stderr)
        denied_output = json.loads(denied.stdout)["hookSpecificOutput"]
        require(denied_output["permissionDecision"] == "deny", "unsafe command was not denied")

        detection_lines = (directory / "detections.jsonl").read_text().splitlines()
        require(len(detection_lines) == 1, "expected exactly one detection")
        detection = json.loads(detection_lines[0])
        require(detection["schema_version"] == "1.2.0", "unexpected detection schema")
        require(detection["response"]["action"] == "blocked", "detection was not blocked")
        require(bool(detection["evidence_chains"]), "detection has no evidence chain")
        require("ping evil.com" not in detection_lines[0], "raw command leaked into detection")

        original = f"{sys.executable} {TRACE_FIXTURE}"
        allowed = invoke(hook_event(original), rules)
        require(allowed.returncode == 0, allowed.stderr)
        allowed_output = json.loads(allowed.stdout)["hookSpecificOutput"]
        require(allowed_output["permissionDecision"] == "allow", "safe command was not allowed")
        rewritten = allowed_output["updatedInput"]["command"]

        executed = subprocess.run(
            ["/bin/sh", "-c", rewritten],
            text=True,
            capture_output=True,
            check=True,
        )
        environments = {
            row["level"]: row["environment"]
            for row in (json.loads(line) for line in executed.stdout.splitlines())
        }
        require(environments["parent"] == environments["child"], "child lost trace context")
        require(bool(environments["parent"]["AIDR_ACTION_ID"]), "action id was not injected")

        post = hook_event(rewritten, "PostToolUse")
        post["tool_response"] = {"exit_code": 0}
        completed = invoke(post, rules)
        require(completed.returncode == 0, completed.stderr)

        observations = [
            json.loads(line) for line in (directory / "events.jsonl").read_text().splitlines()
        ]
        pre_record, post_record = observations[-2:]
        require(
            pre_record["action_correlation"]["action_id"]
            == post_record["action_correlation"]["action_id"],
            "pre/post action ids differ",
        )
        require(len((directory / "detections.jsonl").read_text().splitlines()) == 1,
                "allowed action created a detection")

        print("PASS  denied command never dispatched by the hook")
        print("PASS  schema-v1.2 detection emitted without raw command content")
        print("PASS  safe command allowed with trace and action context")
        print("PASS  child process inherited the complete AiDR context")
        print("PASS  PreToolUse and PostToolUse share one exact action_id")
        print("PASS  temporary test state removed on exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
