from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
AIDR = ROOT / ".aidr"
if str(AIDR) not in sys.path:
    sys.path.insert(0, str(AIDR))


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


compiler = load("aidr_remote_compiler_tests", AIDR / "policy_compiler.py")
hook = load("aidr_remote_hook_tests", AIDR / "codex_hook.py")
threat_intel = sys.modules["threat_intel"]


def malicious_response() -> bytes:
    return json.dumps(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 4,
                        "suspicious": 0,
                        "harmless": 60,
                        "undetected": 5,
                    },
                    "tags": ["phishing"],
                }
            }
        }
    ).encode()


def compile_rule(conditions: str) -> dict:
    source = (
        "DEFAULT ALLOW\nRULE remote-test\n"
        + conditions
        + 'THEN DENY\nMESSAGE "blocked by remote reputation"\nEND\n'
    )
    return compiler.compile_policy(
        source,
        {
            "threat_intelligence": {
                "enabled": True,
                "provider": "virustotal",
                "failure_mode": "open",
            }
        },
        "remote-test.aidrql",
    )


def event(command: str = "", *, tool_name: str = "Bash", tool_input: dict | None = None) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input if tool_input is not None else {"command": command},
    }


class RemoteEnrichmentTests(unittest.TestCase):
    def test_process_lookup_occurs_only_after_regex_and_other_rule_conditions_match(self) -> None:
        policy = compile_rule(
            'WHEN tool.name == "Bash"\n'
            'AND process.executable == "curl"\n'
            'AND network.destinations ANY_MATCHES "^evil\\\\.com$"\n'
            'AND threat.verdicts HAS_ANY ["malicious"]\n'
        )
        calls: list[str] = []

        def transport(url: str, api_key: str, timeout: float) -> tuple[int, bytes]:
            calls.append(url)
            return 200, malicious_response()

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            safe = threat_intel.VirusTotalEnricher(transport=transport)
            self.assertEqual(
                hook.evaluate(event("curl https://safe.com"), policy, threat_enricher=safe)["action"],
                "allow",
            )
            self.assertEqual(calls, [])

            matched = threat_intel.VirusTotalEnricher(transport=transport)
            result = hook.evaluate(
                event("curl https://evil.com/path"), policy, threat_enricher=matched
            )

        self.assertEqual(result["action"], "deny")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith("/domains/evil.com"))
        self.assertEqual(result["matched_rules"][0]["threat_matches"]["threat.verdicts"], ["malicious"])
        self.assertEqual(result["threat_intelligence"]["lookup_count"], 1)

    def test_tool_lookup_is_gated_by_normalized_domain_regex(self) -> None:
        policy = compile_rule(
            'WHEN tool.family == "mcp"\n'
            'AND tool.network.destinations ANY_MATCHES "^evil\\\\.com$"\n'
            'AND tool.threat.verdicts HAS_ANY ["malicious"]\n'
        )
        calls: list[str] = []

        def transport(url: str, api_key: str, timeout: float) -> tuple[int, bytes]:
            calls.append(url)
            return 200, malicious_response()

        enricher = threat_intel.VirusTotalEnricher(transport=transport)
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            result = hook.evaluate(
                event(
                    tool_name="mcp__fetch",
                    tool_input={"url": "https://evil.com/path?secret=omitted"},
                ),
                policy,
                threat_enricher=enricher,
            )
        self.assertEqual(result["action"], "deny")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("secret", calls[0])

    def test_post_tool_observation_never_calls_remote_provider(self) -> None:
        policy = compile_rule(
            'WHEN network.destinations ANY_MATCHES "^evil\\\\.com$"\n'
            'AND threat.verdicts HAS_ANY ["malicious"]\n'
        )
        calls: list[str] = []
        enricher = threat_intel.VirusTotalEnricher(
            transport=lambda url, api_key, timeout: (calls.append(url) or 200, malicious_response())
        )
        payload = event("curl https://evil.com")
        payload["hook_event_name"] = "PostToolUse"
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            result = hook.evaluate(payload, policy, threat_enricher=enricher)
        self.assertEqual(result["action"], "allow")
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
