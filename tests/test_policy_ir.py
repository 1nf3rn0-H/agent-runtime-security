from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / ".agent-runtime-security" / "policy_ir.py"
RULES = ROOT / ".agent-runtime-security" / "rules.json"
SCHEMA = ROOT / "schemas" / "agent-runtime-security-runtime-policy.schema.json"

spec = importlib.util.spec_from_file_location("agent_runtime_security_policy_ir", MODULE_PATH)
policy_ir = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = policy_ir
spec.loader.exec_module(policy_ir)


def current_policy() -> dict:
    return json.loads(RULES.read_text(encoding="utf-8"))


class RuntimePolicyIRTests(unittest.TestCase):
    def test_checked_in_policy_and_schema_declare_same_version(self) -> None:
        policy = current_policy()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(
            schema["properties"]["policy_ir_version"]["const"],
            policy_ir.POLICY_IR_VERSION,
        )
        self.assertEqual(policy["policy_ir_version"], policy_ir.POLICY_IR_VERSION)
        self.assertIs(policy_ir.validate_policy(policy), policy)

    def test_rejects_unknown_and_incompatible_top_level_fields(self) -> None:
        policy = current_policy()
        policy["unexpected"] = True
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "unknown keys"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        policy["policy_ir_version"] = "2.0.0"
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "unsupported version"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        policy["default_action"] = []
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "allow or deny"):
            policy_ir.validate_policy(policy)

    def test_validates_threat_intelligence_runtime_settings(self) -> None:
        policy = current_policy()
        policy["threat_intelligence"]["enabled"] = "yes"
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "must be a boolean"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        policy["threat_intelligence"]["unexpected"] = True
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "unknown keys"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        policy["threat_intelligence"]["timeout_ms"] = 50
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "100 through 10000"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        policy["rules"].append(
            {
                "id": "threat-gate-test",
                "action": "audit",
                "match": {
                    "case_sensitive": False,
                    "conditions": [
                        {
                            "field": "network.destinations",
                            "operator": "ANY_MATCHES",
                            "value": "^example\\.com$",
                        },
                        {
                            "field": "threat.verdicts",
                            "operator": "HAS_ANY",
                            "value": ["malicious"],
                        },
                    ],
                },
            }
        )
        policy_ir.validate_policy(policy)
        del policy["rules"][-1]["match"]["conditions"][0]
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "ANY_MATCHES gate"):
            policy_ir.validate_policy(policy)

    def test_rejects_duplicate_rules_and_invalid_predicates(self) -> None:
        policy = current_policy()
        policy["rules"].append(copy.deepcopy(policy["rules"][0]))
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "duplicate rule id"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        condition = policy["rules"][0]["match"]["conditions"][0]
        condition["operator"] = "EXECUTES"
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "unsupported operator"):
            policy_ir.validate_policy(policy)

        policy = current_policy()
        condition = policy["rules"][0]["match"]["conditions"][0]
        condition["operator"] = "EXISTS"
        with self.assertRaisesRegex(policy_ir.PolicyValidationError, "must not define value"):
            policy_ir.validate_policy(policy)

    def test_policy_hash_is_canonical_and_changes_with_policy(self) -> None:
        first = current_policy()
        reordered = {key: first[key] for key in reversed(first)}
        self.assertEqual(policy_ir.policy_sha256(first), policy_ir.policy_sha256(reordered))
        reordered["default_action"] = "deny"
        self.assertNotEqual(policy_ir.policy_sha256(first), policy_ir.policy_sha256(reordered))

    def test_atomic_activation_sets_restricted_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "rules.json"
            digest = policy_ir.write_policy_atomic(output, current_policy())
            self.assertEqual(digest, policy_ir.policy_sha256(current_policy()))
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            self.assertEqual(list(output.parent.glob(".policy-*")), [])
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), current_policy())

    def test_load_refreshes_and_falls_back_to_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            active = Path(temporary) / "rules.json"
            policy_ir.write_policy_atomic(active, current_policy())
            first = policy_ir.load_policy(active)
            lkg = policy_ir.last_known_good_path(active)
            self.assertTrue(lkg.exists())
            self.assertFalse(first.used_last_known_good)

            active.write_text('{"truncated":', encoding="utf-8")
            recovered = policy_ir.load_policy(active)
            self.assertTrue(recovered.used_last_known_good)
            self.assertEqual(recovered.sha256, first.sha256)
            self.assertIn("invalid JSON", recovered.load_warning or "")

    def test_rejects_oversize_and_fails_when_both_copies_are_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            active = Path(temporary) / "rules.json"
            active.write_bytes(b" " * (policy_ir.MAX_POLICY_BYTES + 1))
            with self.assertRaisesRegex(policy_ir.PolicyValidationError, "exceeds"):
                policy_ir.load_policy(active)

            active.write_text("{}", encoding="utf-8")
            policy_ir.last_known_good_path(active).write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(policy_ir.PolicyValidationError, "last-known-good"):
                policy_ir.load_policy(active)

    def test_loader_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            active = Path(temporary) / "rules.json"
            active.write_text(
                '{"policy_ir_version":"1.0.0","policy_ir_version":"2.0.0"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(policy_ir.PolicyValidationError, "duplicate JSON key"):
                policy_ir.load_policy(active)


if __name__ == "__main__":
    unittest.main()
