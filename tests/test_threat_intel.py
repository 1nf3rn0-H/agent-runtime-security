from __future__ import annotations

import importlib.util
import json
import os
import sys
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = ROOT / ".agent-runtime-security" / "threat_intel.py"

spec = importlib.util.spec_from_file_location("agent_runtime_security_threat_intel_tests", MODULE_PATH)
threat_intel = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = threat_intel
spec.loader.exec_module(threat_intel)


def response(*, malicious: int = 0, suspicious: int = 0, harmless: int = 70) -> bytes:
    return json.dumps(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": 5,
                    },
                    "tags": ["test-tag"],
                }
            }
        }
    ).encode()


class ThreatIntelTests(unittest.TestCase):
    def test_disabled_configuration_builds_no_enricher(self) -> None:
        self.assertIsNone(threat_intel.build_enricher(None))
        self.assertIsNone(threat_intel.build_enricher({"enabled": False}))

    def test_domain_lookup_uses_fixed_virustotal_endpoint_and_api_key_header_value(self) -> None:
        calls: list[tuple[str, str, float]] = []

        def transport(url: str, api_key: str, timeout: float) -> tuple[int, bytes]:
            calls.append((url, api_key, timeout))
            return 200, response(malicious=3)

        enricher = threat_intel.VirusTotalEnricher(transport=transport)
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            result = enricher.lookup([("domain", "EVIL.COM")])

        self.assertEqual(result.verdicts, ("malicious",))
        self.assertEqual(result.matched_targets, ("evil.com",))
        self.assertEqual(result.sources, ("virustotal",))
        self.assertEqual(calls, [
            ("https://www.virustotal.com/api/v3/domains/evil.com", "test-secret", 1.5)
        ])
        self.assertNotIn("test-secret", json.dumps(enricher.metadata()))

    def test_ip_lookup_and_per_event_memoization(self) -> None:
        calls = 0

        def transport(url: str, api_key: str, timeout: float) -> tuple[int, bytes]:
            nonlocal calls
            calls += 1
            self.assertIn("/ip_addresses/203.0.113.9", url)
            return 200, response(suspicious=2)

        enricher = threat_intel.VirusTotalEnricher(transport=transport)
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            first = enricher.lookup([("ip", "203.0.113.9")])
            second = enricher.lookup([("ip", "203.0.113.9")])
        self.assertEqual(first.verdicts, ("suspicious",))
        self.assertEqual(second, first)
        self.assertEqual(calls, 1)
        self.assertEqual(enricher.metadata()["lookup_count"], 1)

    def test_404_is_unknown_not_a_provider_failure(self) -> None:
        enricher = threat_intel.VirusTotalEnricher(
            transport=lambda url, api_key, timeout: (404, b"")
        )
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
            result = enricher.lookup([("domain", "unknown.example")])
        self.assertEqual(result.verdicts, ("unknown",))
        self.assertTrue(enricher.metadata()["available"])

    def test_missing_key_obeys_open_and_closed_failure_modes(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            open_enricher = threat_intel.VirusTotalEnricher(failure_mode="open")
            self.assertEqual(open_enricher.lookup([("domain", "example.com")]).verdicts, ())
            self.assertIn("API key", open_enricher.metadata()["warning"])

            closed_enricher = threat_intel.VirusTotalEnricher(failure_mode="closed")
            with self.assertRaisesRegex(threat_intel.ThreatIntelError, "API key"):
                closed_enricher.lookup([("domain", "example.com")])

    def test_oversized_or_invalid_response_is_not_trusted(self) -> None:
        for payload in (b"not-json", b"x" * (threat_intel.MAX_RESPONSE_BYTES + 1)):
            with self.subTest(size=len(payload)):
                enricher = threat_intel.VirusTotalEnricher(
                    failure_mode="closed",
                    transport=lambda url, api_key, timeout, value=payload: (200, value),
                )
                with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test-secret"}, clear=False):
                    with self.assertRaises(threat_intel.ThreatIntelError):
                        enricher.lookup([("domain", "example.com")])


if __name__ == "__main__":
    unittest.main()
