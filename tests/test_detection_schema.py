from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "agent-runtime-security-detection-event.schema.json"
EXAMPLES = (
    ROOT / "examples" / "detection-blocked-network-command.json",
    ROOT / "examples" / "detection-correlated-process-chain.json",
)


class DetectionSchemaTests(unittest.TestCase):
    def test_schema_and_examples_are_valid_json(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["properties"]["schema_version"]["const"], "1.2.0")
        for path in EXAMPLES:
            event = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(event["schema_version"], "1.2.0")
            self.assertEqual(event["event_type"], "detection")

    def test_example_graph_references_resolve(self) -> None:
        for path in EXAMPLES:
            event = json.loads(path.read_text(encoding="utf-8"))
            entity_ids = [entity["id"] for entity in event["entities"]]
            self.assertEqual(len(entity_ids), len(set(entity_ids)), path.name)
            known = set(entity_ids)
            self.assertIn(event["correlation"]["initiating_entity_id"], known, path.name)

            for relationship in event["relationships"]:
                self.assertIn(relationship["source_entity_id"], known, path.name)
                self.assertIn(relationship["target_entity_id"], known, path.name)

            evidence_ids: set[str] = set()
            for evidence in event["evidence"]:
                self.assertNotIn(evidence["evidence_id"], evidence_ids, path.name)
                evidence_ids.add(evidence["evidence_id"])
                self.assertIn(evidence["source_entity_id"], known, path.name)
                for target in evidence.get("target_entity_ids", []):
                    self.assertIn(target, known, path.name)

            relationship_edges = {
                (
                    relationship["source_entity_id"],
                    relationship["relationship"],
                    relationship["target_entity_id"],
                )
                for relationship in event["relationships"]
            }
            for chain in event.get("evidence_chains", []):
                sequences = [step["sequence"] for step in chain["steps"]]
                self.assertEqual(sequences, list(range(1, len(sequences) + 1)), path.name)
                for step in chain["steps"]:
                    self.assertIn(step["evidence_id"], evidence_ids, path.name)
                    edge = (
                        step["source_entity_id"],
                        step["relationship"],
                        step["target_entity_id"],
                    )
                    self.assertIn(edge, relationship_edges, path.name)

    def test_examples_contain_no_trace_tokens(self) -> None:
        for path in EXAMPLES:
            serialized = path.read_text(encoding="utf-8")
            self.assertNotIn("ARS_TRACE_TOKEN", serialized, path.name)
            self.assertNotIn("ARS_ACTOR_TOKEN", serialized, path.name)


if __name__ == "__main__":
    unittest.main()
