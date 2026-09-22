"""Build schema-versioned Agent Runtime Security detection events from matched policy decisions."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from correlation import ActionCorrelation
from trace_context import TraceContext


SCHEMA_VERSION = "1.2.0"
PRODUCER_VERSION = "0.1.0"
IDENTIFIER_PART = re.compile(r"[^a-z0-9_]+")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4()}"


def _rule_identifier(rule_id: str) -> str:
    if re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+", rule_id):
        return rule_id
    normalized = IDENTIFIER_PART.sub("_", rule_id.casefold()).strip("_") or "unnamed"
    return f"agent_runtime_security.rule.{normalized}"


def _correlation_id(
    context: TraceContext, rule_id: str, tool_name: str, input_sha256: str
) -> str:
    material = "\x00".join((context.trace_id, rule_id, tool_name, input_sha256)).encode()
    return "cor_" + hashlib.sha256(material).hexdigest()[:32]


def build_detection_event(
    *,
    event: dict[str, Any],
    context: TraceContext,
    action: dict[str, Any],
    action_correlation: ActionCorrelation,
    rule: dict[str, Any],
    reason: str,
    latency_us: int,
    policy_metadata: dict[str, Any],
    semantic_targets: dict[str, list[str]] | None = None,
    threat_intelligence: dict[str, Any] | None = None,
    threat_matches: dict[str, list[Any]] | None = None,
) -> dict[str, Any]:
    """Create one immutable detection for one denying rule match."""
    observed_at = _timestamp()
    original_rule_id = str(rule.get("id") or "unnamed")
    tool_name = str(event.get("tool_name") or "unknown")
    actor_id = str(context.actor_id or "root")
    agent_entity_id = f"agent:{actor_id}"
    tool_entity_id = f"tool_call:{action_correlation.action_id}"
    evidence_id = _identifier("evd")
    input_sha256 = str(action["input"]["sha256"])

    evidence_attributes: dict[str, Any] = {
        "policy.rule_id": original_rule_id,
        "policy.bundle_sha256": str(policy_metadata["sha256"]),
        "policy.ir_version": str(policy_metadata["ir_version"]),
        "tool.input_sha256": input_sha256,
    }
    target_entities: list[dict[str, Any]] = []
    target_relationships: list[dict[str, Any]] = []
    target_ids: list[str] = []
    target_count = 0
    entity_types = {
        "network.destinations": "network_endpoint",
        "network.urls": "network_endpoint",
        "file.paths": "file",
        "git.repositories": "repository",
    }
    for field_name, values in (semantic_targets or {}).items():
        bounded_values = [str(value) for value in values[:64] if str(value)]
        if not bounded_values:
            continue
        evidence_attributes[field_name] = bounded_values
        for value in bounded_values:
            if target_count >= 63:
                break
            digest = hashlib.sha256(f"{field_name}\0{value}".encode()).hexdigest()[:32]
            entity_type = entity_types.get(field_name, "other")
            target_id = f"{entity_type}:{digest}"
            if target_id in target_ids:
                continue
            target_ids.append(target_id)
            target_entities.append(
                {
                    "id": target_id,
                    "type": entity_type,
                    "attributes": {
                        "target.field": field_name,
                        "target.value": value,
                    },
                }
            )
            target_relationships.append(
                {
                    "source_entity_id": tool_entity_id,
                    "relationship": "targeted",
                    "target_entity_id": target_id,
                    "observed_at": observed_at,
                }
            )
            target_count += 1
    for field_name, values in (threat_matches or {}).items():
        bounded_values = [value for value in values[:64] if value is not None and value != ""]
        if bounded_values:
            evidence_attributes[field_name] = bounded_values
    detection_event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": _identifier("det"),
        "event_type": "detection",
        "emitted_at": observed_at,
        "producer": {
            "name": "agent-runtime-security",
            "version": PRODUCER_VERSION,
            "component": "policy_engine",
        },
        "detection": {
            "rule": {
                "id": _rule_identifier(original_rule_id),
                "version": str(rule.get("version") or "1"),
                "ruleset": "local",
            },
            "title": str(rule.get("title") or rule.get("message") or f"Policy denied {tool_name}"),
            "category": str(rule.get("category") or "policy.rule_match"),
            "severity": str(rule.get("severity") or "medium"),
            "confidence": 100,
            "tags": ["policy", "pre_execution", action["family"]] + (
                ["threat_intelligence"] if any((threat_matches or {}).values()) else []
            ),
        },
        "observed_window": {
            "first_observed_at": observed_at,
            "last_observed_at": observed_at,
            "observation_count": 1,
        },
        "correlation": {
            "correlation_id": _correlation_id(
                context, original_rule_id, tool_name, input_sha256
            ),
            "trace_ids": [context.trace_id],
            "action_ids": [action_correlation.action_id],
            "request_fingerprints": [action_correlation.request_fingerprint],
            "sessions": [
                {
                    "provider": "codex",
                    "session_id": context.session_id,
                }
            ],
            "initiating_entity_id": agent_entity_id,
        },
        "entities": [
            {
                "id": agent_entity_id,
                "type": "agent",
                "attributes": {
                    "agent.provider": "codex",
                    "agent.type": context.actor_type,
                },
            },
            {
                "id": tool_entity_id,
                "type": "tool_call",
                "attributes": {
                    "tool.name": tool_name,
                    "tool.family": action["family"],
                    "tool.input_sha256": input_sha256,
                },
            },
        ] + target_entities,
        "relationships": [
            {
                "source_entity_id": agent_entity_id,
                "relationship": "initiated",
                "target_entity_id": tool_entity_id,
                "observed_at": observed_at,
            }
        ] + target_relationships,
        "evidence": [
            {
                "evidence_id": evidence_id,
                "observed_at": observed_at,
                "action_type": action["type"],
                "phase": "pre_execution",
                "role": "trigger",
                "source_entity_id": agent_entity_id,
                "target_entity_ids": [tool_entity_id] + target_ids,
                "summary": f"Rule {original_rule_id} denied the proposed {tool_name} action.",
                "attributes": evidence_attributes,
            }
        ],
        "evidence_chains": [
            {
                "chain_id": _identifier("chn"),
                "type": "causal",
                "summary": f"The {actor_id} agent initiated the denied {tool_name} action.",
                "steps": [
                    {
                        "sequence": 1,
                        "evidence_id": evidence_id,
                        "source_entity_id": agent_entity_id,
                        "relationship": "initiated",
                        "target_entity_id": tool_entity_id,
                    }
                ] + [
                    {
                        "sequence": index + 2,
                        "evidence_id": evidence_id,
                        "source_entity_id": tool_entity_id,
                        "relationship": "targeted",
                        "target_entity_id": target_id,
                    }
                    for index, target_id in enumerate(target_ids)
                ],
            }
        ],
        "response": {
            "action": "blocked",
            "enforcement_point": "pre_execution",
            "reason": reason,
            "policy_latency_us": latency_us,
        },
        "data_handling": {
            "classification": "internal",
            "command_content": "omitted",
            "secret_scan": "not_run",
        },
        "extensions": {
            "com.agent_runtime_security.policy": {
                "bundle_sha256": policy_metadata["sha256"],
                "ir_version": policy_metadata["ir_version"],
                "source": policy_metadata.get("source"),
                "used_last_known_good": policy_metadata["used_last_known_good"],
            },
            "com.agent_runtime_security.threat_intelligence": {
                "enabled": bool((threat_intelligence or {}).get("enabled")),
                "available": bool((threat_intelligence or {}).get("available")),
                "provider": (threat_intelligence or {}).get("provider"),
                "source": (threat_intelligence or {}).get("source"),
                "lookup_count": (threat_intelligence or {}).get("lookup_count", 0),
                "latency_ms": (threat_intelligence or {}).get("latency_ms", 0.0),
                "failure_mode": (threat_intelligence or {}).get("failure_mode"),
            },
            "com.openai.codex": {
                "hook_event_name": event.get("hook_event_name"),
                "permission_mode": event.get("permission_mode"),
            }
        },
    }

    description = str(rule.get("description") or "")
    if description:
        detection_event["detection"]["description"] = description
    return detection_event
