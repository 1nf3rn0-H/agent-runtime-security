"""Stable identifiers for hook observations and tool-action lifecycles."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Any

from trace_context import TraceContext


def _digest(*parts: str) -> str:
    material = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def new_observation_id() -> str:
    return f"obs_{uuid.uuid4()}"


@dataclass(frozen=True)
class ActionCorrelation:
    action_id: str
    request_fingerprint: str
    tool_use_id: str | None

    def telemetry(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "request_fingerprint": self.request_fingerprint,
            "tool_use_id": self.tool_use_id,
            "strength": "exact" if self.tool_use_id else "best_effort",
        }


def correlate_action(
    event: dict[str, Any], context: TraceContext, action: dict[str, Any]
) -> ActionCorrelation:
    tool_use_id_value = event.get("tool_use_id")
    tool_use_id = str(tool_use_id_value) if tool_use_id_value else None
    request_fingerprint = "req_" + _digest(
        context.trace_id,
        str(event.get("turn_id") or ""),
        context.actor_id,
        str(event.get("tool_name") or "unknown"),
        str(action["input"]["sha256"]),
    )
    action_material = tool_use_id or request_fingerprint
    action_id = "act_" + _digest(context.trace_id, action_material)
    return ActionCorrelation(
        action_id=action_id,
        request_fingerprint=request_fingerprint,
        tool_use_id=tool_use_id,
    )
