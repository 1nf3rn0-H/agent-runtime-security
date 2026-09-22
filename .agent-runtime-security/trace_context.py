"""Persistent trace contexts used to correlate Codex agents and child processes."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


STATE_SCHEMA_VERSION = "1.0"
ROOT_ACTOR_ID = "root"


class TraceContextError(RuntimeError):
    pass


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    trace_token: str
    actor_id: str
    actor_type: str
    actor_token: str
    parent_actor_id: str | None
    session_id: str

    @property
    def trace_token_fingerprint(self) -> str:
        return token_fingerprint(self.trace_token)

    @property
    def actor_token_fingerprint(self) -> str:
        return token_fingerprint(self.actor_token)

    def environment(
        self,
        tool_call_id: str | None = None,
        action_id: str | None = None,
        request_fingerprint: str | None = None,
    ) -> dict[str, str]:
        values = {
            "ARS_TRACE_ID": self.trace_id,
            "ARS_TRACE_TOKEN": self.trace_token,
            "ARS_ACTOR_ID": self.actor_id,
            "ARS_ACTOR_TOKEN": self.actor_token,
            "ARS_CODEX_SESSION_ID": self.session_id,
        }
        if tool_call_id:
            values["ARS_TOOL_CALL_ID"] = tool_call_id
        if action_id:
            values["ARS_ACTION_ID"] = action_id
        if request_fingerprint:
            values["ARS_REQUEST_FINGERPRINT"] = request_fingerprint
        return values

    def telemetry(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "trace_token_fingerprint": self.trace_token_fingerprint,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "actor_token_fingerprint": self.actor_token_fingerprint,
            "parent_actor_id": self.parent_actor_id,
        }


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


class TraceRegistry:
    """File-backed session registry with process-safe updates on macOS/Linux."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.state_dir.chmod(0o700)
        except OSError:
            pass
        self._lock_path = self.state_dir / ".lock"

    @contextmanager
    def _lock(self) -> Iterator[None]:
        descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _state_path(self, session_id: str) -> Path:
        digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
        return self.state_dir / f"session-{digest}.json"

    def _new_state(self, session_id: str) -> dict[str, Any]:
        now = time.time_ns()
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "session_id": session_id,
            "trace_id": f"trc_{secrets.token_hex(16)}",
            "trace_token": secrets.token_urlsafe(32),
            "created_at_unix_ns": now,
            "updated_at_unix_ns": now,
            "actors": {
                ROOT_ACTOR_ID: {
                    "actor_id": ROOT_ACTOR_ID,
                    "actor_type": "root",
                    "actor_token": secrets.token_urlsafe(32),
                    "parent_actor_id": None,
                    "created_at_unix_ns": now,
                }
            },
        }

    def _load(self, path: Path, session_id: str) -> dict[str, Any]:
        if not path.exists():
            return self._new_state(session_id)
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TraceContextError(f"cannot read trace state: {exc}") from exc
        if state.get("session_id") != session_id:
            raise TraceContextError("trace state session mismatch")
        if state.get("schema_version") != STATE_SCHEMA_VERSION:
            raise TraceContextError("unsupported trace state schema")
        return state

    def _save(self, path: Path, state: dict[str, Any]) -> None:
        state["updated_at_unix_ns"] = time.time_ns()
        descriptor, temporary_name = tempfile.mkstemp(prefix=".trace-", dir=self.state_dir)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(state, handle, separators=(",", ":"), sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    @staticmethod
    def _context(state: dict[str, Any], actor_id: str) -> TraceContext:
        actor = state["actors"][actor_id]
        return TraceContext(
            trace_id=state["trace_id"],
            trace_token=state["trace_token"],
            actor_id=actor["actor_id"],
            actor_type=actor.get("actor_type", "subagent"),
            actor_token=actor["actor_token"],
            parent_actor_id=actor.get("parent_actor_id"),
            session_id=state["session_id"],
        )

    def get(self, session_id: str, actor_id: str | None = None) -> TraceContext:
        if not session_id:
            raise TraceContextError("Codex hook event has no session_id")
        requested_actor = actor_id or ROOT_ACTOR_ID
        path = self._state_path(session_id)
        with self._lock():
            state = self._load(path, session_id)
            if requested_actor not in state["actors"]:
                requested_actor = ROOT_ACTOR_ID
            self._save(path, state)
            return self._context(state, requested_actor)

    def register_subagent(
        self,
        session_id: str,
        agent_id: str,
        agent_type: str | None = None,
        parent_actor_id: str | None = None,
    ) -> TraceContext:
        if not session_id or not agent_id:
            raise TraceContextError("SubagentStart requires session_id and agent_id")
        path = self._state_path(session_id)
        with self._lock():
            state = self._load(path, session_id)
            if agent_id not in state["actors"]:
                parent = parent_actor_id if parent_actor_id in state["actors"] else ROOT_ACTOR_ID
                state["actors"][agent_id] = {
                    "actor_id": agent_id,
                    "actor_type": agent_type or "subagent",
                    "actor_token": secrets.token_urlsafe(32),
                    "parent_actor_id": parent,
                    "created_at_unix_ns": time.time_ns(),
                }
            self._save(path, state)
            return self._context(state, agent_id)
