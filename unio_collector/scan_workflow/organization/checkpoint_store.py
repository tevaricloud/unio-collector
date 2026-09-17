"""Atomic organization checkpoint schema-v2 persistence."""

from __future__ import annotations

# ruff: noqa: ANN401, FBT001
import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector.core.atomic_artifact import write_text_atomically

if TYPE_CHECKING:
    from pathlib import Path


class OrganizationCheckpointStore:
    """Load and atomically replace local organization lifecycle state."""

    schema_version = 2

    def transition(
        self,
        state: dict[str, Any],
        path: Path,
        lock: Any,
        alias: str,
        stage: str,
        attempt: int,
    ) -> None:
        """Persist one in-progress account lifecycle transition."""
        with lock:
            state["accounts"][alias] = {
                "status": "running",
                "stage": stage,
                "attempts": attempt,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        self.write(path, state, lock)

    def write(self, path: Path, state: dict[str, Any], lock: Any) -> None:
        """Atomically persist checkpoint state through a unique sibling file."""
        with lock:
            write_text_atomically(path, json.dumps(state, indent=2, sort_keys=True) + "\n")

    def load(self, path: Path, fingerprint: str, resume: bool) -> dict[str, Any]:
        """Load only a matching schema-v2 resume request."""
        if not resume or not path.exists():
            return {}
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("schema_version") != self.schema_version:
            message = "Legacy organization checkpoint schema v1 cannot be resumed; restart the organization operation."
            raise ValueError(message)
        if state.get("request_fingerprint") != fingerprint:
            message = "Organization resume request fingerprint does not match the saved run."
            raise ValueError(message)
        return state


__all__ = ["OrganizationCheckpointStore"]
