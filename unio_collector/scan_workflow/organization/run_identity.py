"""Organization execution run identity persistence."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def organization_run_id(output: Path) -> str:
    """Reuse a persisted run identity or create a new opaque identifier."""
    state = output / "state" / "organization-run-state.json"
    if state.exists():
        try:
            existing = json.loads(state.read_text(encoding="utf-8")).get("run_id")
            if existing:
                return str(existing)
        except (OSError, json.JSONDecodeError):
            pass
    return uuid.uuid4().hex[:12]


__all__ = ["organization_run_id"]
