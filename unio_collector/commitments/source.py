"""Per-operation AWS commitment evidence outcome contract."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommitmentSourceOutcome:
    """Record the result of one independent read-only evidence source."""

    source: str
    status: str
    record_count: int = 0
    limitation: str | None = None
