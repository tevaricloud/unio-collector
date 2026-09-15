"""Prepared metadata and records shared by evidence bundle writers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True)
class EvidenceBundleSource:
    """Carry supplied bundle facts without retaining a finding model or builder."""

    generated_at: datetime
    account_context: dict[str, Any]
    scan_period: object
    summary: dict[str, Any]
    compatibility_payload: dict[str, Any]
    finding_count: int
    evidence_records: list[dict[str, Any]]
