from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.providers.finding_source import FindingSource as Finding


@dataclass(frozen=True)
class CurDataExportEvidence:  # noqa: D101
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    collection_evidence_version: int = 0
    billing_facts: dict[str, Any] = field(default_factory=dict)
