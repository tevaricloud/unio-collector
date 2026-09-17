from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ScannerAnalysisBoundarySummary:
    """Registry-level readiness for strict evidence-only scanner analysis."""

    scanner_count: int
    by_analysis_boundary: dict[str, int]
    strict_evidence_only_ready_count: int
    result_bundle_only_count: int
    deferred_scanner_ids: tuple[str, ...]

    def convert_to_dict(self) -> dict[str, Any]:  # noqa: D102
        return {
            "scanner_count": self.scanner_count,
            "by_analysis_boundary": dict(self.by_analysis_boundary),
            "strict_evidence_only_ready_count": (self.strict_evidence_only_ready_count),
            "result_bundle_only_count": self.result_bundle_only_count,
            "deferred_scanner_ids": list(self.deferred_scanner_ids),
        }
