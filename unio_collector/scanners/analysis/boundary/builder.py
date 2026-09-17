from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.analysis.boundary.summary import (
    ScannerAnalysisBoundarySummary,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from unio_collector.scanners.scanner.definition import ScannerDefinition


class ScannerAnalysisBoundarySummaryBuilder:
    """Builds strict evidence-only readiness summaries from scanner metadata."""

    def build(  # noqa: D102
        self,
        definitions: Iterable[ScannerDefinition],
    ) -> ScannerAnalysisBoundarySummary:
        ordered = sorted(definitions, key=lambda item: item.scanner_id)
        by_boundary: dict[str, int] = {
            "result_bundle_only": 0,
            "strict_evidence_only_ready": 0,
        }
        deferred: list[str] = []
        strict_ready = 0
        result_only = 0
        for definition in ordered:
            boundary = definition.analysis_boundary
            by_boundary[boundary] = by_boundary.get(boundary, 0) + 1
            if boundary == "strict_evidence_only_ready":
                strict_ready += 1
            else:
                result_only += 1
                deferred.append(definition.scanner_id)
        return ScannerAnalysisBoundarySummary(
            scanner_count=len(ordered),
            by_analysis_boundary=dict(sorted(by_boundary.items())),
            strict_evidence_only_ready_count=strict_ready,
            result_bundle_only_count=result_only,
            deferred_scanner_ids=tuple(deferred),
        )
