"""Describe declared offline evidence replay support without scanner execution."""

from __future__ import annotations

from unio_collector.scanners.registry.catalog import list_scanners


def build_scanner_analysis_boundary_summary() -> dict[str, object]:  # noqa: D103
    from unio_collector.scanners.analysis.boundary.builder import (  # noqa: PLC0415
        ScannerAnalysisBoundarySummaryBuilder,
    )

    return ScannerAnalysisBoundarySummaryBuilder().build(list_scanners()).convert_to_dict()
