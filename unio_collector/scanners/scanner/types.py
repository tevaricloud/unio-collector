from __future__ import annotations  # noqa: D100

from typing import Literal

Maturity = Literal["experimental", "basic", "stable"]
ScannerRiskLevel = Literal["low", "medium", "high"]
RequiredPermissionLevel = Literal["read_only", "write_limited", "admin_like"]
ScannerExecutionPhase = Literal["baseline", "independent", "dependent"]
ScannerAnalysisBoundary = Literal[
    "result_bundle_only",
    "strict_evidence_only_ready",
]
