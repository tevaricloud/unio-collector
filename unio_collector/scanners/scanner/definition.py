from __future__ import annotations  # noqa: D100

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.permission import ScannerIamRequirement
    from unio_collector.scanners.scanner.types import (
        Maturity,
        RequiredPermissionLevel,
        ScannerAnalysisBoundary,
        ScannerExecutionPhase,
        ScannerRiskLevel,
    )


@dataclass(frozen=True)
class ScannerDefinition:
    """Registry metadata describing one scanner."""

    scanner_id: str
    display_name: str
    description: str
    aws_services: tuple[str, ...]
    resource_types: tuple[str, ...]
    default_enabled: bool
    supports_regions: bool
    required_iam_actions: tuple[str, ...]
    required_permission_level: RequiredPermissionLevel
    aws_api_calls: tuple[str, ...]
    risk_level: ScannerRiskLevel
    output_finding_types: tuple[str, ...]
    maturity: Maturity
    limitations: tuple[str, ...]
    conditional_iam_actions: tuple[str, ...] = ()
    iam_requirements: tuple[ScannerIamRequirement, ...] | None = None
    cloudwatch_namespaces_used: tuple[str, ...] = ()
    metrics_used: tuple[str, ...] = ()
    explanation: str = ""
    execution_phase: ScannerExecutionPhase = "independent"
    depends_on_scanner_ids: tuple[str, ...] = ()
    may_incur_charges: bool = False
    chargeable_reason: str = ""
    analysis_boundary: ScannerAnalysisBoundary = "result_bundle_only"
    analysis_boundary_reason: str = "Scanner currently produces deterministic findings during scan execution; strict evidence-only analyzer replay is deferred."
    collector_factory_path: str = "unio_collector.scanners.collection.factory:build_collector_scanner"

    def convert_to_dict(self) -> dict:  # noqa: D102
        return asdict(self)
