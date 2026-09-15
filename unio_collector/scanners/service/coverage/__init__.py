from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.core.parsing import parse_int_or_zero as parse_int
    from unio_collector.scanners.lightsail.cost_governance import LightsailCostGovernanceReviewScanner
    from unio_collector.scanners.route53.cost_governance import Route53CostGovernanceReviewScanner
    from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
    from unio_collector.scanners.service.coverage.helpers import count_records, stable_id
    from unio_collector.scanners.service.coverage.packs import SERVICE_COVERAGE_SCANNER_PACKS, SERVICE_COVERAGE_SCANNER_TYPES
    from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord
    from unio_collector.scanners.service.coverage.scanner import ServiceCoverageScanner
    from unio_collector.scanners.sns.cost_governance import SnsCostGovernanceReviewScanner
    from unio_collector.scanners.step_functions.cost_governance import StepFunctionsCostGovernanceReviewScanner


_EXPORTS = {
    "SERVICE_COVERAGE_SCANNER_PACKS": ("unio_collector.scanners.service.coverage.packs", "SERVICE_COVERAGE_SCANNER_PACKS"),
    "SERVICE_COVERAGE_SCANNER_TYPES": ("unio_collector.scanners.service.coverage.packs", "SERVICE_COVERAGE_SCANNER_TYPES"),
    "LightsailCostGovernanceReviewScanner": ("unio_collector.scanners.lightsail.cost_governance", "LightsailCostGovernanceReviewScanner"),
    "Route53CostGovernanceReviewScanner": ("unio_collector.scanners.route53.cost_governance", "Route53CostGovernanceReviewScanner"),
    "ServiceCoverageEvidence": ("unio_collector.scanners.service.coverage.evidence", "ServiceCoverageEvidence"),
    "ServiceCoverageRecord": ("unio_collector.scanners.service.coverage.record", "ServiceCoverageRecord"),
    "ServiceCoverageScanner": ("unio_collector.scanners.service.coverage.scanner", "ServiceCoverageScanner"),
    "SnsCostGovernanceReviewScanner": ("unio_collector.scanners.sns.cost_governance", "SnsCostGovernanceReviewScanner"),
    "StepFunctionsCostGovernanceReviewScanner": ("unio_collector.scanners.step_functions.cost_governance", "StepFunctionsCostGovernanceReviewScanner"),
    "count_records": ("unio_collector.scanners.service.coverage.helpers", "count_records"),
    "parse_int": ("unio_collector.core.parsing", "parse_int_or_zero"),
    "stable_id": ("unio_collector.scanners.service.coverage.helpers", "stable_id"),
}

__all__ = [
    "SERVICE_COVERAGE_SCANNER_PACKS",
    "SERVICE_COVERAGE_SCANNER_TYPES",
    "LightsailCostGovernanceReviewScanner",
    "Route53CostGovernanceReviewScanner",
    "ServiceCoverageEvidence",
    "ServiceCoverageRecord",
    "ServiceCoverageScanner",
    "SnsCostGovernanceReviewScanner",
    "StepFunctionsCostGovernanceReviewScanner",
    "count_records",
    "parse_int",
    "stable_id",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
