"""Lazy compatibility exports for scan-scope helpers."""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "AWS_REGION_PATTERN": (
        "unio_collector.scan_workflow.scope.billing.region_coverage",
        "AWS_REGION_PATTERN",
    ),
    "CHARGED_SERVICE_COVERAGE_STATUSES": (
        "unio_collector.scan_workflow.scope.charged.services_coverage",
        "CHARGED_SERVICE_COVERAGE_STATUSES",
    ),
    "DEFAULT_MATERIALITY_THRESHOLD": (
        "unio_collector.scan_workflow.scope.billing.region_coverage",
        "DEFAULT_MATERIALITY_THRESHOLD",
    ),
    "GLOBAL_REGION_VALUES": (
        "unio_collector.scan_workflow.scope.billing.region_coverage",
        "GLOBAL_REGION_VALUES",
    ),
    "ONLY_SCANNER_DISABLED_REASON": (
        "unio_collector.scan_workflow.scope.scanner.assessor",
        "ONLY_SCANNER_DISABLED_REASON",
    ),
    "BillingRegionCoverageBuilder": (
        "unio_collector.scan_workflow.scope.billing.region_coverage",
        "BillingRegionCoverageBuilder",
    ),
    "BillingRegionCoveragePayload": (
        "unio_collector.scan_workflow.scope.billing.coverage_payload",
        "BillingRegionCoveragePayload",
    ),
    "ChargedServiceCoverageRow": (
        "unio_collector.scan_workflow.scope.charged.service_row",
        "ChargedServiceCoverageRow",
    ),
    "ChargedServicesCoverageBuilder": (
        "unio_collector.scan_workflow.scope.charged.services_coverage",
        "ChargedServicesCoverageBuilder",
    ),
    "ScannerScopeAssessment": (
        "unio_collector.scan_workflow.scope.scanner.assessment",
        "ScannerScopeAssessment",
    ),
    "ScannerScopeAssessor": (
        "unio_collector.scan_workflow.scope.scanner.assessor",
        "ScannerScopeAssessor",
    ),
    "bundle_currency": (
        "unio_collector.scan_workflow.scope.charged.services_coverage",
        "bundle_currency",
    ),
    "normalize_billing_region": (
        "unio_collector.scan_workflow.scope.billing.region_coverage",
        "normalize_billing_region",
    ),
    "normalize_service_name": (
        "unio_collector.scan_workflow.scope.charged.services_coverage",
        "normalize_service_name",
    ),
}

__all__ = [
    "AWS_REGION_PATTERN",
    "CHARGED_SERVICE_COVERAGE_STATUSES",
    "DEFAULT_MATERIALITY_THRESHOLD",
    "GLOBAL_REGION_VALUES",
    "ONLY_SCANNER_DISABLED_REASON",
    "BillingRegionCoverageBuilder",
    "BillingRegionCoveragePayload",
    "ChargedServiceCoverageRow",
    "ChargedServicesCoverageBuilder",
    "ScannerScopeAssessment",
    "ScannerScopeAssessor",
    "bundle_currency",
    "normalize_billing_region",
    "normalize_service_name",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve a historical scan-scope export from its canonical module."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
