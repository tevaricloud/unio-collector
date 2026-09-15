from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.platform.api_gateway.evidence import ApiGatewayCostReviewEvidence
    from unio_collector.scanners.platform.api_gateway.scanner import ApiGatewayCostReviewScanner
    from unio_collector.scanners.platform.ecs.evidence import EcsCostGovernanceReviewEvidence
    from unio_collector.scanners.platform.ecs.regional_scope import EcsRegionalCollectionScope
    from unio_collector.scanners.platform.ecs.scanner import EcsCostGovernanceReviewScanner
    from unio_collector.scanners.platform.eks.evidence import EksCostRiskReviewEvidence
    from unio_collector.scanners.platform.eks.scanner import EksCostRiskReviewScanner
    from unio_collector.scanners.platform.elasticache.evidence import ElastiCacheCostReviewEvidence
    from unio_collector.scanners.platform.elasticache.scanner import ElastiCacheCostReviewScanner
    from unio_collector.scanners.platform.managed.helpers import (
        add_managed_platform_cost_context,
        build_managed_platform_billing_context_summary,
        build_managed_platform_collector,
        build_managed_platform_execution_detail_note,
        collect_managed_platform_regional_costs,
        has_cost_context,
        record_managed_platform_execution_detail,
    )
    from unio_collector.scanners.platform.managed.types import PLATFORM_COST_EXPLORER_SERVICE_NAMES, ManagedPlatformRecord, TManagedPlatformRecord
    from unio_collector.scanners.platform.opensearch.evidence import OpenSearchCostReviewEvidence
    from unio_collector.scanners.platform.opensearch.scanner import OpenSearchCostReviewScanner
    from unio_collector.scanners.platform.packs import PLATFORM_SCANNER_PACKS, PLATFORM_SCANNER_TYPES
    from unio_collector.scanners.platform.redshift.evidence import RedshiftCostReviewEvidence
    from unio_collector.scanners.platform.redshift.scanner import RedshiftCostReviewScanner


_EXPORTS = {
    "PLATFORM_COST_EXPLORER_SERVICE_NAMES": ("unio_collector.scanners.platform.managed.types", "PLATFORM_COST_EXPLORER_SERVICE_NAMES"),
    "PLATFORM_SCANNER_PACKS": ("unio_collector.scanners.platform.packs", "PLATFORM_SCANNER_PACKS"),
    "PLATFORM_SCANNER_TYPES": ("unio_collector.scanners.platform.packs", "PLATFORM_SCANNER_TYPES"),
    "ApiGatewayCostReviewEvidence": ("unio_collector.scanners.platform.api_gateway.evidence", "ApiGatewayCostReviewEvidence"),
    "ApiGatewayCostReviewScanner": ("unio_collector.scanners.platform.api_gateway.scanner", "ApiGatewayCostReviewScanner"),
    "EcsCostGovernanceReviewEvidence": ("unio_collector.scanners.platform.ecs.evidence", "EcsCostGovernanceReviewEvidence"),
    "EcsCostGovernanceReviewScanner": ("unio_collector.scanners.platform.ecs.scanner", "EcsCostGovernanceReviewScanner"),
    "EcsRegionalCollectionScope": ("unio_collector.scanners.platform.ecs.regional_scope", "EcsRegionalCollectionScope"),
    "EksCostRiskReviewEvidence": ("unio_collector.scanners.platform.eks.evidence", "EksCostRiskReviewEvidence"),
    "EksCostRiskReviewScanner": ("unio_collector.scanners.platform.eks.scanner", "EksCostRiskReviewScanner"),
    "ElastiCacheCostReviewEvidence": ("unio_collector.scanners.platform.elasticache.evidence", "ElastiCacheCostReviewEvidence"),
    "ElastiCacheCostReviewScanner": ("unio_collector.scanners.platform.elasticache.scanner", "ElastiCacheCostReviewScanner"),
    "ManagedPlatformRecord": ("unio_collector.scanners.platform.managed.types", "ManagedPlatformRecord"),
    "OpenSearchCostReviewEvidence": ("unio_collector.scanners.platform.opensearch.evidence", "OpenSearchCostReviewEvidence"),
    "OpenSearchCostReviewScanner": ("unio_collector.scanners.platform.opensearch.scanner", "OpenSearchCostReviewScanner"),
    "RedshiftCostReviewEvidence": ("unio_collector.scanners.platform.redshift.evidence", "RedshiftCostReviewEvidence"),
    "RedshiftCostReviewScanner": ("unio_collector.scanners.platform.redshift.scanner", "RedshiftCostReviewScanner"),
    "TManagedPlatformRecord": ("unio_collector.scanners.platform.managed.types", "TManagedPlatformRecord"),
    "add_managed_platform_cost_context": ("unio_collector.scanners.platform.managed.helpers", "add_managed_platform_cost_context"),
    "build_managed_platform_billing_context_summary": ("unio_collector.scanners.platform.managed.helpers", "build_managed_platform_billing_context_summary"),
    "build_managed_platform_collector": ("unio_collector.scanners.platform.managed.helpers", "build_managed_platform_collector"),
    "build_managed_platform_execution_detail_note": ("unio_collector.scanners.platform.managed.helpers", "build_managed_platform_execution_detail_note"),
    "collect_managed_platform_regional_costs": ("unio_collector.scanners.platform.managed.helpers", "collect_managed_platform_regional_costs"),
    "has_cost_context": ("unio_collector.scanners.platform.managed.helpers", "has_cost_context"),
    "record_managed_platform_execution_detail": ("unio_collector.scanners.platform.managed.helpers", "record_managed_platform_execution_detail"),
}

__all__ = [
    "PLATFORM_COST_EXPLORER_SERVICE_NAMES",
    "PLATFORM_SCANNER_PACKS",
    "PLATFORM_SCANNER_TYPES",
    "ApiGatewayCostReviewEvidence",
    "ApiGatewayCostReviewScanner",
    "EcsCostGovernanceReviewEvidence",
    "EcsCostGovernanceReviewScanner",
    "EcsRegionalCollectionScope",
    "EksCostRiskReviewEvidence",
    "EksCostRiskReviewScanner",
    "ElastiCacheCostReviewEvidence",
    "ElastiCacheCostReviewScanner",
    "ManagedPlatformRecord",
    "OpenSearchCostReviewEvidence",
    "OpenSearchCostReviewScanner",
    "RedshiftCostReviewEvidence",
    "RedshiftCostReviewScanner",
    "TManagedPlatformRecord",
    "add_managed_platform_cost_context",
    "build_managed_platform_billing_context_summary",
    "build_managed_platform_collector",
    "build_managed_platform_execution_detail_note",
    "collect_managed_platform_regional_costs",
    "has_cost_context",
    "record_managed_platform_execution_detail",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
