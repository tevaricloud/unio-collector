from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.dynamodb.cost_governance.evidence import DynamoDbCostGovernanceEvidence
    from unio_collector.scanners.dynamodb.cost_governance.scanner import DynamoDbCostGovernanceReviewScanner
    from unio_collector.scanners.dynamodb.helpers import (
        DYNAMODB_COST_EXPLORER_SERVICE_NAME,
        build_dynamodb_collector,
        enrich_dynamodb_records_with_cost_context,
        get_dynamodb_regional_cost_context,
        get_dynamodb_service_cost_context,
        is_dynamodb_cost_service,
        parse_decimal,
        resolve_cost_explorer_region,
    )
    from unio_collector.scanners.dynamodb.packs import DYNAMODB_SCANNER_MODULE_REGISTRATION, DYNAMODB_SCANNER_PACKS, DYNAMODB_SCANNER_TYPES
    from unio_collector.scanners.dynamodb.table_detail_scope import DynamoDbTableDetailScope


_EXPORTS = {
    "DYNAMODB_COST_EXPLORER_SERVICE_NAME": ("unio_collector.scanners.dynamodb.helpers", "DYNAMODB_COST_EXPLORER_SERVICE_NAME"),
    "DYNAMODB_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.dynamodb.packs", "DYNAMODB_SCANNER_MODULE_REGISTRATION"),
    "DYNAMODB_SCANNER_PACKS": ("unio_collector.scanners.dynamodb.packs", "DYNAMODB_SCANNER_PACKS"),
    "DYNAMODB_SCANNER_TYPES": ("unio_collector.scanners.dynamodb.packs", "DYNAMODB_SCANNER_TYPES"),
    "DynamoDbCostGovernanceEvidence": ("unio_collector.scanners.dynamodb.cost_governance.evidence", "DynamoDbCostGovernanceEvidence"),
    "DynamoDbCostGovernanceReviewScanner": ("unio_collector.scanners.dynamodb.cost_governance.scanner", "DynamoDbCostGovernanceReviewScanner"),
    "DynamoDbTableDetailScope": ("unio_collector.scanners.dynamodb.table_detail_scope", "DynamoDbTableDetailScope"),
    "build_dynamodb_collector": ("unio_collector.scanners.dynamodb.helpers", "build_dynamodb_collector"),
    "enrich_dynamodb_records_with_cost_context": ("unio_collector.scanners.dynamodb.helpers", "enrich_dynamodb_records_with_cost_context"),
    "get_dynamodb_regional_cost_context": ("unio_collector.scanners.dynamodb.helpers", "get_dynamodb_regional_cost_context"),
    "get_dynamodb_service_cost_context": ("unio_collector.scanners.dynamodb.helpers", "get_dynamodb_service_cost_context"),
    "is_dynamodb_cost_service": ("unio_collector.scanners.dynamodb.helpers", "is_dynamodb_cost_service"),
    "parse_decimal": ("unio_collector.scanners.dynamodb.helpers", "parse_decimal"),
    "resolve_cost_explorer_region": ("unio_collector.scanners.dynamodb.helpers", "resolve_cost_explorer_region"),
}

__all__ = [
    "DYNAMODB_COST_EXPLORER_SERVICE_NAME",
    "DYNAMODB_SCANNER_MODULE_REGISTRATION",
    "DYNAMODB_SCANNER_PACKS",
    "DYNAMODB_SCANNER_TYPES",
    "DynamoDbCostGovernanceEvidence",
    "DynamoDbCostGovernanceReviewScanner",
    "DynamoDbTableDetailScope",
    "build_dynamodb_collector",
    "enrich_dynamodb_records_with_cost_context",
    "get_dynamodb_regional_cost_context",
    "get_dynamodb_service_cost_context",
    "is_dynamodb_cost_service",
    "parse_decimal",
    "resolve_cost_explorer_region",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
