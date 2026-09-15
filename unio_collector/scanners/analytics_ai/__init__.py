from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.analytics_ai.athena.evidence import AthenaQueryEfficiencyReviewEvidence
    from unio_collector.scanners.analytics_ai.athena.scanner import AthenaQueryEfficiencyReviewScanner
    from unio_collector.scanners.analytics_ai.bedrock.evidence import BedrockCostReviewEvidence
    from unio_collector.scanners.analytics_ai.bedrock.scanner import BedrockCostReviewScanner
    from unio_collector.scanners.analytics_ai.execution_detail import AnalyticsAiExecutionDetailSpec
    from unio_collector.scanners.analytics_ai.glue.evidence import GlueJobCrawlerCostReviewEvidence
    from unio_collector.scanners.analytics_ai.glue.scanner import GlueJobCrawlerCostReviewScanner
    from unio_collector.scanners.analytics_ai.helpers import (
        ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES,
        ANALYTICS_AI_EXECUTION_DETAIL_SPECS,
        AnalyticsAiRecord,
        add_analytics_ai_cost_context,
        build_analytics_ai_collector,
        build_analytics_ai_execution_detail_note,
        has_analytics_ai_cost_context,
        record_analytics_ai_execution_detail,
        sum_analytics_ai_record_fields,
    )
    from unio_collector.scanners.analytics_ai.packs import ANALYTICS_AI_SCANNER_PACKS, ANALYTICS_AI_SCANNER_TYPES
    from unio_collector.scanners.analytics_ai.sagemaker.evidence import SageMakerCostReviewEvidence
    from unio_collector.scanners.analytics_ai.sagemaker.scanner import SageMakerCostReviewScanner


_EXPORTS = {
    "ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES": ("unio_collector.scanners.analytics_ai.helpers", "ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES"),
    "ANALYTICS_AI_EXECUTION_DETAIL_SPECS": ("unio_collector.scanners.analytics_ai.helpers", "ANALYTICS_AI_EXECUTION_DETAIL_SPECS"),
    "ANALYTICS_AI_SCANNER_PACKS": ("unio_collector.scanners.analytics_ai.packs", "ANALYTICS_AI_SCANNER_PACKS"),
    "ANALYTICS_AI_SCANNER_TYPES": ("unio_collector.scanners.analytics_ai.packs", "ANALYTICS_AI_SCANNER_TYPES"),
    "AnalyticsAiExecutionDetailSpec": ("unio_collector.scanners.analytics_ai.execution_detail", "AnalyticsAiExecutionDetailSpec"),
    "AnalyticsAiRecord": ("unio_collector.scanners.analytics_ai.helpers", "AnalyticsAiRecord"),
    "AthenaQueryEfficiencyReviewEvidence": ("unio_collector.scanners.analytics_ai.athena.evidence", "AthenaQueryEfficiencyReviewEvidence"),
    "AthenaQueryEfficiencyReviewScanner": ("unio_collector.scanners.analytics_ai.athena.scanner", "AthenaQueryEfficiencyReviewScanner"),
    "BedrockCostReviewEvidence": ("unio_collector.scanners.analytics_ai.bedrock.evidence", "BedrockCostReviewEvidence"),
    "BedrockCostReviewScanner": ("unio_collector.scanners.analytics_ai.bedrock.scanner", "BedrockCostReviewScanner"),
    "GlueJobCrawlerCostReviewEvidence": ("unio_collector.scanners.analytics_ai.glue.evidence", "GlueJobCrawlerCostReviewEvidence"),
    "GlueJobCrawlerCostReviewScanner": ("unio_collector.scanners.analytics_ai.glue.scanner", "GlueJobCrawlerCostReviewScanner"),
    "SageMakerCostReviewEvidence": ("unio_collector.scanners.analytics_ai.sagemaker.evidence", "SageMakerCostReviewEvidence"),
    "SageMakerCostReviewScanner": ("unio_collector.scanners.analytics_ai.sagemaker.scanner", "SageMakerCostReviewScanner"),
    "add_analytics_ai_cost_context": ("unio_collector.scanners.analytics_ai.helpers", "add_analytics_ai_cost_context"),
    "build_analytics_ai_collector": ("unio_collector.scanners.analytics_ai.helpers", "build_analytics_ai_collector"),
    "build_analytics_ai_execution_detail_note": ("unio_collector.scanners.analytics_ai.helpers", "build_analytics_ai_execution_detail_note"),
    "has_analytics_ai_cost_context": ("unio_collector.scanners.analytics_ai.helpers", "has_analytics_ai_cost_context"),
    "record_analytics_ai_execution_detail": ("unio_collector.scanners.analytics_ai.helpers", "record_analytics_ai_execution_detail"),
    "sum_analytics_ai_record_fields": ("unio_collector.scanners.analytics_ai.helpers", "sum_analytics_ai_record_fields"),
}

__all__ = [
    "ANALYTICS_AI_COST_EXPLORER_SERVICE_NAMES",
    "ANALYTICS_AI_EXECUTION_DETAIL_SPECS",
    "ANALYTICS_AI_SCANNER_PACKS",
    "ANALYTICS_AI_SCANNER_TYPES",
    "AnalyticsAiExecutionDetailSpec",
    "AnalyticsAiRecord",
    "AthenaQueryEfficiencyReviewEvidence",
    "AthenaQueryEfficiencyReviewScanner",
    "BedrockCostReviewEvidence",
    "BedrockCostReviewScanner",
    "GlueJobCrawlerCostReviewEvidence",
    "GlueJobCrawlerCostReviewScanner",
    "SageMakerCostReviewEvidence",
    "SageMakerCostReviewScanner",
    "add_analytics_ai_cost_context",
    "build_analytics_ai_collector",
    "build_analytics_ai_execution_detail_note",
    "has_analytics_ai_cost_context",
    "record_analytics_ai_execution_detail",
    "sum_analytics_ai_record_fields",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
