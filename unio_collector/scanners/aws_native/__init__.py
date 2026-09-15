from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.aws_native.compute_optimizer_scanner import ComputeOptimizerRecommendationReviewScanner
    from unio_collector.scanners.aws_native.cost_hub_scanner import CostOptimizationHubRecommendationReviewScanner
    from unio_collector.scanners.aws_native.helpers import (
        MAX_NATIVE_RECOMMENDATION_RECORDS,
        compact_dict,
        deduplicate_strings,
        extract_estimated_savings,
        first_dict,
        first_text,
        get_dict,
        get_first_list,
        infer_cost_optimization_hub_service,
        safe_finding_id,
    )
    from unio_collector.scanners.aws_native.packs import (
        AWS_NATIVE_RECOMMENDATION_SCANNER_MODULE_REGISTRATION,
        AWS_NATIVE_RECOMMENDATION_SCANNER_PACKS,
        AWS_NATIVE_RECOMMENDATION_SCANNER_TYPES,
    )
    from unio_collector.scanners.aws_native.status_policy import AwsNativeRecommendationStatusPolicy


_EXPORTS = {
    "AWS_NATIVE_RECOMMENDATION_SCANNER_MODULE_REGISTRATION": (
        "unio_collector.scanners.aws_native.packs",
        "AWS_NATIVE_RECOMMENDATION_SCANNER_MODULE_REGISTRATION",
    ),
    "AWS_NATIVE_RECOMMENDATION_SCANNER_PACKS": ("unio_collector.scanners.aws_native.packs", "AWS_NATIVE_RECOMMENDATION_SCANNER_PACKS"),
    "AWS_NATIVE_RECOMMENDATION_SCANNER_TYPES": ("unio_collector.scanners.aws_native.packs", "AWS_NATIVE_RECOMMENDATION_SCANNER_TYPES"),
    "MAX_NATIVE_RECOMMENDATION_RECORDS": ("unio_collector.scanners.aws_native.helpers", "MAX_NATIVE_RECOMMENDATION_RECORDS"),
    "AwsNativeRecommendationStatusPolicy": ("unio_collector.scanners.aws_native.status_policy", "AwsNativeRecommendationStatusPolicy"),
    "ComputeOptimizerRecommendationReviewScanner": (
        "unio_collector.scanners.aws_native.compute_optimizer_scanner",
        "ComputeOptimizerRecommendationReviewScanner",
    ),
    "CostOptimizationHubRecommendationReviewScanner": ("unio_collector.scanners.aws_native.cost_hub_scanner", "CostOptimizationHubRecommendationReviewScanner"),
    "compact_dict": ("unio_collector.scanners.aws_native.helpers", "compact_dict"),
    "deduplicate_strings": ("unio_collector.scanners.aws_native.helpers", "deduplicate_strings"),
    "extract_estimated_savings": ("unio_collector.scanners.aws_native.helpers", "extract_estimated_savings"),
    "first_dict": ("unio_collector.scanners.aws_native.helpers", "first_dict"),
    "first_text": ("unio_collector.scanners.aws_native.helpers", "first_text"),
    "get_dict": ("unio_collector.scanners.aws_native.helpers", "get_dict"),
    "get_first_list": ("unio_collector.scanners.aws_native.helpers", "get_first_list"),
    "infer_cost_optimization_hub_service": ("unio_collector.scanners.aws_native.helpers", "infer_cost_optimization_hub_service"),
    "safe_finding_id": ("unio_collector.scanners.aws_native.helpers", "safe_finding_id"),
}

__all__ = [
    "AWS_NATIVE_RECOMMENDATION_SCANNER_MODULE_REGISTRATION",
    "AWS_NATIVE_RECOMMENDATION_SCANNER_PACKS",
    "AWS_NATIVE_RECOMMENDATION_SCANNER_TYPES",
    "MAX_NATIVE_RECOMMENDATION_RECORDS",
    "AwsNativeRecommendationStatusPolicy",
    "ComputeOptimizerRecommendationReviewScanner",
    "CostOptimizationHubRecommendationReviewScanner",
    "compact_dict",
    "deduplicate_strings",
    "extract_estimated_savings",
    "first_dict",
    "first_text",
    "get_dict",
    "get_first_list",
    "infer_cost_optimization_hub_service",
    "safe_finding_id",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
