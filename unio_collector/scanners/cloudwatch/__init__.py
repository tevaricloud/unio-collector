from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.cloudwatch.idle_log import CloudWatchIdleLogReviewScanner
    from unio_collector.scanners.cloudwatch.log_activity.scanner import CloudWatchLogActivityScanner
    from unio_collector.scanners.cloudwatch.log_cost.relevance import is_log_cost_relevance_finding
    from unio_collector.scanners.cloudwatch.log_cost.scanner import CloudWatchLogCostRelevanceScanner
    from unio_collector.scanners.cloudwatch.log_retention.scanner import CloudWatchLogRetentionScanner
    from unio_collector.scanners.cloudwatch.packs import CLOUDWATCH_SCANNER_MODULE_REGISTRATION, CLOUDWATCH_SCANNER_PACKS, CLOUDWATCH_SCANNER_TYPES

_EXPORTS = {
    "CLOUDWATCH_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.cloudwatch.packs", "CLOUDWATCH_SCANNER_MODULE_REGISTRATION"),
    "CLOUDWATCH_SCANNER_PACKS": ("unio_collector.scanners.cloudwatch.packs", "CLOUDWATCH_SCANNER_PACKS"),
    "CLOUDWATCH_SCANNER_TYPES": ("unio_collector.scanners.cloudwatch.packs", "CLOUDWATCH_SCANNER_TYPES"),
    "CloudWatchIdleLogReviewScanner": ("unio_collector.scanners.cloudwatch.idle_log", "CloudWatchIdleLogReviewScanner"),
    "CloudWatchLogActivityScanner": ("unio_collector.scanners.cloudwatch.log_activity.scanner", "CloudWatchLogActivityScanner"),
    "CloudWatchLogCostRelevanceScanner": ("unio_collector.scanners.cloudwatch.log_cost.scanner", "CloudWatchLogCostRelevanceScanner"),
    "CloudWatchLogRetentionScanner": ("unio_collector.scanners.cloudwatch.log_retention.scanner", "CloudWatchLogRetentionScanner"),
    "is_log_cost_relevance_finding": ("unio_collector.scanners.cloudwatch.log_cost.relevance", "is_log_cost_relevance_finding"),
}

__all__ = [
    "CLOUDWATCH_SCANNER_MODULE_REGISTRATION",
    "CLOUDWATCH_SCANNER_PACKS",
    "CLOUDWATCH_SCANNER_TYPES",
    "CloudWatchIdleLogReviewScanner",
    "CloudWatchLogActivityScanner",
    "CloudWatchLogCostRelevanceScanner",
    "CloudWatchLogRetentionScanner",
    "is_log_cost_relevance_finding",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
