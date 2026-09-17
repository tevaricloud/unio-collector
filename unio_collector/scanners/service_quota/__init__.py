"""Compatibility exports for Service Quotas; collectors use canonical modules."""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.service_quota.check_spec import ServiceQuotaCheckSpec
    from unio_collector.scanners.service_quota.constants import DEFAULT_SERVICE_QUOTA_REMAINING_THRESHOLD
    from unio_collector.scanners.service_quota.matcher import ServiceQuotaMatcher
    from unio_collector.scanners.service_quota.parsing import normalize_quota_text, parse_quota_value
    from unio_collector.scanners.service_quota.payload import build_service_quota_payload
    from unio_collector.scanners.service_quota.proximity import UsageCounter
    from unio_collector.scanners.service_quota.reader.builder import ServiceQuotaReaderContextBuilder
    from unio_collector.scanners.service_quota.reader.context import ServiceQuotaReaderContext
    from unio_collector.scanners.service_quota.record import ServiceQuotaRecord
    from unio_collector.scanners.service_quota.supported_checks import SUPPORTED_SERVICE_QUOTA_CHECKS
    from unio_collector.scanners.service_quota.threshold_policy import ServiceQuotaThresholdPolicy
    from unio_collector.scanners.service_quota.usage import ServiceQuotaUsage
    from unio_collector.scanners.service_quota.utils import (
        calculate_utilization_percent,
        classify_quota_attention,
        describe_quota_record,
        recommend_quota_action,
    )


_EXPORTS = {
    "DEFAULT_SERVICE_QUOTA_REMAINING_THRESHOLD": ("unio_collector.scanners.service_quota.constants", "DEFAULT_SERVICE_QUOTA_REMAINING_THRESHOLD"),
    "SUPPORTED_SERVICE_QUOTA_CHECKS": ("unio_collector.scanners.service_quota.supported_checks", "SUPPORTED_SERVICE_QUOTA_CHECKS"),
    "ServiceQuotaCheckSpec": ("unio_collector.scanners.service_quota.check_spec", "ServiceQuotaCheckSpec"),
    "ServiceQuotaMatcher": ("unio_collector.scanners.service_quota.matcher", "ServiceQuotaMatcher"),
    "ServiceQuotaReaderContext": ("unio_collector.scanners.service_quota.reader.context", "ServiceQuotaReaderContext"),
    "ServiceQuotaReaderContextBuilder": ("unio_collector.scanners.service_quota.reader.builder", "ServiceQuotaReaderContextBuilder"),
    "ServiceQuotaRecord": ("unio_collector.scanners.service_quota.record", "ServiceQuotaRecord"),
    "ServiceQuotaThresholdPolicy": ("unio_collector.scanners.service_quota.threshold_policy", "ServiceQuotaThresholdPolicy"),
    "ServiceQuotaUsage": ("unio_collector.scanners.service_quota.usage", "ServiceQuotaUsage"),
    "UsageCounter": ("unio_collector.scanners.service_quota.proximity", "UsageCounter"),
    "build_service_quota_payload": ("unio_collector.scanners.service_quota.payload", "build_service_quota_payload"),
    "calculate_utilization_percent": ("unio_collector.scanners.service_quota.utils", "calculate_utilization_percent"),
    "classify_quota_attention": ("unio_collector.scanners.service_quota.utils", "classify_quota_attention"),
    "describe_quota_record": ("unio_collector.scanners.service_quota.utils", "describe_quota_record"),
    "normalize_quota_text": ("unio_collector.scanners.service_quota.parsing", "normalize_quota_text"),
    "parse_quota_value": ("unio_collector.scanners.service_quota.parsing", "parse_quota_value"),
    "recommend_quota_action": ("unio_collector.scanners.service_quota.utils", "recommend_quota_action"),
}

__all__ = [
    "DEFAULT_SERVICE_QUOTA_REMAINING_THRESHOLD",
    "SUPPORTED_SERVICE_QUOTA_CHECKS",
    "ServiceQuotaCheckSpec",
    "ServiceQuotaMatcher",
    "ServiceQuotaReaderContext",
    "ServiceQuotaReaderContextBuilder",
    "ServiceQuotaRecord",
    "ServiceQuotaThresholdPolicy",
    "ServiceQuotaUsage",
    "UsageCounter",
    "build_service_quota_payload",
    "calculate_utilization_percent",
    "classify_quota_attention",
    "describe_quota_record",
    "normalize_quota_text",
    "parse_quota_value",
    "recommend_quota_action",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, symbol_name = _EXPORTS[name]
    symbol = getattr(import_module(module_name), symbol_name)
    globals()[name] = symbol
    return symbol
