"""CloudWatch public exports.

The package keeps the historical ``unio_collector.aws.cloudwatch`` import surface
while loading collector classes lazily to avoid circular imports during metric
helper initialization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

__all__ = [
    "CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT",
    "CLOUDWATCH_LOG_METRIC_DETAIL_MODES",
    "CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES",
    "CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED",
    "CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE",
    "CloudWatchLogMetricCollectionOptions",
    "CloudWatchLogsCollector",
    "LogGroupActivityRecord",
    "LogGroupRecord",
    "RegionalLogGroupInventoryRecord",
    "get_log_group_metric_priority",
    "millis_to_datetime",
    "normalize_cloudwatch_log_metric_detail_mode",
    "normalize_cloudwatch_log_metric_prioritization_scope",
    "normalize_max_metric_log_groups",
    "normalize_max_metric_log_groups_per_region",
    "normalize_stored_bytes",
]

_EXPORT_MODULES = {
    "CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT": "unio_collector.aws.cloudwatch.log.constants",
    "CLOUDWATCH_LOG_METRIC_DETAIL_MODES": "unio_collector.aws.cloudwatch.log.constants",
    "CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES": "unio_collector.aws.cloudwatch.log.constants",
    "CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED": "unio_collector.aws.cloudwatch.log.constants",
    "CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE": ("unio_collector.aws.cloudwatch.log.constants"),
    "CloudWatchLogMetricCollectionOptions": ("unio_collector.aws.cloudwatch.log.metric_options"),
    "CloudWatchLogsCollector": "unio_collector.aws.cloudwatch.log.collector",
    "LogGroupActivityRecord": "unio_collector.aws.log.group.activity",
    "LogGroupRecord": "unio_collector.aws.log.group.record",
    "RegionalLogGroupInventoryRecord": "unio_collector.aws.regional.log_group_record",
    "get_log_group_metric_priority": "unio_collector.aws.cloudwatch.log.helpers",
    "millis_to_datetime": "unio_collector.aws.cloudwatch.log.helpers",
    "normalize_cloudwatch_log_metric_detail_mode": ("unio_collector.aws.cloudwatch.log.metric_options"),
    "normalize_cloudwatch_log_metric_prioritization_scope": ("unio_collector.aws.cloudwatch.log.metric_options"),
    "normalize_max_metric_log_groups": "unio_collector.aws.cloudwatch.log.metric_options",
    "normalize_max_metric_log_groups_per_region": ("unio_collector.aws.cloudwatch.log.metric_options"),
    "normalize_stored_bytes": "unio_collector.aws.cloudwatch.log.helpers",
}

if TYPE_CHECKING:
    from unio_collector.aws.cloudwatch.log.collector import CloudWatchLogsCollector
    from unio_collector.aws.cloudwatch.log.constants import (
        CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
        CLOUDWATCH_LOG_METRIC_DETAIL_MODES,
        CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES,
        CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED,
        CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE,
    )
    from unio_collector.aws.cloudwatch.log.helpers import (
        get_log_group_metric_priority,
        millis_to_datetime,
        normalize_stored_bytes,
    )
    from unio_collector.aws.cloudwatch.log.metric_options import (
        CloudWatchLogMetricCollectionOptions,
        normalize_cloudwatch_log_metric_detail_mode,
        normalize_cloudwatch_log_metric_prioritization_scope,
        normalize_max_metric_log_groups,
        normalize_max_metric_log_groups_per_region,
    )
    from unio_collector.aws.log.group.activity import LogGroupActivityRecord
    from unio_collector.aws.log.group.record import LogGroupRecord
    from unio_collector.aws.regional.log_group_record import RegionalLogGroupInventoryRecord


def __getattr__(name: str) -> Any:  # noqa: ANN401
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    module = __import__(module_name, fromlist=[name])
    return getattr(module, name)
