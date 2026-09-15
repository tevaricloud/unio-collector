from __future__ import annotations  # noqa: D100

from dataclasses import dataclass

from unio_collector.aws.cloudwatch.log.constants import (
    CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
    CLOUDWATCH_LOG_METRIC_DETAIL_MODES,
    CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES,
)


@dataclass(frozen=True, init=False)
class CloudWatchLogMetricCollectionOptions:  # noqa: D101
    metric_detail_mode: str
    max_metric_log_groups_per_region: int
    metric_prioritization_scope: str
    max_metric_log_groups: int

    def __init__(  # noqa: D107
        self,
        metric_detail_mode: object = "full",
        max_metric_log_groups_per_region: object = 0,
        metric_prioritization_scope: object = "regional",
        max_metric_log_groups: object = 0,
    ) -> None:
        normalized_mode = normalize_cloudwatch_log_metric_detail_mode(
            metric_detail_mode,
        )
        normalized_limit = normalize_max_metric_log_groups_per_region(
            max_metric_log_groups_per_region,
        )
        normalized_scope = normalize_cloudwatch_log_metric_prioritization_scope(
            metric_prioritization_scope,
        )
        normalized_global_limit = normalize_max_metric_log_groups(max_metric_log_groups)
        if normalized_global_limit <= 0:
            normalized_global_limit = normalized_limit
        if normalized_mode == "full":
            normalized_limit = 0
            normalized_global_limit = 0
        object.__setattr__(
            self,
            "metric_detail_mode",
            normalized_mode,
        )
        object.__setattr__(
            self,
            "max_metric_log_groups_per_region",
            normalized_limit,
        )
        object.__setattr__(
            self,
            "metric_prioritization_scope",
            normalized_scope,
        )
        object.__setattr__(
            self,
            "max_metric_log_groups",
            normalized_global_limit,
        )

    def should_prioritize(self, log_group_count: int) -> bool:  # noqa: D102
        return (
            self.metric_detail_mode == "prioritized" and self.max_metric_log_groups_per_region > 0 and log_group_count > self.max_metric_log_groups_per_region
        )

    def should_prioritize_globally(self) -> bool:  # noqa: D102
        return self.metric_detail_mode == "prioritized" and self.metric_prioritization_scope == "global" and self.max_metric_log_groups > 0

    def convert_to_cache_key(self) -> tuple[str, int, str, int]:  # noqa: D102
        return (
            self.metric_detail_mode,
            self.max_metric_log_groups_per_region,
            self.metric_prioritization_scope,
            self.max_metric_log_groups,
        )


def normalize_cloudwatch_log_metric_detail_mode(value: object) -> str:  # noqa: D103
    normalized = str(value or "full").strip().lower()
    if normalized in CLOUDWATCH_LOG_METRIC_DETAIL_MODES:
        return normalized
    allowed = ", ".join(sorted(CLOUDWATCH_LOG_METRIC_DETAIL_MODES))
    msg = f"CloudWatch Logs metric_detail_mode must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_cloudwatch_log_metric_prioritization_scope(value: object) -> str:  # noqa: D103
    normalized = str(value or "regional").strip().lower()
    if normalized in CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES:
        return normalized
    allowed = ", ".join(sorted(CLOUDWATCH_LOG_METRIC_PRIORITIZATION_SCOPES))
    msg = f"CloudWatch Logs metric_prioritization_scope must be one of {allowed}; got {value!r}."
    raise ValueError(
        msg,
    )


def normalize_max_metric_log_groups_per_region(value: object) -> int:  # noqa: D103
    if isinstance(value, bool):
        return CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        parsed = int(value)
    else:
        msg = f"CloudWatch Logs max_metric_log_groups_per_region must be an integer; got {value!r}."
        raise ValueError(
            msg,
        )
    if parsed < 0:
        return CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT
    return parsed


def normalize_max_metric_log_groups(value: object) -> int:  # noqa: D103
    if isinstance(value, bool):
        return CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        parsed = int(value)
    else:
        msg = f"CloudWatch Logs max_metric_log_groups must be an integer; got {value!r}."
        raise ValueError(
            msg,
        )
    if parsed < 0:
        return CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT
    return parsed
