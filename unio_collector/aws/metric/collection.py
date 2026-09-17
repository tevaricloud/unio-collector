"""Neutral CloudWatch aggregates and request-window grouping."""

from __future__ import annotations

from decimal import Decimal, DecimalException
from typing import TYPE_CHECKING

from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.read.reason import MetricReadReason
from unio_collector.aws.metric.read.values import MetricReadValues
from unio_collector.aws.metric.summary import MetricSummary

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.metric.request import MetricRequest


def group_metric_requests_by_window(requests: list[MetricRequest]) -> list[list[MetricRequest]]:
    """Preserve request order within each identical provider query window."""
    groups: dict[tuple[datetime, datetime], list[MetricRequest]] = {}
    for request in requests:
        groups.setdefault((request.start_time, request.end_time), []).append(request)
    return list(groups.values())


def build_metric_observation(
    request: MetricRequest,
    values: list[Decimal | MetricDatapoint],
    *,
    limitation: str | None = None,
) -> MetricSummary:
    """Aggregate complete numeric samples without applying utilization policy."""
    status = values.status if isinstance(values, MetricReadValues) else "complete"
    reason = values.reason if isinstance(values, MetricReadValues) else None
    datapoints = tuple(sorted((value for value in values if isinstance(value, MetricDatapoint)), key=lambda point: point.timestamp))
    numbers = [value.value if isinstance(value, MetricDatapoint) else value for value in values]
    minimum = maximum = average = rounded = None
    if any(not isinstance(value, Decimal) or not value.is_finite() for value in numbers):
        status, reason = "unavailable", MetricReadReason.INVALID_NUMERIC_VALUE
        datapoints = ()
    if numbers and status == "complete":
        try:
            average = sum(numbers, Decimal(0)) / Decimal(len(numbers))
            rounded = average.quantize(Decimal("0.01"))
            minimum, maximum = min(numbers), max(numbers)
        except DecimalException:
            status, reason = "unavailable", MetricReadReason.UNREPRESENTABLE_AGGREGATE
            average = rounded = None
    if limitation is None and status != "complete":
        limitation = f"CloudWatch metric evidence was {status} ({reason.name.lower() if reason is not None else 'unknown_read_state'})."
    elif limitation is None and not numbers:
        limitation = "No CloudWatch datapoints were returned for the scan window."
    return MetricSummary(
        namespace=request.namespace,
        metric_name=request.metric_name,
        statistic=request.statistic,
        period=request.period,
        start_time=request.start_time,
        end_time=request.end_time,
        observed_min=minimum,
        observed_max=maximum,
        observed_average=rounded,
        threshold_used=request.threshold_used,
        interpretation="observed" if average is not None else "insufficient_data",
        limitation=limitation,
        datapoints=datapoints,
        collection_evidence_version=1,
        collection_context=request.collection_context,
        collection_status=status,
        collection_reason=reason.value if reason is not None else None,
        observed_average_parts=(average.as_tuple().sign, average.as_tuple().digits, int(average.as_tuple().exponent)) if average is not None else None,
    )
