"""Compatibility metric exports; collection uses canonical factual modules."""

from __future__ import annotations

from typing import TYPE_CHECKING

from unio_collector.aws.metric.collection import group_metric_requests_by_window
from unio_collector.aws.metric.compatibility import resolve_metric_export

if TYPE_CHECKING:
    from unio_collector.analyzers.metric.compatibility import build_metric_summary
    from unio_collector.analyzers.metric.policy import interpret_metric_average

__getattr__ = resolve_metric_export

__all__ = [
    "build_metric_summary",
    "group_metric_requests_by_window",
    "interpret_metric_average",
]
