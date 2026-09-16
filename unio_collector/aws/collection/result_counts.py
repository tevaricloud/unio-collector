from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsCollectionResultCounts:  # noqa: D101
    result_count: int = 0
    resource_count: int = 0
    metric_datapoint_count: int = 0
    page_count: int = 0
