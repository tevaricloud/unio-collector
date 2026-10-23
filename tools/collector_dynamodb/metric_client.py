"""Synthetic SDK response shapes retained from existing DynamoDB owning fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def build_dynamodb_metric_values(table_name: str, metric_name: str) -> list[float]:  # noqa: D103
    if table_name == "orders":
        return {
            "ConsumedReadCapacityUnits": [100.0, 120.0],
            "ConsumedWriteCapacityUnits": [20.0, 30.0],
            "ReadThrottleEvents": [0.0, 2.0],
            "WriteThrottleEvents": [0.0, 0.0],
            "ThrottledRequests": [0.0, 1.0],
            "SystemErrors": [0.0, 0.0],
            "SuccessfulRequestLatency": [5.0, 6.0],
        }.get(metric_name, [])
    if table_name == "events":
        return {
            "ConsumedReadCapacityUnits": [0.0, 0.0],
            "ConsumedWriteCapacityUnits": [3.0, 4.0],
            "ReadThrottleEvents": [0.0, 0.0],
            "WriteThrottleEvents": [0.0, 0.0],
            "ThrottledRequests": [0.0, 0.0],
            "SystemErrors": [0.0, 0.0],
            "SuccessfulRequestLatency": [2.0, 2.5],
        }.get(metric_name, [])
    return []


class SyntheticMetricClient:  # noqa: D101
    def __init__(self: Any) -> None:  # noqa: D107
        self.calls: list[str] = []

    def can_paginate(self: Any, operation_name: str) -> bool:  # noqa: D102
        del operation_name
        return False

    def get_metric_data(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        queries = kwargs.get("MetricDataQueries", [])
        self.calls.append(f"get_metric_data:{len(queries)}")
        results = []
        for query in queries:
            query_id = query["Id"]
            metric = query["MetricStat"]["Metric"]["MetricName"]
            dimensions = query["MetricStat"]["Metric"]["Dimensions"]
            table_name = next(
                (item["Value"] for item in dimensions if item.get("Name") == "TableName"),
                "",
            )
            values = build_dynamodb_metric_values(table_name, metric)
            results.append(
                {
                    "Id": query_id,
                    "Values": values,
                    "Timestamps": [datetime(2026, 9, index + 1, tzinfo=UTC) for index in range(len(values))],
                    "StatusCode": "Complete",
                },
            )
        return {"MetricDataResults": results}

    def get_metric_statistics(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        self.calls.append(f"get_metric_statistics:{kwargs.get('MetricName')}")
        return {"Datapoints": []}
