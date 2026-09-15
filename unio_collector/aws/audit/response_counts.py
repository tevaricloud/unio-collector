from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AwsResponseResultCounts:  # noqa: D101
    result_count: int = 0
    resource_count: int = 0
    metric_datapoint_count: int = 0


def count_response_results(  # noqa: D103
    *,
    service_name: str,
    operation_name: str,
    response: Any | None,  # noqa: ANN401
) -> AwsResponseResultCounts:
    if not isinstance(response, dict):
        return AwsResponseResultCounts()
    if service_name == "ce":
        return AwsResponseResultCounts(
            result_count=count_cost_explorer_results(operation_name, response),
            resource_count=0,
            metric_datapoint_count=0,
        )
    if service_name == "pricing":
        return AwsResponseResultCounts(
            result_count=count_pricing_results(operation_name, response),
            resource_count=0,
            metric_datapoint_count=0,
        )
    if service_name == "cloudwatch" and operation_name == "GetMetricData":
        metric_results = response.get("MetricDataResults")
        if not isinstance(metric_results, list):
            return AwsResponseResultCounts()
        return AwsResponseResultCounts(
            result_count=len(metric_results),
            resource_count=0,
            metric_datapoint_count=sum(len(item.get("Values", [])) for item in metric_results if isinstance(item, dict)),
        )
    if service_name == "cloudwatch" and operation_name == "GetMetricStatistics":
        datapoints = response.get("Datapoints")
        datapoint_count = len(datapoints) if isinstance(datapoints, list) else 0
        return AwsResponseResultCounts(
            result_count=datapoint_count,
            resource_count=0,
            metric_datapoint_count=datapoint_count,
        )
    if service_name == "cloudfront":
        result_count = count_cloudfront_results(operation_name, response)
        return AwsResponseResultCounts(
            result_count=result_count,
            resource_count=result_count,
            metric_datapoint_count=0,
        )
    result_count = count_response_list_items(response)
    return AwsResponseResultCounts(
        result_count=result_count,
        resource_count=result_count,
        metric_datapoint_count=0,
    )


def count_cost_explorer_results(  # noqa: D103
    operation_name: str,
    response: dict[str, Any],
) -> int:
    if operation_name == "GetCostAndUsage":
        return count_cost_explorer_cost_rows(response)
    return count_response_list_items(response)


def count_cost_explorer_cost_rows(response: dict[str, Any]) -> int:  # noqa: D103
    periods = response.get("ResultsByTime")
    if not isinstance(periods, list):
        return 0
    row_count = 0
    for period in periods:
        if not isinstance(period, dict):
            continue
        groups = period.get("Groups")
        if isinstance(groups, list) and groups:
            row_count += len(groups)
            continue
        total = period.get("Total")
        if isinstance(total, dict) and total:
            row_count += 1
    return row_count


def count_pricing_results(  # noqa: D103
    operation_name: str,
    response: dict[str, Any],
) -> int:
    if operation_name == "GetProducts":
        price_list = response.get("PriceList")
        return len(price_list) if isinstance(price_list, list) else 0
    return count_response_list_items(response)


def count_cloudfront_results(  # noqa: D103
    operation_name: str,
    response: dict[str, Any],
) -> int:
    if operation_name == "ListDistributions":
        distribution_list = response.get("DistributionList")
        if not isinstance(distribution_list, dict):
            return 0
        items = distribution_list.get("Items")
        return len(items) if isinstance(items, list) else 0
    if operation_name == "ListTagsForResource":
        tags = response.get("Tags")
        if not isinstance(tags, dict):
            return 0
        items = tags.get("Items")
        return len(items) if isinstance(items, list) else 0
    return count_response_list_items(response)


def count_response_list_items(response: Any | None) -> int:  # noqa: ANN401, D103
    if not isinstance(response, dict):
        return 0
    count = 0
    for key, value in response.items():
        if key == "ResponseMetadata":
            continue
        if isinstance(value, list):
            count += len(value)
    return count
