from __future__ import annotations  # noqa: D100

from collections.abc import Iterable, Sized
from importlib import import_module
from typing import TYPE_CHECKING, Any

from unio_collector.aws.collection.result_counts import AwsCollectionResultCounts

if TYPE_CHECKING:
    from unio_collector.aws.collection.task import AwsCollectionTask
    from unio_collector.aws.collection.task_result import AwsCollectionTaskResult


def format_collection_task_warning(result: AwsCollectionTaskResult[Any]) -> str:  # noqa: D103
    region = result.task.region or "aws-global"
    detail = result.error_code or result.error_message or result.status
    return f"{result.task.collector_id} could not collect {result.task.service}:{result.task.operation} in {region}: {detail}."


def count_collection_results(  # noqa: D103
    task: AwsCollectionTask[Any],
    value: Any,  # noqa: ANN401
) -> AwsCollectionResultCounts:
    if task.service in {"ce", "pricing"}:
        return AwsCollectionResultCounts(
            result_count=count_collection_items(value),
            resource_count=0,
            metric_datapoint_count=0,
            page_count=count_page_items(value),
        )
    if task.service == "cloudwatch" and task.operation == "GetMetricData" and isinstance(value, dict):
        result_count = len(value)
        metric_datapoint_count = sum(len(child) for child in value.values() if isinstance(child, list))
        return AwsCollectionResultCounts(
            result_count=result_count,
            resource_count=0,
            metric_datapoint_count=metric_datapoint_count,
            page_count=1,
        )
    result_count = count_collection_items(value)
    return AwsCollectionResultCounts(
        result_count=result_count,
        resource_count=result_count,
        metric_datapoint_count=0,
        page_count=count_page_items(value),
    )


def count_collection_items(value: Any) -> int:  # noqa: ANN401, D103
    if value is None:
        return 0
    resources_returned = getattr(value, "resources_returned", None)
    if isinstance(resources_returned, int):
        return resources_returned
    if isinstance(value, dict):
        return sum(len(item) for item in value.values() if isinstance(item, list))
    if isinstance(value, Sized) and not isinstance(value, (str, bytes, bytearray)):
        return len(value)
    return 1


def count_page_items(value: Any) -> int:  # noqa: ANN401, D103
    page_count = getattr(value, "page_count", None)
    if isinstance(page_count, int):
        return page_count
    if isinstance(value, dict):
        pages = value.get("pages")
        if isinstance(pages, list):
            return len(pages)
        page_count_value = value.get("page_count")
        if isinstance(page_count_value, int):
            return page_count_value
        return 1
    if value is None:
        return 0
    if isinstance(value, Sized) and not isinstance(value, (str, bytes, bytearray)):
        return 1
    return 1


def record_collection_results(  # noqa: D103
    session: Any,  # noqa: ANN401
    task_results: Iterable[AwsCollectionTaskResult[Any]],
) -> None:
    diagnostics_module = import_module("unio_collector.aws.collection.diagnostics")
    diagnostics_class = diagnostics_module.AwsCollectionDiagnostics
    diagnostics = getattr(session, "collection_diagnostics", None)
    if diagnostics is None:
        diagnostics = diagnostics_class()
        session.collection_diagnostics = diagnostics

    if isinstance(diagnostics, diagnostics_class):
        diagnostics.record_results(task_results)
