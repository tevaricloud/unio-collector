from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

from unio_collector.aws.collection.helpers import format_collection_task_warning

if TYPE_CHECKING:
    from unio_collector.aws.collection.task_result import AwsCollectionTaskResult


@dataclass(frozen=True)
class RegionalCollectionResult[T]:  # noqa: D101
    values: list[T]
    task_results: list[AwsCollectionTaskResult[list[T]]]

    def get_failed_results(self) -> list[AwsCollectionTaskResult[list[T]]]:  # noqa: D102
        return [result for result in self.task_results if result.status != "completed"]

    def build_warning_messages(self) -> list[str]:  # noqa: D102
        messages: list[str] = [format_collection_task_warning(result) for result in self.get_failed_results()]
        return messages
