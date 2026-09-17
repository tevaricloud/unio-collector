from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.metric.request import MetricRequest
    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class AwsInventoryMetricHelper:
    """Batch CloudWatch metric requests and group summaries by resource owner."""

    def collect_summaries_by_owner(  # noqa: D102
        self,
        *,
        collector: Any,  # noqa: ANN401
        records: list[dict[str, Any]],
        owner_key: str,
        build_requests: Callable[[dict[str, Any]], list[MetricRequest]],
    ) -> dict[str, list[MetricSummary]]:
        requests: list[MetricRequest] = []
        owners: list[str] = []
        by_owner: dict[str, list[MetricSummary]] = {}
        for record in records:
            owner = str(record.get(owner_key) or "")
            if not owner:
                continue
            by_owner.setdefault(owner, [])
            owner_requests = build_requests(record)
            requests.extend(owner_requests)
            owners.extend([owner] * len(owner_requests))
        summaries = collector.collect_metric_summaries(requests)
        for owner, summary in zip(owners, summaries, strict=True):
            by_owner.setdefault(owner, []).append(summary)
        return by_owner
