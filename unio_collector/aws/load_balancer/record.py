from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class LoadBalancerRecord:  # noqa: D101
    load_balancer_arn: str
    load_balancer_name: str
    load_balancer_type: str
    state: str
    account_id: str
    region: str
    target_group_count: int
    registered_target_count: int
    healthy_target_count: int
    target_health_detail_mode: str = "full"
    target_health_metadata_collected: bool = True
    target_health_skip_reason: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    tags_collected: bool = True
    tag_skip_reason: str | None = None
    metrics: list[MetricSummary] = field(default_factory=list)
    collection_errors: tuple[str, ...] = ()
