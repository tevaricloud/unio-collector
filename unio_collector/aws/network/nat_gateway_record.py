from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class NatGatewayRecord:  # noqa: D101
    nat_gateway_id: str
    account_id: str
    region: str
    state: str
    subnet_id: str | None
    vpc_id: str | None
    connectivity_type: str | None
    create_time: datetime | None
    tags: dict[str, str]
    metric_summaries: list[MetricSummary] = field(default_factory=list)
