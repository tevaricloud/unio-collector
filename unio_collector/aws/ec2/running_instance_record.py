from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from unio_collector.aws.metric.summary import MetricSummary


@dataclass(frozen=True)
class RunningInstanceRecord:  # noqa: D101
    instance_id: str
    account_id: str
    region: str
    instance_type: str
    launch_time: datetime | None
    tags: dict[str, str]
    metric_summaries: list[MetricSummary]
    root_device_type: str = "unknown"
    instance_lifecycle: str = "on-demand"
    platform_details: str = "unknown"
    tenancy: str = "default"
    vpc_id: str | None = None
    subnet_id: str | None = None
    public_ip_address: str | None = None
    managed_workload_markers: tuple[str, ...] = ()
