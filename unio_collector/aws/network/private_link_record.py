from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PrivateLinkRegionRecord:  # noqa: D101
    account_id: str
    region: str
    interface_endpoint_count: int = 0
    gateway_load_balancer_endpoint_count: int = 0
    available_endpoint_count: int = 0
    pending_endpoint_count: int = 0
    tagged_endpoint_count: int = 0
    endpoint_service_count: int = 0
    endpoint_service_names: list[str] = field(default_factory=list)
    sample_endpoint_ids: list[str] = field(default_factory=list)
    sample_vpc_ids: list[str] = field(default_factory=list)
    sample_service_names: list[str] = field(default_factory=list)
