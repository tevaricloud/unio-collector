from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PublicIpv4RegionRecord:  # noqa: D101
    account_id: str
    region: str
    elastic_ip_count: int = 0
    attached_elastic_ip_count: int = 0
    unattached_elastic_ip_count: int = 0
    eni_public_ip_count: int = 0
    auto_assigned_public_ip_count: int = 0
    allocation_ids: list[str] = field(default_factory=list)
    sample_interface_ids: list[str] = field(default_factory=list)
    tagged_address_count: int = 0
