from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityGroupIngressRule:  # noqa: D101
    group_id: str
    group_name: str
    vpc_id: str | None
    region: str
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str
    associated_platform: str | None = None
    association_reason: str | None = None
    name_contains_lightsail: bool | None = None
