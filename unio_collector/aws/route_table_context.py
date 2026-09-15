from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteTableContext:  # noqa: D101
    route_table_id: str | None
    vpc_id: str | None
    subnet_id: str | None
    default_route_target: str | None
    default_route_target_type: str | None
    association: str
