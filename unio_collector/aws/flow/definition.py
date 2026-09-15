from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class VpcFlowLogDefinition:  # noqa: D101
    flow_log_id: str
    region: str
    resource_id: str | None
    resource_type: str | None
    log_group_name: str
    traffic_type: str | None
    format_supported: bool = True
