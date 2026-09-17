from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Ec2InstanceInventoryContext:  # noqa: D101
    collector: Any
    instances_by_region: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    regions: list[str] = field(default_factory=list)
