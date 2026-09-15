from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Ec2RegionInstanceInventory:  # noqa: D101
    region: str
    instances: list[dict[str, Any]]
