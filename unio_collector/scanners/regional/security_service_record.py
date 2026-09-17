from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RegionalSecurityServiceRecord:  # noqa: D101
    service_name: str
    region: str
    enabled: bool | None
    detail: str
    metadata: dict[str, Any] = field(default_factory=dict)
