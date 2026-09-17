from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ServiceCoverageRecord:  # noqa: D101
    service: str
    region: str
    resource_type: str
    resource_id: str
    resource_name: str | None = None
    arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)

    def convert_to_signal(self) -> dict[str, Any]:  # noqa: D102
        return {
            "service": self.service,
            "region": self.region,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "arn": self.arn,
            "tag_count": len(self.tags),
            **self.attributes,
        }
