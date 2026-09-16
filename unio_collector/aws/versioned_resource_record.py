from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class VersionedResourceRecord:  # noqa: D101
    service: str
    resource_id: str
    resource_name: str | None
    account_id: str
    region: str
    arn: str | None
    engine: str | None
    version: str | None
    tags: dict[str, str]
    platform: str | None = None
    resource_type: str | None = None
    evidence_source: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
