from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class TaggableResourceRecord:  # noqa: D101
    resource_id: str
    resource_type: str
    service: str
    account_id: str
    region: str
    resource_name: str | None = None
    arn: str | None = None
    tags: dict[str, str] | None = None
    associated_resource_id: str | None = None
    associated_resource_type: str | None = None
    associated_resource_tags: dict[str, str] | None = None
    association_reason: str | None = None
