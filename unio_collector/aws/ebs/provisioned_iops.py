from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ProvisionedIopsVolumeRecord:  # noqa: D101
    volume_id: str
    account_id: str
    region: str
    volume_type: str
    size_gib: int
    provisioned_iops: int | None
    state: str
    tags: dict[str, str]
