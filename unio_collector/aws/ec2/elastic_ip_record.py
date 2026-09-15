from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ElasticIpRecord:  # noqa: D101
    allocation_id: str | None
    public_ip: str | None
    account_id: str
    region: str
    domain: str | None
    tags: dict[str, str]
