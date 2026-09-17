from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedResourceArn:  # noqa: D101
    partition: str
    service: str
    region: str
    account_id: str
    resource_type: str
    resource_id: str
