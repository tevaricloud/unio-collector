from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class AwsRateLimitKey:  # noqa: D101
    account_id: str
    region: str
    service: str
    operation: str | None = None
