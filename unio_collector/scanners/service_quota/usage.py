from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class ServiceQuotaUsage:  # noqa: D101
    value: int | None
    confidence: str
    method: str
    limitation: str | None = None
