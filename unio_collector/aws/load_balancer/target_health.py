from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class TargetHealthSummary:  # noqa: D101
    registered_count: int
    healthy_count: int
    available: bool = True
