from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class EcrRegistryScanRecord:  # noqa: D101
    region: str
    scan_type: str | None
    rule_count: int
