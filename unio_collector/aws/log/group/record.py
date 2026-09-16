from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class LogGroupRecord:  # noqa: D101
    log_group_name: str
    region: str
    stored_bytes: int | None
