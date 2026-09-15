from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.log.group.activity import LogGroupActivityRecord


@dataclass(frozen=True)
class CloudWatchLogActivityEvidence:  # noqa: D101
    records: list[LogGroupActivityRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
    idle_days: int = 30
