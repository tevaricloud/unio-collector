from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.log.group.record import LogGroupRecord


@dataclass(frozen=True)
class CloudWatchLogRetentionEvidence:  # noqa: D101
    records: list[LogGroupRecord] = field(default_factory=list)
    regions: list[str] = field(default_factory=list)
