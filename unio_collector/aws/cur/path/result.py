from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.cur.data.source import CurDataSource


@dataclass(frozen=True)
class CurPathResolutionResult:  # noqa: D101
    data_sources: tuple[CurDataSource, ...]
    limitations: tuple[str, ...]
    reason_codes: tuple[str, ...] = ()
