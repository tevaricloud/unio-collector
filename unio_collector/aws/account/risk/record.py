from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AccountCostRiskRecord:  # noqa: D101
    account_id: str
    cloudtrail_available: bool
    trails: list[dict[str, Any]] = field(default_factory=list)
    trail_statuses: list[dict[str, Any]] = field(default_factory=list)
    iam_summary_available: bool = False
    iam_summary: dict[str, Any] = field(default_factory=dict)
    trail_statuses_complete: bool = True
    trail_status_omitted_count: int = 0
    collection_errors: tuple[str, ...] = ()
