from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AccountCostRiskBaseSignals:  # noqa: D101
    trails_response: dict[str, Any] | None = None
    iam_summary: dict[str, Any] | None = None
