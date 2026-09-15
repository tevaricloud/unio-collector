from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import date
    from decimal import Decimal


@dataclass(frozen=True)
class CurLineItem:  # noqa: D101
    usage_start_date: date
    service_name: str
    region: str
    usage_type: str | None
    resource_id: str | None
    account_id: str | None
    cost: Decimal
    currency: str
    tags: dict[str, str] = field(default_factory=dict)
