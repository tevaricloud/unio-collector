from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class BillingGuardrailRecord:  # noqa: D101
    account_id: str
    budgets: list[dict[str, Any]] = field(default_factory=list)
    anomaly_monitors: list[dict[str, Any]] = field(default_factory=list)
    anomaly_subscriptions: list[dict[str, Any]] = field(default_factory=list)
    billing_alarms: list[dict[str, Any]] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
