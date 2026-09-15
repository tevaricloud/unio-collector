from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.core.attempt import AttemptDeadlineContract


@dataclass(frozen=True)
class AwsAuditContext:  # noqa: D101
    scanner_id: str
    collector: str
    allowed_api_calls: tuple[str, ...]
    recipient_account_id: str | None = None
    attempt: AttemptDeadlineContract | None = None
