from __future__ import annotations  # noqa: D100

from unio_collector.core.base_model import UnioBaseModel


class AccountFailure(UnioBaseModel):
    """Persist a sanitized isolated account failure."""

    account_reference: str
    stage: str
    code: str
    category: str
    sanitized_detail: str
    retryable: bool
    attempts: int
