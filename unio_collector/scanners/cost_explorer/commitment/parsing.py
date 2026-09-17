"""Pure parsing helpers for commitment portfolio collection."""

from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from unio_collector.aws.response_admission import require_response_mapping

if TYPE_CHECKING:
    from unio_collector.commitments.inventory import CommitmentInventoryItem


class CommitmentAccountScopeError(ValueError):
    """Explicit provider account evidence does not prove the requested scope."""


def decimal_value(value: object) -> Decimal | None:
    """Parse a decimal without converting missing or malformed values to zero."""
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = Decimal(str(value))
        return parsed if parsed.is_finite() else None
    except (InvalidOperation, ValueError):
        return None


def object_dict(value: object) -> dict[str, Any]:
    """Preserve absent optional objects, but reject malformed present objects."""
    return {} if value is None else require_response_mapping(value)


def period_dates(period: object) -> tuple[date | None, date | None]:
    """Parse an AWS Cost Explorer exclusive time period."""
    if not isinstance(period, dict):
        return None, None
    try:
        start = date.fromisoformat(str(period["Start"]))
        end = date.fromisoformat(str(period["End"]))
    except (KeyError, ValueError):
        return None, None
    return (start, end) if start < end else (None, None)


def validate_account_scope(value: object, account_id: str) -> None:
    """Reject explicit account attributes that differ from the scan target."""
    if isinstance(value, dict):
        for key, child in require_response_mapping(value).items():
            if key.lower() in {"accountid", "linkedaccount", "linkedaccountid"} and (not isinstance(child, str) or child != account_id):
                msg = "Cost Explorer returned evidence for a different linked account."
                raise CommitmentAccountScopeError(msg)
            validate_account_scope(child, account_id)
    elif isinstance(value, list):
        for child in value:
            validate_account_scope(child, account_id)


def currencies_by_service(inventory: list[CommitmentInventoryItem]) -> dict[str, set[str]]:
    """Return observed inventory currencies by commitment service."""
    values: dict[str, set[str]] = {}
    for item in inventory:
        if item.payment.currency:
            values.setdefault(item.identity.service, set()).add(item.payment.currency)
    return values


def selected_regions(configured: list[str], session_region: object) -> list[str]:
    """Resolve configured regions with the session region as a bounded fallback."""
    regions = sorted(set(configured))
    return regions or ([str(session_region)] if session_region else [])


def global_region(session_region: object) -> str:
    """Resolve a control-plane region for global commitment APIs."""
    return str(session_region or "us-east-1")


def assessment_time(period_end_exclusive: date) -> datetime:
    """Return the deterministic assessment instant for an exclusive period end."""
    return datetime.combine(period_end_exclusive, datetime.min.time(), tzinfo=UTC)
