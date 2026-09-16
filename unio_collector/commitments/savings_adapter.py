"""Savings Plans inventory adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from unio_collector.commitments.ec2_adapter import THREE_YEAR_SECONDS, YEAR_SECONDS
from unio_collector.commitments.identity import CommitmentIdentity
from unio_collector.commitments.inventory import CommitmentInventoryItem
from unio_collector.commitments.payment import CommitmentPayment
from unio_collector.commitments.specification import CommitmentSpecification
from unio_collector.commitments.term import CommitmentTerm


class SavingsPlanAdapter:
    """Parse DescribeSavingsPlans inventory into shared contracts."""

    def parse(
        self,
        record: dict[str, object],
        *,
        account_id: str,
        region: str | None = None,
        as_of: datetime | None = None,
    ) -> CommitmentInventoryItem | None:
        """Convert one valid Savings Plan record."""
        source_id = _text(record.get("savingsPlanId"))
        if not source_id:
            return None
        duration = _integer(record.get("termDurationInSeconds"))
        end = _datetime(record.get("end"))
        return CommitmentInventoryItem(
            identity=CommitmentIdentity(
                provider="aws",
                service="savings_plans",
                commitment_type=_text(record.get("savingsPlanType")) or "savings_plan",
                source_namespace="savings_plan_id",
                source_id=source_id,
                account_id=account_id,
                arn=_text(record.get("savingsPlanArn")),
            ),
            specification=CommitmentSpecification(
                scope="global",
                region=_text(record.get("region")) or region,
                instance_family=_text(record.get("ec2InstanceFamily")),
                quantity=_decimal(record.get("commitment")),
                capacity_unit="currency_per_hour",
                lifecycle_state=_text(record.get("state")),
            ),
            term=CommitmentTerm(
                start=_datetime(record.get("start")),
                end=end,
                term_seconds=duration,
                term_label=_term_label(duration),
                remaining_seconds=_remaining_seconds(end, as_of),
            ),
            payment=CommitmentPayment(
                payment_option=_text(record.get("paymentOption")),
                upfront_amount=_decimal(record.get("upfrontPaymentAmount")),
                recurring_amount=_decimal(record.get("recurringPaymentAmount")),
                recurring_unit="hour",
                currency=_text(record.get("currency")),
            ),
            source_operation="savingsplans:DescribeSavingsPlans",
            evidence_timestamp=as_of,
        )


def _term_label(duration: int | None) -> str | None:
    if duration == YEAR_SECONDS:
        return "one_year"
    if duration == THREE_YEAR_SECONDS:
        return "three_year"
    return None


def _remaining_seconds(end: datetime | None, as_of: datetime | None) -> int | None:
    if end is None:
        return None
    reference = as_of or datetime.now(UTC)
    return max(int((end - reference).total_seconds()), 0)


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _integer(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def _decimal(value: object) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = Decimal(str(value))
        return parsed if parsed.is_finite() else None
    except (InvalidOperation, ValueError):
        return None


def _datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
