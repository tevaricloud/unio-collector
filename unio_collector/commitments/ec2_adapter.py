"""EC2 Reserved Instance inventory adapter."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation

from unio_collector.commitments.identity import CommitmentIdentity
from unio_collector.commitments.inventory import CommitmentInventoryItem
from unio_collector.commitments.payment import CommitmentPayment
from unio_collector.commitments.specification import CommitmentSpecification
from unio_collector.commitments.term import CommitmentTerm

YEAR_SECONDS = 31_536_000
THREE_YEAR_SECONDS = 94_608_000


class Ec2ReservedInstanceAdapter:
    """Parse EC2 DescribeReservedInstances records without pricing inference."""

    def parse(
        self,
        record: dict[str, object],
        *,
        account_id: str,
        region: str | None = None,
        as_of: datetime | None = None,
    ) -> CommitmentInventoryItem | None:
        """Convert one valid EC2 Reserved Instance record."""
        source_id = _text(record.get("ReservedInstancesId"))
        if not source_id:
            return None
        start = _datetime(record.get("Start"))
        end = _datetime(record.get("End"))
        duration = _integer(record.get("Duration"))
        return CommitmentInventoryItem(
            identity=CommitmentIdentity(
                provider="aws",
                service="ec2_reserved_instance",
                commitment_type="reserved_instance",
                source_namespace="ec2_reserved_instances_id",
                source_id=source_id,
                account_id=account_id,
            ),
            specification=CommitmentSpecification(
                scope=_text(record.get("Scope")),
                region=region,
                availability_zone=_text(record.get("AvailabilityZone")),
                instance_family=_instance_family(record.get("InstanceType")),
                instance_type=_text(record.get("InstanceType")),
                commitment_class=_text(record.get("OfferingClass")),
                platform=_text(record.get("ProductDescription")),
                tenancy=_text(record.get("InstanceTenancy")),
                quantity=_decimal(record.get("InstanceCount")),
                capacity_unit="instances",
                lifecycle_state=_text(record.get("State")),
            ),
            term=CommitmentTerm(
                start=start,
                end=end,
                term_seconds=duration,
                term_label=_term_label(duration),
                remaining_seconds=_remaining_seconds(end, as_of),
            ),
            payment=CommitmentPayment(
                payment_option=_text(record.get("OfferingType")),
                upfront_amount=_decimal(record.get("FixedPrice")),
                recurring_amount=_recurring_amount(record.get("RecurringCharges")),
                recurring_unit="hour",
                currency=_text(record.get("CurrencyCode")),
            ),
            source_operation="ec2:DescribeReservedInstances",
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


def _instance_family(value: object) -> str | None:
    text = _text(value)
    return text.split(".", maxsplit=1)[0] if text and "." in text else None


def _recurring_amount(value: object) -> Decimal | None:
    if not isinstance(value, list):
        return None
    amounts: list[Decimal] = []
    for item in value:
        if not isinstance(item, dict) or item.get("Frequency") != "Hourly":
            return None
        amount = _decimal(item.get("Amount"))
        if amount is None:
            return None
        amounts.append(amount)
    return sum(amounts, Decimal(0)) if amounts else None


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
