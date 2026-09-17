from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit import AwsAuditContext
from unio_collector.aws.cost_explorer.collector import CostExplorerCollector
from unio_collector.billing.baseline import (
    BillingBaselineStatus,
    LastCompletedMonthBillingBaseline,
)
from unio_collector.billing.period_resolver import CompletedMonthPeriodResolver

if TYPE_CHECKING:
    from datetime import date

    from unio_collector.aws.session import AuditedAwsSession


class AwsBillingBaselineService:
    """Collect the run-level last-completed-month AWS billing baseline."""

    def collect(
        self,
        *,
        session: AuditedAwsSession,
        account_id: str,
        reference_date: date | None = None,
    ) -> LastCompletedMonthBillingBaseline:
        """Return billing evidence or a fail-safe unavailable baseline."""
        period = CompletedMonthPeriodResolver().resolve(
            reference_date=reference_date,
        )
        context = AwsAuditContext(
            scanner_id="last-completed-month-billing-baseline",
            collector="AwsBillingBaselineService",
            allowed_api_calls=("ce:GetCostAndUsage",),
            recipient_account_id=account_id,
        )
        try:
            return CostExplorerCollector(
                session,
                audit_context=context,
            ).collect_last_completed_month_baseline(
                reference_date=reference_date,
            )
        except Exception as exc:  # noqa: BLE001
            permission_denied = aws_errors.is_permission_error(exc)
            status: BillingBaselineStatus = "permission_denied" if permission_denied else "unavailable"
            return LastCompletedMonthBillingBaseline(
                period=period,
                status=status,
                complete=False,
                limitations=[
                    (
                        "AWS Cost Explorer permission was unavailable for the completed-month billing baseline."
                        if permission_denied
                        else "AWS Cost Explorer did not return the completed-month billing baseline."
                    ),
                ],
            )
