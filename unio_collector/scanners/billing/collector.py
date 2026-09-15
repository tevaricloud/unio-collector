from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.billing_guardrails import (
    BillingGuardrailCollector,
    normalize_billing_monitor_detail_mode,
    normalize_billing_subscriber_detail_mode,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class BillingAlertsAndBudgetsCollector(BaseUnioScanner):
    """Collect provider evidence for billing-alerts-and-budgets-review."""

    def collect(self, context: ScannerContext) -> object:  # noqa: D102
        subscriber_detail_mode = normalize_billing_subscriber_detail_mode(
            context.options.get(
                "subscriber_detail_mode",
                "full",
            ),
        )
        monitor_detail_mode = normalize_billing_monitor_detail_mode(
            context.options.get(
                "monitor_detail_mode",
                "full",
            ),
        )
        collector = BillingGuardrailCollector(
            context.security.session,
            account_id=context.security.account_id,
            audit_context=context.security.create_audit_context(
                "BillingGuardrailCollector",
            ),
            subscriber_detail_mode=subscriber_detail_mode,
            monitor_detail_mode=monitor_detail_mode,
        )
        record = collector.collect()
        self.record_subscriber_detail_note(context, subscriber_detail_mode)
        self.record_monitor_detail_note(context, monitor_detail_mode)
        return record

    def record_subscriber_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        subscriber_detail_mode: str,
    ) -> None:
        if subscriber_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "budget_notification_subscribers",
                "summary": ("Budget notification subscriber detail calls were skipped by scanner configuration."),
                "config_key": (f"{context.definition.scanner_id}.subscriber_detail_mode"),
                "configured_value": subscriber_detail_mode,
                "result_scope": "current_scan",
                "impact": ("The scan still checks budgets and budget notifications, but does not confirm subscriber counts."),
            },
        )

    def record_monitor_detail_note(  # noqa: D102
        self,
        context: ScannerContext,
        monitor_detail_mode: str,
    ) -> None:
        if monitor_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "billing_monitoring_controls",
                "summary": ("Cost anomaly monitor and CloudWatch billing alarm checks were skipped by scanner configuration."),
                "config_key": f"{context.definition.scanner_id}.monitor_detail_mode",
                "configured_value": monitor_detail_mode,
                "result_scope": "current_scan",
                "impact": (
                    "Budget and budget notification checks still run, but "
                    "anomaly detection and CloudWatch billing alarm coverage "
                    "must be validated in full mode for client-facing reports."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="BillingAlertsAndBudgetsScanner",
            implementation_module="unio_collector.scanners.billing.alerts_and_budgets",
        )
