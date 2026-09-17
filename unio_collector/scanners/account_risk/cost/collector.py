from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.account.risk import AccountCostRiskCollector
from unio_collector.scanners.account_risk.cost.evidence import AccountCostRiskEvidence
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class AccountCostRiskSignalCollector(BaseUnioScanner):
    """Collect provider evidence for account-cost-risk-signal-review."""

    def collect(self, context: ScannerContext) -> AccountCostRiskEvidence:  # noqa: D102
        risk_collector = AccountCostRiskCollector(
            context.security.session,
            account_id=context.security.account_id,
            audit_context=context.security.create_audit_context(
                "AccountCostRiskCollector",
            ),
        )
        return AccountCostRiskEvidence(
            daily_costs=context.costs.collect_daily_costs(),
            account_risk=risk_collector.collect(),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="AccountCostRiskSignalScanner",
            implementation_module="unio_collector.scanners.account_risk.cost.signal",
        )
