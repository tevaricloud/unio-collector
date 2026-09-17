from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.account_risk.root.recovery.evidence import (
    RootAccountRecoveryAdvisoryEvidence,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class RootAccountRecoveryAdvisoryCollector(BaseUnioScanner):
    """Collect provider evidence for root-account-recovery-advisory."""

    def collect(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> RootAccountRecoveryAdvisoryEvidence:
        return RootAccountRecoveryAdvisoryEvidence(
            account_id=context.security.account_id,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="RootAccountRecoveryAdvisoryScanner",
            implementation_module="unio_collector.scanners.account_risk.root.recovery.scanner",
        )
