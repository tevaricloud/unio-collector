from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cost_explorer.commitment.collector import (
    AwsCommitmentPortfolioCollector,
)
from unio_collector.scanners.cost_explorer.commitment.evidence import (
    CommitmentReviewEvidence,
)
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CommitmentAndPricingReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> CommitmentReviewEvidence:  # noqa: D102
        portfolio = AwsCommitmentPortfolioCollector().collect(context)
        return CommitmentReviewEvidence(
            account_id=context.security.account_id,
            portfolio=portfolio,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="CommitmentAndPricingReviewScanner",
            implementation_module="unio_collector.scanners.cost_explorer.commitment.scanner",
        )
