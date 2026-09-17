from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.free_tier.collector import FreeTierCollector
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.free_tier.collection_result import FreeTierCollectionResult
    from unio_collector.scanners.scanner.context import ScannerContext


class FreeTierUsageReviewCollector(BaseUnioScanner):
    """Collect provider evidence for free-tier-usage-review."""

    def collect(self, context: ScannerContext) -> FreeTierCollectionResult:  # noqa: D102
        collector = FreeTierCollector(
            context.security.session,
            account_id=context.security.account_id,
            audit_context=context.security.create_audit_context(
                "FreeTierCollector",
            ),
        )
        return collector.collect()

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="FreeTierUsageReviewScanner",
            implementation_module="unio_collector.scanners.free_tier.usage_review",
        )
