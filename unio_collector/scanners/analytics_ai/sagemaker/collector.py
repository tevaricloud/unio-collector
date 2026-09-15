from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.analytics_ai.helpers import (
    add_analytics_ai_cost_context,
    build_analytics_ai_collector,
    record_analytics_ai_execution_detail,
)
from unio_collector.scanners.analytics_ai.sagemaker.evidence import (
    SageMakerCostReviewEvidence,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class SageMakerCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> SageMakerCostReviewEvidence:  # noqa: D102
        collector = build_analytics_ai_collector(context)
        records = collector.collect_sagemaker_records()
        records = add_analytics_ai_cost_context(records, context)
        regions = collector.get_available_regions()
        record_analytics_ai_execution_detail(
            context,
            records,
            regions=regions,
        )
        return SageMakerCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="SageMakerCostReviewScanner",
            implementation_module="unio_collector.scanners.analytics_ai.sagemaker.scanner",
        )
