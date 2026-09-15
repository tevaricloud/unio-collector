from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.scanners.analytics_ai.bedrock.evidence import (
    BedrockCostReviewEvidence,
)
from unio_collector.scanners.analytics_ai.helpers import (
    add_analytics_ai_cost_context,
    build_analytics_ai_collector,
    record_analytics_ai_execution_detail,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class BedrockCostReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> BedrockCostReviewEvidence:  # noqa: D102
        collector = build_analytics_ai_collector(context)
        records = collector.collect_bedrock_records()
        records = add_analytics_ai_cost_context(records, context)
        regions = collector.get_available_regions()
        record_analytics_ai_execution_detail(
            context,
            records,
            regions=regions,
        )
        operation_limitations = [
            {
                "region": record.region,
                "api_action": limitation.api_action,
                "status": limitation.status,
                "error_classification": limitation.error_classification,
                "error_code": limitation.error_code,
            }
            for record in records
            for limitation in record.operation_limitations
        ]
        if operation_limitations:
            context.warnings.add_coverage_note(
                {
                    "note_type": "service_coverage",
                    "scanner_id": context.definition.scanner_id,
                    "scope_area": "bedrock_operation_capability",
                    "operation_limitations": operation_limitations,
                    "impact": ("Unsupported Bedrock operations were skipped while other regional Bedrock evidence collection continued."),
                },
            )
        return BedrockCostReviewEvidence(
            records=records,
            regions=regions,
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="BedrockCostReviewScanner",
            implementation_module="unio_collector.scanners.analytics_ai.bedrock.scanner",
        )
