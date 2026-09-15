from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, cast

from unio_collector.aws.serverless.sqs_lambda.collector import SqsLambdaInventoryCollector
from unio_collector.scanners.options import parse_scanner_option_int

if TYPE_CHECKING:
    from unio_collector.scanners.base import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class SqsLambdaPollingCostReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for sqs-lambda-polling-cost-review."""

    collector_id = "SqsLambdaInventoryCollector"

    collector_type = SqsLambdaInventoryCollector

    def collect_inventory_records(  # noqa: D102
        self,
        collector: SqsLambdaInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        max_mappings_per_region = self.get_max_mappings_per_region(context)
        records = list(
            collector.collect_event_source_mappings(
                context.options.get_scan_period(),
                max_mappings_per_region=max_mappings_per_region,
            ),
        )
        if collector.collection_summary.collection_capped:
            self.record_mapping_limit_note(context, max_mappings_per_region)
        return cast("list[object]", records)

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: SqsLambdaInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, object]:
        max_mappings_per_region = self.get_max_mappings_per_region(context)
        return {
            "max_mappings_per_region": max_mappings_per_region,
            "metric_collection_mode": "batched_cloudwatch_metric_data",
            "collection_summary": collector.collection_summary.convert_to_dict(),
        }

    def get_max_mappings_per_region(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> int | None:
        value = parse_scanner_option_int(
            context.options.get(
                "max_mappings_per_region",
                0,
            ),
        )
        if value <= 0:
            return None
        return value

    def record_mapping_limit_note(  # noqa: D102
        self,
        context: ScannerContext,
        max_mappings_per_region: int | None,
    ) -> None:
        if max_mappings_per_region is None:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "sqs_lambda_event_source_mappings",
                "summary": (f"SQS Lambda polling review was capped at {max_mappings_per_region} SQS event source mapping(s) per region for this scan."),
                "configured_limit": max_mappings_per_region,
                "config_key": ("sqs-lambda-polling-cost-review.max_mappings_per_region"),
                "result_scope": "current_scan",
                "impact": ("Topology and metric collection are bounded for faster development scans. Use 0 for full per-region mapping coverage."),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="SqsLambdaPollingCostReviewScanner",
            implementation_module="unio_collector.scanners.serverless_polling",
        )
