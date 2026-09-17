from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.athena.query.scope import AthenaQueryCollectionScope
from unio_collector.scanners.analytics_ai.athena.evidence import (
    AthenaQueryEfficiencyReviewEvidence,
)
from unio_collector.scanners.analytics_ai.helpers import (
    add_analytics_ai_cost_context,
    build_analytics_ai_collector,
    record_analytics_ai_execution_detail,
)
from unio_collector.scanners.analytics_ai.policy_input import read_analytics_policy_input
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.options import parse_scanner_option_int
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.aws.athena.region_record import AthenaRegionRecord
    from unio_collector.scanners.scanner.context import ScannerContext


class AthenaQueryEfficiencyReviewCollector(BaseUnioScanner):
    """Collect service evidence independently of private finding interpretation."""

    def collect(self, context: ScannerContext) -> AthenaQueryEfficiencyReviewEvidence:  # noqa: D102
        collector = build_analytics_ai_collector(
            context,
            athena_query_execution_options=(self.build_query_execution_collection_options(context)),
        )
        records = collector.collect_athena_records()
        records = add_analytics_ai_cost_context(records, context)
        regions = collector.get_available_regions()
        record_analytics_ai_execution_detail(
            context,
            records,
            regions=regions,
        )
        self.record_query_execution_coverage_notes(context, records)
        return AthenaQueryEfficiencyReviewEvidence(
            records=records,
            regions=regions,
        )

    def build_query_execution_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> AthenaQueryCollectionScope:
        scanner_id = context.definition.scanner_id
        return AthenaQueryCollectionScope(
            max_query_execution_workgroups=max(
                1,
                parse_scanner_option_int(
                    context.options.get_for_scanner(
                        scanner_id,
                        "max_query_execution_workgroups",
                        10,
                    ),
                ),
            ),
            max_query_executions_per_workgroup=min(
                50,
                max(
                    1,
                    parse_scanner_option_int(
                        context.options.get_for_scanner(
                            scanner_id,
                            "max_query_executions_per_workgroup",
                            25,
                        ),
                    ),
                ),
            ),
            long_running_query_ms=read_analytics_policy_input(context, "long_running_query_ms", parse_scanner_option_int),
            high_bytes_scanned=read_analytics_policy_input(context, "high_bytes_scanned", parse_scanner_option_int),
            policy_input_source=1,
        )

    def record_query_execution_coverage_notes(  # noqa: D102
        self,
        context: ScannerContext,
        records: list[AthenaRegionRecord],
    ) -> None:
        for record in records:
            if not record.query_execution_collection_limited:
                continue
            context.warnings.add_coverage_note(
                {
                    "scanner_id": context.definition.scanner_id,
                    "note_type": "configuration_limit",
                    "scope_area": "analytics_ai_metadata",
                    "region": record.region,
                    "summary": ("Athena query-execution metadata collection was capped by scanner configuration."),
                    "reason": ("Athena query-execution metadata collection was capped by scanner configuration."),
                    "config_keys": [
                        ("athena-query-efficiency-review.max_query_execution_workgroups"),
                        ("athena-query-efficiency-review.max_query_executions_per_workgroup"),
                    ],
                    "workgroups_checked": (record.query_execution_workgroups_checked),
                    "workgroup_count": record.workgroup_count,
                    "query_execution_count": record.query_execution_count,
                },
            )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the existing scanner execution metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="AthenaQueryEfficiencyReviewScanner",
            implementation_module="unio_collector.scanners.analytics_ai.athena.scanner",
        )
