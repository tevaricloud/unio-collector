from __future__ import annotations  # noqa: D100

from abc import ABC
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch import (
    CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
    CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE,
    CloudWatchLogMetricCollectionOptions,
    LogGroupActivityRecord,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.cloudwatch.log_activity.evidence import (
    CloudWatchLogActivityEvidence,
)
from unio_collector.scanners.options import parse_scanner_option_int

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class CloudWatchLogActivityCollector(BaseUnioScanner, ABC):
    """Share evidence collection without private scanner analysis."""

    idle_days_option_key = "idle_days"

    def collect(self, context: ScannerContext) -> CloudWatchLogActivityEvidence:  # noqa: D102
        metric_options = self.build_metric_collection_options(context)
        records = context.cloudwatch.collect_log_group_activity(metric_options)
        self.add_metric_coverage_note(context, metric_options, records)
        return CloudWatchLogActivityEvidence(
            records=records,
            regions=self.get_regions_scanned(context),
            idle_days=self.get_idle_days(context),
        )

    def get_idle_days(self, context: ScannerContext) -> int:  # noqa: D102
        return parse_scanner_option_int(
            context.options.get(self.idle_days_option_key, 30),
        )

    def get_regions_scanned(self, context: ScannerContext) -> list[str]:  # noqa: D102
        collector = context.cloudwatch.create_logs_collector()
        return collector.get_available_regions()

    def build_metric_collection_options(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> CloudWatchLogMetricCollectionOptions:
        return CloudWatchLogMetricCollectionOptions(
            metric_detail_mode=context.options.get(
                "metric_detail_mode",
                "full",
            ),
            max_metric_log_groups_per_region=context.options.get(
                "max_metric_log_groups_per_region",
                CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
            ),
            metric_prioritization_scope=context.options.get(
                "metric_prioritization_scope",
                "regional",
            ),
            max_metric_log_groups=context.options.get(
                "max_metric_log_groups",
                0,
            ),
        )

    def add_metric_coverage_note(  # noqa: D102
        self,
        context: ScannerContext,
        metric_options: CloudWatchLogMetricCollectionOptions,
        records: list[Any],
    ) -> None:
        if metric_options.metric_detail_mode == "full":
            return
        typed_records = [record for record in records if isinstance(record, LogGroupActivityRecord)]
        skipped_count = sum(1 for record in typed_records if record.metric_collection_status == CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE)
        if skipped_count <= 0:
            return
        collected_count = len(typed_records) - skipped_count
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "cloudwatch_log_metrics",
                "summary": (
                    "CloudWatch Logs metric enrichment was prioritized for "
                    f"{collected_count} of {len(typed_records)} log group(s); "
                    f"{skipped_count} lower-priority group(s) kept inventory "
                    "and retention evidence only."
                ),
                "config_key": (f"{context.definition.scanner_id}.metric_detail_mode"),
                "configured_value": metric_options.metric_detail_mode,
                "metric_prioritization_scope": (metric_options.metric_prioritization_scope),
                "max_metric_log_groups": metric_options.max_metric_log_groups,
                "max_metric_log_groups_per_region": (metric_options.max_metric_log_groups_per_region),
                "result_scope": "current_scan",
                "impact": (
                    "Development scans preserve log group inventory, stored "
                    "bytes, and retention state, but do not collect ingestion "
                    "datapoints for every lower-priority log group."
                ),
            },
        )
