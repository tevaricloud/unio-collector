from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.cloudwatch import (
    CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
    CloudWatchLogMetricCollectionOptions,
    CloudWatchLogsCollector,
    LogGroupActivityRecord,
    LogGroupRecord,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class CloudWatchEvidenceMixin(EvidenceCollectionBase):  # noqa: D101
    def collect_cached_log_groups_without_retention(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> list[Any]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="cloudwatch_logs_inventory",
            label="CloudWatch Logs retention inventory",
        )
        collector = self.create_cloudwatch_logs_collector(definition)
        regions = collector.get_available_regions()
        activity_records = self.get_existing_log_activity_records(definition, regions)
        if activity_records is not None:
            return [
                LogGroupRecord(
                    log_group_name=record.log_group_name,
                    region=record.region,
                    stored_bytes=record.stored_bytes,
                )
                for record in activity_records
                if record.retention_in_days is None
            ]
        runtime_state = self.runner.runtime_state
        access = runtime_state.cache.get_or_load_with_status(
            "cloudwatch_logs_inventory",
            (
                runtime_state.account_id,
                "without_retention",
                tuple(regions),
            ),
            collector.collect_log_groups_without_retention,
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="cloudwatch_logs_inventory",
            label="CloudWatch Logs retention inventory",
            access_status=access.status,
        )
        return list(access.value)

    def get_existing_log_activity_records(  # noqa: D102
        self,
        definition: ScannerDefinition,
        regions: list[str],
    ) -> list[LogGroupActivityRecord] | None:
        access = None
        for metric_options in self._get_log_activity_cache_lookup_options(
            definition,
        ):
            access = self.runner.runtime_state.cache.get_existing_with_status(
                "cloudwatch_logs_activity",
                self._build_log_activity_cache_key(regions, metric_options),
                access_policy=self.build_cache_access_policy(
                    consumer_id=definition.scanner_id,
                ),
            )
            if access is not None:
                break
        if access is None:
            return None
        self.add_cached_evidence_note(
            definition,
            namespace="cloudwatch_logs_activity",
            label=("CloudWatch Logs retention inventory derived from activity metrics and inventory"),
            access_status=access.status,
        )
        return [record for record in access.value if isinstance(record, LogGroupActivityRecord)]

    def collect_cached_log_group_activity(  # noqa: D102
        self,
        definition: ScannerDefinition,
        metric_options: CloudWatchLogMetricCollectionOptions | None = None,
    ) -> list[Any]:
        self.ensure_can_start_evidence_collection(
            definition,
            namespace="cloudwatch_logs_activity",
            label="CloudWatch Logs activity metrics and inventory",
        )
        metric_options = metric_options or self._build_log_metric_options_for_scanner(
            definition.scanner_id,
        )
        collector = self.create_cloudwatch_logs_collector(definition)
        regions = collector.get_available_regions()
        runtime_state = self.runner.runtime_state
        period = runtime_state.config.scan_period
        access = runtime_state.cache.get_or_load_with_status(
            "cloudwatch_logs_activity",
            self._build_log_activity_cache_key(regions, metric_options),
            lambda: collector.collect_log_group_activity(period, metric_options),
            access_policy=self.build_cache_access_policy(
                consumer_id=definition.scanner_id,
            ),
        )
        self.add_cached_evidence_note(
            definition,
            namespace="cloudwatch_logs_activity",
            label="CloudWatch Logs activity metrics and inventory",
            access_status=access.status,
        )
        return list(access.value)

    def _build_log_activity_cache_key(
        self,
        regions: list[str],
        metric_options: CloudWatchLogMetricCollectionOptions,
    ) -> tuple[object, ...]:
        runtime_state = self.runner.runtime_state
        period = runtime_state.config.scan_period
        return (
            runtime_state.account_id,
            tuple(regions),
            period.current_start_date.isoformat(),
            period.current_end_exclusive.isoformat(),
            metric_options.convert_to_cache_key(),
        )

    def _build_log_metric_options_for_scanner(
        self,
        scanner_id: str,
    ) -> CloudWatchLogMetricCollectionOptions:
        runtime_state = self.runner.runtime_state
        return CloudWatchLogMetricCollectionOptions(
            metric_detail_mode=runtime_state.get_scanner_option(
                scanner_id,
                "metric_detail_mode",
                "full",
            ),
            max_metric_log_groups_per_region=runtime_state.get_scanner_option(
                scanner_id,
                "max_metric_log_groups_per_region",
                CLOUDWATCH_LOG_METRIC_DETAIL_DEFAULT_LIMIT,
            ),
            metric_prioritization_scope=runtime_state.get_scanner_option(
                scanner_id,
                "metric_prioritization_scope",
                "regional",
            ),
            max_metric_log_groups=runtime_state.get_scanner_option(
                scanner_id,
                "max_metric_log_groups",
                0,
            ),
        )

    def _get_log_activity_cache_lookup_options(
        self,
        definition: ScannerDefinition,
    ) -> list[CloudWatchLogMetricCollectionOptions]:
        options = [
            self._build_log_metric_options_for_scanner(definition.scanner_id),
            self._build_log_metric_options_for_scanner(
                "cloudwatch-idle-log-review",
            ),
        ]
        unique_options: list[CloudWatchLogMetricCollectionOptions] = []
        seen: set[tuple[str, int, str, int]] = set()
        for option in options:
            key = option.convert_to_cache_key()
            if key in seen:
                continue
            seen.add(key)
            unique_options.append(option)
        return unique_options

    def create_cloudwatch_logs_collector(  # noqa: D102
        self,
        definition: ScannerDefinition,
    ) -> CloudWatchLogsCollector:
        runtime_state = self.runner.runtime_state
        return CloudWatchLogsCollector(
            runtime_state.session,
            audit_context=self.runner.create_audit_context(
                definition,
                "CloudWatchLogsCollector",
            ),
            selected_regions=runtime_state.get_selected_regions(),
        )
