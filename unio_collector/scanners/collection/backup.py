from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.backup import (
    BackupInventoryCollector,
    normalize_backup_selection_detail_mode,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation


class BackupRetentionReviewCollector(RegionalInventoryCollector):
    """Collect provider evidence for backup-retention-review."""

    collector_id = "BackupInventoryCollector"

    collector_type = BackupInventoryCollector

    def create_collector(self, context: ScannerContext) -> BackupInventoryCollector:  # noqa: D102
        return context.security.create_regional_inventory_collector(
            BackupInventoryCollector,
            collector_name=self.collector_id,
            max_detail_workers=self.get_detail_worker_count(context),
            collect_tags=self.get_collect_tags(context),
        )

    def collect_inventory_records(  # noqa: D102
        self,
        collector: BackupInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        selection_detail_mode = self.get_selection_detail_mode(context)
        self.record_detail_worker_note(context, self.get_detail_worker_count(context))
        self.record_age_policy_note(context, self.get_older_than_days(context))
        self.record_selection_detail_mode_note(context, selection_detail_mode)
        self.record_tag_collection_note(
            context,
            collect_tags=self.get_collect_tags(context),
        )
        return list(
            collector.collect_inventory_records(
                selection_detail_mode=selection_detail_mode,
                reference_time=context.analysis.reference_instant,
            ),
        )

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: BackupInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, Any]:
        del collector
        return {
            "older_than_days": self.get_older_than_days(context),
            "long_retention_days": self.get_long_retention_days(context),
            "selection_detail_mode": self.get_selection_detail_mode(context),
            "max_detail_workers": self.get_detail_worker_count(context),
            "collect_tags": self.get_collect_tags(context),
        }

    def get_older_than_days(self, context: ScannerContext) -> int:  # noqa: D102
        return context.options.get_int("older_than_days", 90)

    def get_long_retention_days(self, context: ScannerContext) -> int:  # noqa: D102
        return context.options.get_int("long_retention_days", 365)

    def get_selection_detail_mode(self, context: ScannerContext) -> str:  # noqa: D102
        return normalize_backup_selection_detail_mode(
            context.options.get("selection_detail_mode", "full"),
        )

    def get_detail_worker_count(self, context: ScannerContext) -> int:  # noqa: D102
        default_workers = context.options.get_runtime_max_workers(16)
        return max(1, context.options.get_int("max_detail_workers", default_workers))

    def get_collect_tags(self, context: ScannerContext) -> bool:  # noqa: D102
        return context.options.get_bool("collect_tags", default=True)

    def record_detail_worker_note(  # noqa: D102
        self,
        context: ScannerContext,
        worker_count: int,
    ) -> None:
        context.warnings.add_coverage_note(
            {
                "note_type": "execution_detail",
                "scope_area": "backup_metadata_details",
                "summary": (f"AWS Backup metadata detail collection used up to {worker_count} bounded worker(s)."),
                "configured_value": worker_count,
                "config_key": "backup-retention-review.max_detail_workers",
                "result_scope": "current_scan",
            },
        )

    def record_age_policy_note(  # noqa: D102
        self,
        context: ScannerContext,
        older_than_days: int,
    ) -> None:
        context.warnings.add_coverage_note(
            {
                "note_type": "analysis_policy",
                "scope_area": "backup_recovery_points",
                "summary": (
                    f"AWS Backup recovery point findings require an age of at least {older_than_days} days; collection retains younger recovery-point evidence."
                ),
                "configured_limit": older_than_days,
                "config_key": "backup-retention-review.older_than_days",
                "result_scope": "finding_analysis",
            },
        )

    def record_selection_detail_mode_note(  # noqa: D102
        self,
        context: ScannerContext,
        selection_detail_mode: str,
    ) -> None:
        if selection_detail_mode == "full":
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "backup_selection_details",
                "summary": ("AWS Backup selection detail collection used summary mode; GetBackupSelection calls were skipped for faster development scans."),
                "configured_value": selection_detail_mode,
                "config_key": "backup-retention-review.selection_detail_mode",
                "result_scope": "current_scan",
                "impact": (
                    "Summary mode preserves backup plan and selection inventory "
                    "but cannot confirm broad resource selections. Use full mode "
                    "for client-facing backup scope validation."
                ),
            },
        )

    def record_tag_collection_note(  # noqa: D102
        self,
        context: ScannerContext,
        *,
        collect_tags: bool,
    ) -> None:
        if collect_tags:
            return
        context.warnings.add_coverage_note(
            {
                "note_type": "configuration_limit",
                "scope_area": "backup_resource_tags",
                "summary": ("AWS Backup plan and vault tag collection was skipped by scanner configuration."),
                "configured_value": collect_tags,
                "config_key": "backup-retention-review.collect_tags",
                "result_scope": "current_scan",
                "impact": (
                    "Retention, copy, vault, and recovery-point checks still "
                    "run, but ownership-tag findings are not generated from "
                    "missing tag data in this mode."
                ),
            },
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="BackupRetentionReviewScanner",
            implementation_module="unio_collector.scanners.backup",
        )
