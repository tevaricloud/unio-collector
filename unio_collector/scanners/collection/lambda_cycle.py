from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.lambda_cost.cycle.inventory.collector import (
    LambdaCostCycleInventoryCollector,
)
from unio_collector.aws.serverless.inventory_helpers import (
    normalize_s3_notification_detail_mode,
)
from unio_collector.scanners.regional.collection import RegionalInventoryCollector
from unio_collector.scanners.scanner.implementation import ScannerImplementation

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


class LambdaCostCycleRiskCollector(RegionalInventoryCollector):
    """Collect provider evidence for lambda-cost-cycle-risk-review."""

    collector_id = "LambdaCostCycleInventoryCollector"

    collector_type = LambdaCostCycleInventoryCollector

    def create_collector(  # noqa: D102
        self,
        context: ScannerContext,
    ) -> LambdaCostCycleInventoryCollector:
        max_s3_buckets = self._get_max_s3_buckets(context)
        s3_notification_worker_count = self._get_s3_notification_worker_count(context)
        s3_policy_scan_max_functions = self._get_s3_policy_scan_max_functions(context)
        s3_notification_detail_mode = self._get_s3_notification_detail_mode(context)
        return context.security.create_regional_inventory_collector(
            LambdaCostCycleInventoryCollector,
            collector_name="LambdaCostCycleInventoryCollector",
            max_s3_buckets=max_s3_buckets,
            s3_notification_worker_count=s3_notification_worker_count,
            s3_policy_scan_max_functions=s3_policy_scan_max_functions,
            collect_tags=self._get_collect_tags(context),
            s3_notification_detail_mode=s3_notification_detail_mode,
        )

    def collect_inventory_records(  # noqa: D102
        self,
        collector: LambdaCostCycleInventoryCollector,
        context: ScannerContext,
    ) -> list[object]:
        s3_notification_detail_mode = self._get_s3_notification_detail_mode(context)
        s3_bucket_index = None
        if s3_notification_detail_mode == "full":
            s3_bucket_index = context.s3.collect_bucket_index(
                max_bucket_workers=self._get_s3_notification_worker_count(context),
            )
        lambda_inventory = context.lambda_.collect_function_inventory()
        return list(
            collector.collect_functions(
                context.options.get_scan_period(),
                s3_bucket_index=s3_bucket_index,
                lambda_function_inventory_by_region=lambda_inventory,
            ),
        )

    def collect_inventory_metadata(  # noqa: D102
        self,
        collector: LambdaCostCycleInventoryCollector,
        context: ScannerContext,
    ) -> dict[str, object]:
        return {
            "s3_notification_scan_summary": (collector.s3_notification_scan_summary.convert_to_dict()),
            "collection_summary": collector.collection_summary.convert_to_dict(),
            "collect_tags": self._get_collect_tags(context),
        }

    def _get_max_s3_buckets(self, context: ScannerContext) -> int | None:
        raw_value = context.options.get_for_scanner(
            self.metadata.scanner_id,
            "max_s3_buckets",
            25,
        )
        if raw_value in (None, ""):
            return None
        value = int(str(raw_value))
        if value <= 0:
            msg = "lambda-cost-cycle-risk-review.max_s3_buckets must be positive."
            raise ValueError(
                msg,
            )
        return value

    def _get_s3_notification_worker_count(self, context: ScannerContext) -> int:
        raw_value = context.options.get_for_scanner(
            self.metadata.scanner_id,
            "s3_notification_worker_count",
            8,
        )
        value = int(str(raw_value))
        if value <= 0:
            msg = "lambda-cost-cycle-risk-review.s3_notification_worker_count must be positive."
            raise ValueError(
                msg,
            )
        return value

    def _get_s3_policy_scan_max_functions(self, context: ScannerContext) -> int:
        raw_value = context.options.get_for_scanner(
            self.metadata.scanner_id,
            "s3_policy_scan_max_functions",
            50,
        )
        value = int(str(raw_value))
        if value < 0:
            msg = "lambda-cost-cycle-risk-review.s3_policy_scan_max_functions must be zero or positive."
            raise ValueError(
                msg,
            )
        return value

    def _get_s3_notification_detail_mode(self, context: ScannerContext) -> str:
        return normalize_s3_notification_detail_mode(
            context.options.get_for_scanner(
                self.metadata.scanner_id,
                "s3_notification_detail_mode",
                "full",
            ),
        )

    def _get_collect_tags(self, context: ScannerContext) -> bool:
        value = context.options.get_for_scanner(
            self.metadata.scanner_id,
            "collect_tags",
            default=True,
        )
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() not in {"0", "false", "no", "off"}

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="LambdaCostCycleRiskScanner",
            implementation_module="unio_collector.scanners.lambda_cost_cycle",
        )
