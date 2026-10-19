"""Actual shared Lambda/S3 collection behind synthetic ScannerContext gateways."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import TYPE_CHECKING

from tools.collector_sdk_fixture import SyntheticWrapperRuntime
from unio_collector.aws.lambda_cost.cycle.inventory.collector import LambdaCostCycleInventoryCollector
from unio_collector.aws.s3.collector import S3InventoryCollector

if TYPE_CHECKING:
    from tools.collector_serverless.session import SyntheticServerlessSession
    from unio_collector.aws.lambda_cost.function.inventory import LambdaFunctionInventoryRecord
    from unio_collector.aws.s3.bucket.index import S3BucketIndexResult
    from unio_collector.core.scan.period import ScanPeriod
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class SyntheticServerlessRuntime(SyntheticWrapperRuntime):
    """Invoke actual shared inventory collectors instead of supplying DTO fixtures."""

    def __init__(self, session: SyntheticServerlessSession, *, options: dict[str, object], period: ScanPeriod) -> None:
        """Bind local providers and a fixed reference without changing existing fixtures."""
        super().__init__(session, options=options, scan_period=period, service_costs=None, daily_costs=[])
        reference = datetime(2026, 9, 30, tzinfo=UTC)
        self.analysis_reference_time = SimpleNamespace(instant=reference, date=reference.date(), source="synthetic")

    def collect_cached_lambda_function_inventory(self, definition: ScannerDefinition) -> dict[str, list[LambdaFunctionInventoryRecord]]:
        """Exercise the real shared provider used by both actual wrapper consumers."""
        self.callbacks.append("lambda_function_inventory")
        collector = LambdaCostCycleInventoryCollector(
            self.runtime_state.session,
            account_id=self.runtime_state.account_id,
            audit_context=self.create_audit_context(definition, "LambdaFunctionInventoryCollector"),
            selected_regions=self.runtime_state.get_selected_regions(),
        )
        return collector.collect_function_inventory_by_region()

    def collect_cached_s3_bucket_index(self, definition: ScannerDefinition, *, max_bucket_workers: int) -> S3BucketIndexResult:
        """Exercise the actual S3 index and its supported provider metadata admission."""
        self.callbacks.append("s3_bucket_index")
        collector = S3InventoryCollector(
            self.runtime_state.session,
            account_id=self.runtime_state.account_id,
            audit_context=self.create_audit_context(definition, "S3BucketIndexCollector"),
            selected_regions=self.runtime_state.get_selected_regions(),
            max_bucket_workers=max_bucket_workers,
        )
        return collector.collect_bucket_index()
