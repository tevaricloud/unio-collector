from __future__ import annotations  # noqa: D104

import time

from unio_collector.aws.audit import AwsAuditContext
from unio_collector.aws.s3 import S3BucketIndexResult, S3InventoryCollector
from unio_collector.scan_workflow.evidence.cost.explorer import (
    SHARED_COST_EXPLORER_DAILY_COST_API_CALLS,
    SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS,
    SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
)
from unio_collector.scan_workflow.evidence.cost.explorer.keys import (
    CostExplorerEvidenceCacheKeyBuilder,
)
from unio_collector.scan_workflow.evidence.prefetch.records import (
    SharedEvidencePrefetchRecordBuilder,
    SharedEvidencePrefetchRecordSorter,
)
from unio_collector.scan_workflow.evidence.prefetch.tasks import (
    SharedEvidencePrefetchTaskBuilder,
)
from unio_collector.scan_workflow.evidence.s3 import (
    SHARED_S3_BUCKET_INDEX_API_CALLS,
    SHARED_S3_BUCKET_INDEX_SCANNER_ID,
)
from unio_collector.scan_workflow.evidence.service import EvidenceCollectionBase
from unio_collector.scan_workflow.shared.evidence import (
    SharedEvidencePrefetchCoordinator,
    SharedEvidencePrefetchTask,
)


class SharedEvidencePrefetchMixin(EvidenceCollectionBase):  # noqa: D101
    def build_shared_evidence_prefetch_records(  # noqa: D102
        self,
    ) -> SharedEvidencePrefetchRecordBuilder:
        return SharedEvidencePrefetchRecordBuilder()

    def build_shared_evidence_prefetch_record_sorter(  # noqa: D102
        self,
    ) -> SharedEvidencePrefetchRecordSorter:
        return SharedEvidencePrefetchRecordSorter()

    def prefetch_shared_evidence(  # noqa: D102
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        tasks = self._build_shared_evidence_prefetch_tasks(scanner_ids)
        SharedEvidencePrefetchCoordinator(
            max_workers=self._get_shared_prefetch_worker_count(tasks),
            concurrency_enabled=(self.runner.runtime_state.runtime_config.scanner_concurrency_enabled),
            record_failure=self.runner.shared_evidence_prefetches.append,
        ).run_tasks(tasks)
        self.sort_shared_evidence_prefetches()

    def _build_shared_evidence_prefetch_tasks(
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> list[SharedEvidencePrefetchTask]:
        return SharedEvidencePrefetchTaskBuilder.create(scanner_ids).build_tasks(
            prefetch_s3_bucket_index=(lambda: self._run_shared_s3_bucket_index_prefetch(scanner_ids)),
            prefetch_cost_explorer_daily_costs=(lambda: self.prefetch_shared_cost_explorer_daily_costs(scanner_ids)),
        )

    def _run_shared_s3_bucket_index_prefetch(
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        self.prefetch_shared_s3_bucket_index(scanner_ids)

    def should_prefetch_shared_s3_bucket_index(  # noqa: D102
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> bool:
        return SharedEvidencePrefetchTaskBuilder.create(scanner_ids).should_prefetch_s3_bucket_index()

    def should_prefetch_shared_cost_explorer_daily_costs(  # noqa: D102
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> bool:
        return SharedEvidencePrefetchTaskBuilder.create(scanner_ids).should_prefetch_cost_explorer_daily_costs()

    def _get_shared_prefetch_worker_count(
        self,
        tasks: list[SharedEvidencePrefetchTask],
    ) -> int:
        configured = int(
            getattr(
                self.runner.runtime_state.runtime_config,
                "scanner_max_workers",
                1,
            )
            or 1,
        )
        return SharedEvidencePrefetchTaskBuilder.create(()).get_worker_count(
            configured_max_workers=configured,
            tasks=tasks,
        )

    def sort_shared_evidence_prefetches(self) -> None:  # noqa: D102
        self.build_shared_evidence_prefetch_record_sorter().sort_records(
            self.runner.shared_evidence_prefetches,
        )

    def prefetch_shared_s3_bucket_index(  # noqa: D102
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> S3BucketIndexResult | None:
        if not self.should_prefetch_shared_s3_bucket_index(scanner_ids):
            return None
        runtime_state = self.runner.runtime_state
        max_bucket_workers = max(
            1,
            int(getattr(runtime_state.runtime_config, "max_workers", 16)),
        )
        started = time.perf_counter()
        if not hasattr(runtime_state.session, "create_client"):
            selected_regions = list(runtime_state.config.regions or [])
            self.runner.shared_evidence_prefetches.append(
                self.build_shared_evidence_prefetch_records().build_s3_bucket_index_degradation_record(
                    selected_regions=selected_regions,
                    worker_count=max_bucket_workers,
                    degradation_category="service_unavailable",
                    error_code="AwsClientFactoryUnavailable",
                    duration_ms=int((time.perf_counter() - started) * 1000),
                ),
            )
            return None
        selected_regions = runtime_state.get_selected_regions() or []
        collector = S3InventoryCollector(
            runtime_state.session,
            account_id=runtime_state.account_id,
            audit_context=AwsAuditContext(
                scanner_id=SHARED_S3_BUCKET_INDEX_SCANNER_ID,
                collector="SharedS3BucketIndexPrefetch",
                allowed_api_calls=SHARED_S3_BUCKET_INDEX_API_CALLS,
                recipient_account_id=runtime_state.account_id,
            ),
            selected_regions=runtime_state.get_selected_regions(),
            max_bucket_workers=max_bucket_workers,
        )
        cache_key_parts = (
            runtime_state.account_id,
            tuple(selected_regions),
        )
        try:
            access = runtime_state.cache.get_or_load_with_status(
                "s3_bucket_index",
                cache_key_parts,
                collector.collect_bucket_index,
                access_policy=self.build_cache_access_policy(
                    consumer_id=SHARED_S3_BUCKET_INDEX_SCANNER_ID,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            self.runner.shared_evidence_prefetches.append(
                self.build_shared_evidence_prefetch_records().build_s3_bucket_index_degradation_record(
                    selected_regions=selected_regions,
                    worker_count=max_bucket_workers,
                    error=exc,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                ),
            )
            return None
        self.runner.shared_evidence_prefetches.append(
            self.build_shared_evidence_prefetch_records().build_s3_bucket_index_completed_record(
                access=access,
                selected_regions=selected_regions,
                worker_count=max_bucket_workers,
                duration_ms=int((time.perf_counter() - started) * 1000),
            ),
        )
        return access.value

    def prefetch_shared_cost_explorer_daily_costs(  # noqa: D102
        self,
        scanner_ids: tuple[str, ...] | list[str],
    ) -> None:
        if not self.should_prefetch_shared_cost_explorer_daily_costs(scanner_ids):
            return
        enabled_scanner_ids = set(scanner_ids)
        for group_keys, consumers in SHARED_COST_EXPLORER_DAILY_COST_CONSUMERS.items():
            if not enabled_scanner_ids.intersection(consumers):
                continue
            self._prefetch_cost_explorer_daily_cost_group(group_keys)

    def _prefetch_cost_explorer_daily_cost_group(
        self,
        group_keys: tuple[str, ...],
    ) -> None:
        runtime_state = self.runner.runtime_state
        audit_context = AwsAuditContext(
            scanner_id=SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
            collector="SharedCostExplorerDailyCostPrefetch",
            allowed_api_calls=SHARED_COST_EXPLORER_DAILY_COST_API_CALLS,
            recipient_account_id=runtime_state.account_id,
        )
        period = runtime_state.config.scan_period
        cache_key_parts = CostExplorerEvidenceCacheKeyBuilder(
            account_id=runtime_state.account_id,
        ).build_daily_costs_key(
            period=period,
            group_keys=group_keys,
        )
        started = time.perf_counter()
        try:
            collector = self.runner.create_cost_explorer_collector(audit_context)
            access = runtime_state.cache.get_or_load_with_status(
                "cost_explorer_daily_costs",
                cache_key_parts,
                lambda: collector.collect_daily_costs(
                    scan_period=period,
                    group_keys=group_keys,
                ),
                access_policy=self.build_cache_access_policy(
                    consumer_id=SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            self.runner.shared_evidence_prefetches.append(
                self.build_shared_evidence_prefetch_records().build_cost_explorer_failed_record(
                    group_keys=group_keys,
                    error=exc,
                    duration_ms=int((time.perf_counter() - started) * 1000),
                ),
            )
            return
        self.runner.shared_evidence_prefetches.append(
            self.build_shared_evidence_prefetch_records().build_cost_explorer_completed_record(
                group_keys=group_keys,
                access=access,
                duration_ms=int((time.perf_counter() - started) * 1000),
            ),
        )
