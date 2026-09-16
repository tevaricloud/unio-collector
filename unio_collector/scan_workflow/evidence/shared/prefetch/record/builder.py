from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.scan_workflow.evidence.cache_policy import (
    AwsEvidenceCacheFailureClassifier,
    is_timeout_or_cancellation_failure,
)
from unio_collector.scan_workflow.evidence.cost.explorer import (
    SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
)
from unio_collector.scan_workflow.evidence.s3 import (
    SHARED_S3_BUCKET_INDEX_SCANNER_ID,
)

if TYPE_CHECKING:
    from unio_collector.aws.cache import AwsScanCacheAccess
    from unio_collector.aws.cost_explorer import DailyCostRecord
    from unio_collector.aws.s3 import S3BucketIndexResult


@dataclass(frozen=True)
class SharedEvidencePrefetchRecordBuilder:
    """Builds stable scheduler records for shared-evidence prefetches."""

    def build_s3_bucket_index_completed_record(  # noqa: D102
        self,
        *,
        access: AwsScanCacheAccess[S3BucketIndexResult],
        selected_regions: list[str],
        worker_count: int,
        duration_ms: int,
    ) -> dict[str, Any]:
        return {
            "namespace": "s3_bucket_index",
            "consumer_id": SHARED_S3_BUCKET_INDEX_SCANNER_ID,
            "status": "completed",
            "cache_access_status": access.status,
            "selected_regions": list(selected_regions),
            "worker_count": worker_count,
            "duration_ms": duration_ms,
            "discovered_bucket_count": access.value.discovered_bucket_count,
            "selected_bucket_count": access.value.selected_bucket_count,
            "contains_client_result_data": False,
        }

    def build_s3_bucket_index_degradation_record(  # noqa: D102
        self,
        *,
        selected_regions: list[str],
        worker_count: int,
        error: BaseException | None = None,
        degradation_category: str | None = None,
        error_code: str | None = None,
        duration_ms: int,
    ) -> dict[str, Any]:
        category, resolved_error_code = _classify_s3_prefetch_degradation(
            error,
            degradation_category=degradation_category,
            error_code=error_code,
        )
        return {
            "namespace": "s3_bucket_index",
            "consumer_id": SHARED_S3_BUCKET_INDEX_SCANNER_ID,
            "status": ("failed" if category == "internal_collection_failure" else "degraded"),
            "degradation_category": category,
            "selected_regions": list(selected_regions),
            "worker_count": worker_count,
            "error_code": resolved_error_code,
            "duration_ms": duration_ms,
            "contains_client_result_data": False,
        }

    def build_s3_bucket_index_failed_record(  # noqa: D102
        self,
        *,
        selected_regions: list[str],
        worker_count: int,
        error: Exception,
        duration_ms: int,
    ) -> dict[str, Any]:
        return self.build_s3_bucket_index_degradation_record(
            selected_regions=selected_regions,
            worker_count=worker_count,
            error=error,
            duration_ms=duration_ms,
        )

    def build_cost_explorer_completed_record(  # noqa: D102
        self,
        *,
        group_keys: tuple[str, ...],
        access: AwsScanCacheAccess[list[DailyCostRecord]],
        duration_ms: int,
    ) -> dict[str, Any]:
        return {
            "namespace": "cost_explorer_daily_costs",
            "consumer_id": SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
            "group_keys": list(group_keys),
            "cache_access_status": access.status,
            "status": "completed",
            "duration_ms": duration_ms,
            "record_count": len(access.value),
            "contains_client_result_data": False,
        }

    def build_cost_explorer_failed_record(  # noqa: D102
        self,
        *,
        group_keys: tuple[str, ...],
        error: Exception,
        duration_ms: int,
    ) -> dict[str, Any]:
        return {
            "namespace": "cost_explorer_daily_costs",
            "consumer_id": SHARED_COST_EXPLORER_DAILY_COST_SCANNER_ID,
            "group_keys": list(group_keys),
            "status": "failed",
            "error_code": (aws_errors.get_aws_error_code(error) or error.__class__.__name__),
            "duration_ms": duration_ms,
            "contains_client_result_data": False,
        }


def _classify_s3_prefetch_degradation(
    error: BaseException | None,
    *,
    degradation_category: str | None,
    error_code: str | None,
) -> tuple[str, str]:
    if error is None:
        return (
            degradation_category or "internal_collection_failure",
            error_code or "UnknownPrefetchFailure",
        )
    decision = AwsEvidenceCacheFailureClassifier().classify(error)
    if is_timeout_or_cancellation_failure(error):
        category = "timeout_or_cancellation"
    elif decision.category.value in {
        "permission_denied",
        "expected_absence",
    }:
        category = decision.category.value
    elif decision.category.value in {
        "service_unavailable",
        "throttling",
        "transient_network",
    }:
        category = "service_unavailable"
    else:
        category = "internal_collection_failure"
    return category, decision.error_code or error.__class__.__name__
