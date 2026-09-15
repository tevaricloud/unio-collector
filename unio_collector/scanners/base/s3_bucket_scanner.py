from __future__ import annotations  # noqa: D100

from unio_collector.aws.s3 import (
    S3LifecycleCollectionOptions,
    normalize_s3_multipart_bucket_selection_mode,
)
from unio_collector.scanners.base import BaseUnioScanner, ScannerContext
from unio_collector.scanners.options import (
    parse_scanner_option_bool,
    parse_scanner_option_int,
)


class BaseS3BucketCostScanner(BaseUnioScanner):  # noqa: D101
    def _get_upload_cap(self, context: ScannerContext) -> int:
        return max(
            1,
            context.options.get_int("max_multipart_uploads_per_bucket", 1000),
        )

    def _get_multipart_bucket_cap(self, context: ScannerContext) -> int:
        return max(
            0,
            context.options.get_int("max_multipart_buckets", 0),
        )

    def _get_multipart_bucket_selection_mode(self, context: ScannerContext) -> str:
        return normalize_s3_multipart_bucket_selection_mode(
            context.options.get(
                "multipart_bucket_selection_mode",
                "inventory-order",
            ),
        )

    def _get_bucket_cap(self, context: ScannerContext) -> int:
        return max(
            0,
            context.options.get_int("max_buckets", 1000),
        )

    def _get_bucket_worker_count(self, context: ScannerContext) -> int:
        default_workers = context.options.get_runtime_max_workers(16)
        return max(1, context.options.get_int("max_bucket_workers", default_workers))

    def _get_skip_abort_rule_buckets(self, context: ScannerContext) -> bool:
        return context.options.get_bool(
            "skip_buckets_with_abort_incomplete_rule",
            default=True,
        )

    def _get_lifecycle_collection_options(
        self,
        context: ScannerContext,
        *,
        scanner_id: str | None = None,
    ) -> S3LifecycleCollectionOptions:
        option_scanner_id = scanner_id or context.definition.scanner_id
        return S3LifecycleCollectionOptions.from_profile(
            context.options.get_for_scanner(
                option_scanner_id,
                "collection_profile",
                default="full",
            ),
            collect_tags=self._get_optional_bool_option(
                context,
                option_scanner_id,
                "collect_tags",
            ),
            collect_versioning=self._get_optional_bool_option(
                context,
                option_scanner_id,
                "collect_versioning",
            ),
            collect_replication=self._get_optional_bool_option(
                context,
                option_scanner_id,
                "collect_replication",
            ),
            conditional_versioning_collection=self._get_optional_bool_option(
                context,
                option_scanner_id,
                "conditional_versioning_collection",
            ),
            lifecycle_detail_mode=context.options.get_for_scanner(
                option_scanner_id,
                "lifecycle_detail_mode",
                None,
            ),
            prioritized_lifecycle_bucket_count=self._get_optional_int_option(
                context,
                option_scanner_id,
                "prioritized_lifecycle_bucket_count",
            ),
            include_lifecycle_metric_unknown_buckets=self._get_optional_bool_option(
                context,
                option_scanner_id,
                "include_lifecycle_metric_unknown_buckets",
            ),
        )

    def _get_optional_bool_option(
        self,
        context: ScannerContext,
        scanner_id: str,
        key: str,
    ) -> bool | None:
        value = context.options.get_for_scanner(scanner_id, key, None)
        if value is None:
            return None
        return parse_scanner_option_bool(value)

    def _get_optional_int_option(
        self,
        context: ScannerContext,
        scanner_id: str,
        key: str,
    ) -> int | None:
        value = context.options.get_for_scanner(scanner_id, key, None)
        if value is None:
            return None
        return parse_scanner_option_int(value)

    def _record_collection_context(
        self,
        context: ScannerContext,
        *,
        warnings: list[str],
        coverage_notes: list[dict[str, object]],
    ) -> None:
        for warning in warnings:
            context.warnings.add(warning)
        for note in coverage_notes:
            context.warnings.add_coverage_note(note)
