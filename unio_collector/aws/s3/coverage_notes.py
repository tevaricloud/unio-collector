from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import Any

from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions


@dataclass(frozen=True)
class S3BucketCoverageNoteBuilder:
    """Build structured neutral collection facts for compatibility callers."""

    scanner_id: str
    max_bucket_workers: int

    def build_lifecycle_configuration_notes(  # noqa: D102
        self,
        collection_options: S3LifecycleCollectionOptions | None = None,
    ) -> list[dict[str, Any]]:
        options = collection_options or S3LifecycleCollectionOptions()
        skipped = options.get_skipped_metadata()
        if not skipped:
            return []
        return [
            {
                "note_type": "collection_fact",
                "scope_area": "s3_lifecycle_metadata",
                "collection_profile": options.collection_profile,
                "metadata_not_collected": skipped,
            }
        ]

    def build_bucket_cap_note(  # noqa: D102
        self,
        *,
        max_buckets: int,
        selected_bucket_count: int,
        evaluated_bucket_count: int,
    ) -> dict[str, Any]:
        return {
            "note_type": "collection_fact",
            "scope_area": "s3_bucket_population",
            "operational_bucket_cap": max_buckets,
            "bucket_population_count": selected_bucket_count,
            "retained_bucket_count": evaluated_bucket_count,
            "cap_bound": evaluated_bucket_count < selected_bucket_count,
        }

    def build_execution_notes(  # noqa: D102
        self,
        *,
        include_lifecycle: bool,
        include_multipart: bool,
        lifecycle_bucket_count: int,
        lifecycle_region_count: int,
        multipart_bucket_count: int,
        collection_options: S3LifecycleCollectionOptions,
        conditional_versioning_skipped_count: int,
        prioritized_lifecycle_skipped_count: int,
        lifecycle_metric_unknown_count: int,
    ) -> list[dict[str, Any]]:
        del conditional_versioning_skipped_count, lifecycle_metric_unknown_count
        notes: list[dict[str, Any]] = []
        if include_lifecycle:
            notes.append(
                {
                    "note_type": "collection_fact",
                    "scope_area": "s3_lifecycle_metadata",
                    "retained_bucket_count": lifecycle_bucket_count,
                    "region_count": lifecycle_region_count,
                    "worker_count": self.max_bucket_workers,
                    "operational_detail_cap": (collection_options.get_operational_detail_cap()),
                    "cap_bound": prioritized_lifecycle_skipped_count > 0,
                }
            )
        if include_multipart:
            notes.append(
                self.build_multipart_execution_note(
                    multipart_bucket_count=multipart_bucket_count,
                )
            )
        return notes

    def build_lifecycle_execution_notes(  # noqa: D102
        self,
        *,
        lifecycle_bucket_count: int,
        lifecycle_region_count: int,
        collection_options: S3LifecycleCollectionOptions,
        conditional_versioning_skipped_count: int,
        prioritized_lifecycle_skipped_count: int,
        lifecycle_metric_unknown_count: int,
    ) -> list[dict[str, Any]]:
        return self.build_execution_notes(
            include_lifecycle=True,
            include_multipart=False,
            lifecycle_bucket_count=lifecycle_bucket_count,
            lifecycle_region_count=lifecycle_region_count,
            multipart_bucket_count=0,
            collection_options=collection_options,
            conditional_versioning_skipped_count=(conditional_versioning_skipped_count),
            prioritized_lifecycle_skipped_count=(prioritized_lifecycle_skipped_count),
            lifecycle_metric_unknown_count=lifecycle_metric_unknown_count,
        )

    def build_prioritized_lifecycle_limit_note(  # noqa: D102
        self,
        *,
        collection_options: S3LifecycleCollectionOptions,
        skipped_count: int,
        metric_unknown_count: int,
    ) -> dict[str, Any]:
        del metric_unknown_count
        return {
            "note_type": "collection_fact",
            "scope_area": "s3_lifecycle_metadata",
            "operational_detail_cap": (collection_options.get_operational_detail_cap()),
            "cap_bound": skipped_count > 0,
            "not_collected_bucket_count": skipped_count,
        }

    def build_conditional_versioning_note(  # noqa: D102
        self,
        *,
        skipped_count: int,
    ) -> dict[str, Any]:
        return {
            "note_type": "compatibility_option_fact",
            "option": "conditional_versioning_collection",
            "active_collection_effect": False,
            "skipped_bucket_count": skipped_count,
        }

    def build_multipart_execution_note(  # noqa: D102
        self,
        *,
        multipart_bucket_count: int,
    ) -> dict[str, Any]:
        return {
            "note_type": "collection_fact",
            "scope_area": "s3_multipart_upload_metadata",
            "retained_bucket_count": multipart_bucket_count,
            "worker_count": self.max_bucket_workers,
        }

    def build_multipart_abort_rule_skip_note(  # noqa: D102
        self,
        *,
        selected_bucket_count: int,
        evaluated_bucket_count: int,
    ) -> dict[str, Any]:
        return {
            "note_type": "compatibility_option_fact",
            "option": "skip_buckets_with_abort_incomplete_rule",
            "active_collection_effect": False,
            "bucket_population_count": selected_bucket_count,
            "retained_bucket_count": evaluated_bucket_count,
        }

    def build_multipart_bucket_cap_note(  # noqa: D102
        self,
        *,
        max_multipart_buckets: int,
        selection_mode: str,
        selection_context_available: bool,
        selected_bucket_count: int,
        evaluated_bucket_count: int,
    ) -> dict[str, Any]:
        del selection_mode, selection_context_available
        return {
            "note_type": "collection_fact",
            "scope_area": "s3_multipart_upload_metadata",
            "operational_bucket_cap": max_multipart_buckets,
            "bucket_population_count": selected_bucket_count,
            "retained_bucket_count": evaluated_bucket_count,
            "cap_bound": evaluated_bucket_count < selected_bucket_count,
            "selection_order": "bucket_name",
        }


__all__ = ["S3BucketCoverageNoteBuilder"]
