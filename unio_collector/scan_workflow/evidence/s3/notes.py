from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.aws.s3 import (
        S3LifecycleCollectionOptions,
        S3LifecycleCollectionSummary,
        S3MultipartCollectionSummary,
    )
    from unio_collector.scanners.scanner.definition import ScannerDefinition


@dataclass(frozen=True)
class S3EvidenceCoverageNoteBuilder:
    """Builds scanner coverage notes for shared S3 evidence reuse."""

    def build_multipart_lifecycle_dependency_note(  # noqa: D102
        self,
        *,
        lifecycle_available: bool,
    ) -> dict[str, Any]:
        if lifecycle_available:
            summary = "S3 incomplete multipart upload review retained same-scan lifecycle context for analyzer interpretation."
            impact = (
                "The context can reproduce historical abort-rule and storage "
                "interpretation without changing the neutral bucket population "
                "queried by the collector."
            )
        else:
            summary = "S3 incomplete multipart upload review did not find same-scan lifecycle context."
            impact = "Abort-rule and storage-priority interpretation is unavailable; collected multipart evidence remains authoritative."
        return {
            "note_type": "evidence_dependency",
            "summary": summary,
            "dependency_namespace": "s3_lifecycle_inventory",
            "dependency_available": lifecycle_available,
            "result_scope": "current_scan",
            "impact": impact,
        }

    def build_lifecycle_collection_notes(  # noqa: D102
        self,
        *,
        definition: ScannerDefinition,
        summary: S3LifecycleCollectionSummary | None,
        collection_options: S3LifecycleCollectionOptions,
    ) -> list[dict[str, Any]]:
        if summary is None:
            return []
        notes = self.build_reused_lifecycle_notes(
            definition=definition,
            collection_options=collection_options,
            access_status="loaded",
        )[:-1]
        notes.append(
            {
                "note_type": "execution_detail",
                "scope_area": "s3_lifecycle_metadata",
                "summary": (
                    "S3 lifecycle evidence collection retained "
                    f"{summary.retained_bucket_count} of "
                    f"{summary.bucket_population_count} bucket(s) in stable "
                    "bucket-name order."
                ),
                "collection_state": summary.collection_state,
                "operational_detail_cap": summary.operational_detail_cap,
                "cap_bound": summary.cap_bound,
                "worker_count": summary.worker_count,
                "region_count": summary.region_count,
                "result_scope": "current_scan",
            }
        )
        if summary.collection_capped or summary.collection_partial:
            notes.append(
                {
                    "note_type": "configuration_limit",
                    "scope_area": "s3_lifecycle_metadata",
                    "summary": ("S3 lifecycle evidence is incomplete because an operational detail cap bound or one or more configured reads failed."),
                    "config_key": f"{definition.scanner_id}.lifecycle_detail_mode",
                    "collection_state": summary.collection_state,
                    "configured_limit": summary.operational_detail_cap,
                    "result_scope": "current_scan",
                    "impact": "Findings are limited to successfully collected bucket evidence.",
                }
            )
        return notes

    def build_multipart_collection_notes(  # noqa: D102
        self,
        *,
        summary: S3MultipartCollectionSummary | None,
    ) -> list[dict[str, Any]]:
        if summary is None:
            return []
        notes = [
            {
                "note_type": "execution_detail",
                "scope_area": "s3_multipart_upload_metadata",
                "summary": (
                    "S3 multipart evidence collection retained "
                    f"{summary.retained_bucket_count} of "
                    f"{summary.bucket_population_count} bucket(s) in stable "
                    "bucket-name order."
                ),
                "collection_state": summary.collection_state,
                "operational_bucket_cap": summary.operational_bucket_cap,
                "cap_bound": summary.cap_bound,
                "max_uploads_per_bucket": summary.max_uploads_per_bucket,
                "result_scope": "current_scan",
            }
        ]
        if summary.collection_capped or summary.collection_partial:
            notes.append(
                {
                    "note_type": "configuration_limit",
                    "scope_area": "s3_multipart_upload_metadata",
                    "summary": ("S3 multipart evidence is incomplete because an operational bucket or pagination cap bound, or a read failed."),
                    "config_key": "s3-incomplete-multipart-review.max_multipart_buckets",
                    "configured_limit": summary.operational_bucket_cap,
                    "collection_state": summary.collection_state,
                    "result_scope": "current_scan",
                    "impact": "Findings are limited to successfully collected bucket evidence.",
                }
            )
        return notes

    def build_reused_lifecycle_notes(  # noqa: D102
        self,
        *,
        definition: ScannerDefinition,
        collection_options: S3LifecycleCollectionOptions,
        access_status: str,
    ) -> list[dict[str, Any]]:
        notes: list[dict[str, Any]] = []
        skipped_metadata = collection_options.get_skipped_metadata()
        if skipped_metadata:
            skipped_labels = ", ".join(skipped_metadata)
            notes.append(
                {
                    "note_type": "configuration_limit",
                    "summary": (
                        "S3 bucket metadata collection used the "
                        f"{collection_options.collection_profile} collection "
                        f"profile; skipped metadata: {skipped_labels}."
                    ),
                    "config_key": f"{definition.scanner_id}.collection_profile",
                    "configured_value": collection_options.collection_profile,
                    "skipped_metadata": skipped_metadata,
                    "result_scope": "current_scan",
                    "impact": (
                        "Skipped optional metadata reduces S3 API calls for "
                        "this run. Findings that depend on skipped metadata "
                        "may be absent or have lower confidence; use the full "
                        "profile for client-facing coverage."
                    ),
                },
            )
        action = "waited for" if access_status == "waited" else "reused"
        notes.append(
            {
                "note_type": "execution_detail",
                "scope_area": "s3_lifecycle_metadata",
                "summary": (
                    "S3 bucket metadata collection "
                    f"{action} same-scan cached metadata collected by another "
                    "S3 scanner; duplicate per-bucket metadata calls were skipped."
                ),
                "cache_namespace": "s3_lifecycle_inventory",
                "cache_access_status": access_status,
                "cache_action": action,
                "result_scope": "same_scan",
            },
        )
        return notes


def format_s3_bucket_metadata_label(metadata_type: str) -> str:  # noqa: D103
    labels = {
        "lifecycle": "S3 bucket lifecycle metadata",
        "replication": "S3 bucket replication metadata",
        "tags": "S3 bucket tag metadata",
        "versioning": "S3 bucket versioning metadata",
    }
    return labels.get(
        metadata_type,
        f"S3 bucket {metadata_type.replace('_', ' ')} metadata",
    )
