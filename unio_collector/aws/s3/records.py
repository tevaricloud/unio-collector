# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.s3.helpers import (
    EXPECTED_S3_ABSENCE_CODES,
    collect_replication_destinations,
    count_rule_status,
    find_oldest_upload_initiated,
    has_enabled_replication,
    summarize_lifecycle_rules,
    summarize_replication_rules,
    tags_to_dict,
)
from unio_collector.aws.s3.identity import S3BucketIdentity
from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord
from unio_collector.aws.s3.metadata import S3BucketMetadataResult
from unio_collector.aws.s3.multipart.upload import S3MultipartUploadRecord

if TYPE_CHECKING:
    from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions
    from unio_collector.aws.s3.storage_metric import S3BucketStorageMetric

S3BucketMetadataCacheLoader = Callable[
    [S3BucketIdentity, str, Callable[[], S3BucketMetadataResult]],
    S3BucketMetadataResult,
]


class S3RecordCollectionMixin:  # noqa: D101
    def _build_lifecycle_record_from_metadata(  # noqa: C901
        self,
        bucket: S3BucketIdentity,
        *,
        collection_options: S3LifecycleCollectionOptions,
        metadata_by_type: dict[str, S3BucketMetadataResult],
        storage_metric: S3BucketStorageMetric | None = None,
    ) -> S3BucketLifecycleRecord:
        limitations: list[str] = []
        tags: dict[str, str] = {}
        tag_metadata: S3BucketMetadataResult | None = None
        if collection_options.collect_tags:
            tag_metadata = metadata_by_type.get("tags")
            if tag_metadata is not None:
                tags = dict(tag_metadata.tags)
                if tag_metadata.limitation:
                    limitations.append(tag_metadata.limitation)
            else:
                limitations.append("Bucket tag metadata was not collected.")
        else:
            limitations.append("Bucket tag collection was skipped by configuration.")

        lifecycle_metadata = metadata_by_type.get("lifecycle")
        lifecycle_collected = lifecycle_metadata is not None and lifecycle_metadata.collected
        lifecycle = dict(lifecycle_metadata.payload) if lifecycle_metadata is not None else {}
        if lifecycle_metadata and lifecycle_metadata.limitation:
            limitations.append(lifecycle_metadata.limitation)
        elif lifecycle_metadata is None:
            limitations.append("Bucket lifecycle metadata was not collected.")

        versioning: dict[str, Any] = {}
        versioning_metadata: S3BucketMetadataResult | None = None
        if collection_options.collect_versioning:
            versioning_metadata = metadata_by_type.get("versioning")
            if versioning_metadata is not None:
                versioning = dict(versioning_metadata.payload)
                if versioning_metadata.limitation:
                    limitations.append(versioning_metadata.limitation)
            else:
                limitations.append("Bucket versioning metadata was not collected.")
        else:
            limitations.append(
                "Bucket versioning collection was skipped by configuration.",
            )
        replication: dict[str, Any] = {}
        replication_metadata: S3BucketMetadataResult | None = None
        if collection_options.collect_replication:
            replication_metadata = metadata_by_type.get("replication")
            if replication_metadata is not None:
                replication = dict(replication_metadata.payload)
                if replication_metadata.limitation:
                    limitations.append(replication_metadata.limitation)
            else:
                limitations.append("Bucket replication metadata was not collected.")
        else:
            limitations.append(
                "Bucket replication collection was skipped by configuration.",
            )
        if storage_metric is not None and storage_metric.limitation:
            limitations.append(storage_metric.limitation)

        rules = lifecycle.get("Rules", []) if isinstance(lifecycle, dict) else []
        rule_summaries = summarize_lifecycle_rules(rules)
        replication_rules = replication.get("ReplicationConfiguration", {}).get("Rules", []) if isinstance(replication, dict) else []
        replication_rule_summaries = summarize_replication_rules(replication_rules)
        return S3BucketLifecycleRecord(
            bucket_name=bucket.bucket_name,
            account_id=self.account_id,
            region=bucket.region,
            arn=bucket.arn,
            creation_date=bucket.creation_date,
            collection_profile=collection_options.collection_profile,
            skipped_metadata=collection_options.get_skipped_metadata(),
            tags=tags,
            bucket_tags_collected=(collection_options.collect_tags and tag_metadata is not None and tag_metadata.collected),
            bucket_lifecycle_collected=lifecycle_collected,
            bucket_lifecycle_skip_reason=(lifecycle_metadata.limitation if (lifecycle_metadata is not None and not lifecycle_metadata.collected) else None),
            lifecycle_priority_metric_collected=(storage_metric.metric_collected if storage_metric is not None else False),
            bucket_size_bytes=(storage_metric.size_bytes if storage_metric is not None else None),
            bucket_object_count=(storage_metric.object_count if storage_metric is not None else None),
            has_lifecycle_policy=bool(rules),
            lifecycle_rule_count=len(rules) if isinstance(rules, list) else 0,
            lifecycle_rule_summaries=rule_summaries,
            bucket_versioning_collected=(collection_options.collect_versioning and versioning_metadata is not None and versioning_metadata.collected),
            bucket_versioning_skip_reason=(versioning_metadata.limitation if (versioning_metadata is not None and not versioning_metadata.collected) else None),
            versioning_status=(str(versioning.get("Status")) if isinstance(versioning, dict) and versioning.get("Status") else None),
            has_noncurrent_version_expiration=any(bool(summary.get("has_noncurrent_version_expiration")) for summary in rule_summaries),
            has_noncurrent_version_transition=any(bool(summary.get("has_noncurrent_version_transition")) for summary in rule_summaries),
            has_current_version_expiration=any(bool(summary.get("has_current_version_expiration")) for summary in rule_summaries),
            has_current_version_transition=any(bool(summary.get("has_current_version_transition")) for summary in rule_summaries),
            has_abort_incomplete_multipart_upload=any(bool(summary.get("has_abort_incomplete_multipart_upload")) for summary in rule_summaries),
            enabled_lifecycle_rule_count=count_rule_status(rule_summaries, "Enabled"),
            disabled_lifecycle_rule_count=count_rule_status(rule_summaries, "Disabled"),
            bucket_replication_collected=(collection_options.collect_replication and replication_metadata is not None and replication_metadata.collected),
            replication_enabled=has_enabled_replication(replication_rules),
            replication_rule_count=(len(replication_rules) if isinstance(replication_rules, list) else 0),
            enabled_replication_rule_count=count_rule_status(
                replication_rule_summaries,
                "Enabled",
            ),
            replication_destinations=collect_replication_destinations(
                replication_rules,
            ),
            replication_rule_summaries=replication_rule_summaries,
            limitations=limitations,
        )

    def _collect_multipart_record(
        self,
        bucket: S3BucketIdentity,
    ) -> S3MultipartUploadRecord:
        client = self._create_s3_client(bucket.region)
        limitations: list[str] = []
        uploads: list[dict[str, Any]] = []
        page_count = 0
        pagination_complete = True
        try:
            result = self._pagination.collect_pages(
                client,
                "list_multipart_uploads",
                result_key="Uploads",
                request_parameters={
                    "Bucket": bucket.bucket_name,
                    "PaginationConfig": {
                        "MaxItems": self.max_multipart_uploads_per_bucket,
                    },
                },
            )
            page_count = result.page_count
            pagination_complete = not any(
                bool(page.get("IsTruncated")) or bool(page.get("NextToken")) or bool(page.get("NextKeyMarker")) or bool(page.get("NextUploadIdMarker"))
                for page in result.pages
            )
            for page in result.pages:
                page_uploads = page.get("Uploads", [])
                if isinstance(page_uploads, list):
                    uploads.extend(page_uploads)
        except ClientError as exc:
            pagination_complete = False
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            if code not in EXPECTED_S3_ABSENCE_CODES:
                limitations.append(
                    f"Could not list incomplete multipart uploads: {code}.",
                )
        oldest = find_oldest_upload_initiated(uploads)
        return S3MultipartUploadRecord(
            bucket_name=bucket.bucket_name,
            account_id=self.account_id,
            region=bucket.region,
            arn=bucket.arn,
            upload_count=len(uploads),
            oldest_initiated=oldest,
            sample_keys=[str(upload.get("Key")) for upload in uploads[:5] if upload.get("Key")],
            page_count=page_count,
            pagination_complete=pagination_complete,
            limitations=limitations,
        )

    def _get_bucket_tags(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
    ) -> tuple[dict[str, str], str | None]:
        try:
            response = client.get_bucket_tagging(Bucket=bucket_name)
        except ClientError as exc:
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            if code == "NoSuchTagSet":
                return {}, None
            return {}, f"Could not collect bucket tags: {code}."
        tag_set = response.get("TagSet", [])
        if not isinstance(tag_set, list):
            return {}, None
        return tags_to_dict(tag_set), None

    def _get_optional_response(
        self,
        client: Any,  # noqa: ANN401
        method_name: str,
        bucket_name: str,
        *,
        absent_codes: set[str],
    ) -> tuple[dict[str, Any], str | None]:
        try:
            method = getattr(client, method_name)
            response = method(Bucket=bucket_name)
        except ClientError as exc:
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            if code in absent_codes:
                return {}, None
            return {}, f"Could not collect {method_name}: {code}."
        return response if isinstance(response, dict) else {}, None

    def _create_s3_client(self, region: str) -> Any:  # noqa: ANN401
        with self._client_cache_lock:
            client = self._client_cache.get(region)
            if client is None:
                client = self.session.create_client(
                    "s3",
                    region_name=region,
                    audit_context=self.audit_context,
                )
                self._client_cache[region] = client
            return client

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self.session, "runtime_config", None)
        value = getattr(runtime_config, "max_workers", None)
        return value if isinstance(value, int) and value > 0 else 1
