# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    record_collection_results,
)
from unio_collector.aws.s3.helpers import (
    normalize_s3_location,
)
from unio_collector.aws.s3.identity import S3BucketIdentity
from unio_collector.aws.s3.metadata import S3BucketMetadataResult
from unio_collector.aws.s3.regional_metadata import (
    S3RegionalBucketMetadataResult,
)

if TYPE_CHECKING:
    from unio_collector.aws.s3.bucket.index import S3BucketIndexResult
    from unio_collector.aws.s3.lifecycle.options import S3LifecycleCollectionOptions
    from unio_collector.aws.s3.lifecycle.record import S3BucketLifecycleRecord
    from unio_collector.aws.s3.multipart.upload import S3MultipartUploadRecord

S3BucketMetadataCacheLoader = Callable[
    [S3BucketIdentity, str, Callable[[], S3BucketMetadataResult]],
    S3BucketMetadataResult,
]


class S3BucketCollectionMixin:  # noqa: D101
    def _collect_multipart_records(
        self,
        buckets: list[S3BucketIdentity],
    ) -> list[S3MultipartUploadRecord]:
        tasks = [
            AwsCollectionTask(
                name=f"S3InventoryCollector:multipart:{bucket.bucket_name}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region=bucket.region,
                service="s3",
                operation="ListMultipartUploads",
                payload={"bucket_name": bucket.bucket_name},
                collect=lambda bucket=bucket: self._collect_multipart_record(bucket),
            )
            for bucket in buckets
        ]
        results = AwsCollectionExecutor(max_workers=self.max_bucket_workers).run(tasks)
        record_collection_results(self.session, results)
        return [result.value for result in results if result.status == "completed" and result.value is not None]

    def _limit_bucket_index(
        self,
        bucket_index: S3BucketIndexResult,
        *,
        max_buckets: int,
        collection_options: S3LifecycleCollectionOptions,
    ) -> tuple[list[S3BucketIdentity], list[dict[str, Any]]]:
        buckets = list(bucket_index.buckets)
        if max_buckets <= 0 or len(buckets) <= max_buckets:
            return buckets, self._coverage_notes.build_lifecycle_configuration_notes(
                collection_options,
            )
        limited_buckets = buckets[:max_buckets]
        return limited_buckets, [
            self._coverage_notes.build_bucket_cap_note(
                max_buckets=max_buckets,
                selected_bucket_count=len(buckets),
                evaluated_bucket_count=len(limited_buckets),
            ),
            *self._coverage_notes.build_lifecycle_configuration_notes(collection_options),
        ]

    def _build_execution_notes(
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
        return self._coverage_notes.build_execution_notes(
            include_lifecycle=include_lifecycle,
            include_multipart=include_multipart,
            lifecycle_bucket_count=lifecycle_bucket_count,
            lifecycle_region_count=lifecycle_region_count,
            multipart_bucket_count=multipart_bucket_count,
            collection_options=collection_options,
            conditional_versioning_skipped_count=(conditional_versioning_skipped_count),
            prioritized_lifecycle_skipped_count=(prioritized_lifecycle_skipped_count),
            lifecycle_metric_unknown_count=lifecycle_metric_unknown_count,
        )

    def _limit_multipart_buckets(
        self,
        buckets: list[S3BucketIdentity],
        *,
        max_multipart_buckets: int,
        lifecycle_records: list[S3BucketLifecycleRecord] | None,
        multipart_bucket_selection_mode: object,
    ) -> tuple[list[S3BucketIdentity], list[dict[str, Any]]]:
        return self._multipart_bucket_selector.limit_buckets(
            buckets,
            max_multipart_buckets=max_multipart_buckets,
            lifecycle_records=lifecycle_records,
            multipart_bucket_selection_mode=multipart_bucket_selection_mode,
        )

    def _list_buckets(self) -> list[dict[str, Any]]:
        return self._list_buckets_for_region(None)

    def _list_buckets_for_region(
        self,
        bucket_region: str | None,
    ) -> list[dict[str, Any]]:
        client = self._create_s3_client(bucket_region or "us-east-1")
        request: dict[str, Any] = {}
        if bucket_region:
            request["BucketRegion"] = bucket_region
        response = client.list_buckets(**request)
        buckets = response.get("Buckets", [])
        return buckets if isinstance(buckets, list) else []

    def _collect_selected_region_bucket_identities(
        self,
        unresolved_buckets: list[dict[str, Any]],
    ) -> S3RegionalBucketMetadataResult:
        if not unresolved_buckets or not self.selected_regions:
            return S3RegionalBucketMetadataResult()
        selected_regions = self._get_selected_bucket_regions()
        if not selected_regions:
            return S3RegionalBucketMetadataResult()
        unresolved_names = {str(bucket.get("Name") or "") for bucket in unresolved_buckets if bucket.get("Name")}
        if len(selected_regions) >= len(unresolved_names):
            return S3RegionalBucketMetadataResult()
        tasks = [
            AwsCollectionTask(
                name=f"S3InventoryCollector:regional-bucket-index:{region}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region=region,
                service="s3",
                operation="ListBuckets",
                payload={"bucket_region": region},
                collect=lambda region=region: self._collect_bucket_identities_for_region(
                    region,
                    unresolved_names=unresolved_names,
                ),
            )
            for region in selected_regions
        ]
        task_results = AwsCollectionExecutor(
            max_workers=min(self.max_bucket_workers, len(tasks)),
        ).run(tasks)
        record_collection_results(self.session, task_results)
        identities = [identity for result in task_results if result.status == "completed" and result.value for identity in result.value]
        return S3RegionalBucketMetadataResult(
            identities=identities,
            regional_lookup_complete=all(result.status == "completed" for result in task_results),
        )

    def _collect_bucket_identities_for_region(
        self,
        region: str,
        *,
        unresolved_names: set[str],
    ) -> list[S3BucketIdentity]:
        identities: list[S3BucketIdentity] = []
        for bucket in self._list_buckets_for_region(region):
            bucket_name = str(bucket.get("Name") or "")
            if bucket_name not in unresolved_names:
                continue
            enriched_bucket = dict(bucket)
            enriched_bucket.setdefault("BucketRegion", region)
            identity = self._build_bucket_identity_from_list_metadata(enriched_bucket)
            if identity is not None:
                identities.append(identity)
        return identities

    def _get_selected_bucket_regions(self) -> list[str]:
        return sorted(region for region in self.selected_regions if region not in {"global", "aws-global"})

    def _get_location_fallback_buckets(
        self,
        unresolved_buckets: list[dict[str, Any]],
        *,
        identities_by_name: dict[str, S3BucketIdentity],
        regional_lookup_complete: bool,
    ) -> list[dict[str, Any]]:
        if regional_lookup_complete:
            return []
        return [bucket for bucket in unresolved_buckets if str(bucket.get("Name") or "") not in identities_by_name]

    def _build_bucket_identity_tasks(
        self,
        buckets: list[dict[str, Any]],
    ) -> list[AwsCollectionTask[S3BucketIdentity]]:
        return [
            AwsCollectionTask(
                name=f"S3InventoryCollector:location:{bucket_name}",
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region="aws-global",
                service="s3",
                operation="GetBucketLocation",
                payload={"bucket_name": bucket_name},
                collect=lambda bucket=bucket: self._build_bucket_identity(bucket),
            )
            for bucket in buckets
            if (bucket_name := str(bucket.get("Name") or ""))
        ]

    def _build_bucket_identities_from_list_metadata(
        self,
        buckets: list[dict[str, Any]],
    ) -> tuple[list[S3BucketIdentity], list[dict[str, Any]]]:
        identities: list[S3BucketIdentity] = []
        unresolved: list[dict[str, Any]] = []
        for bucket in buckets:
            identity = self._build_bucket_identity_from_list_metadata(bucket)
            if identity is None:
                unresolved.append(bucket)
            else:
                identities.append(identity)
        return identities, unresolved

    def _build_bucket_identity_from_list_metadata(
        self,
        bucket: dict[str, Any],
    ) -> S3BucketIdentity | None:
        bucket_name = str(bucket.get("Name") or "")
        bucket_region = bucket.get("BucketRegion")
        if not bucket_name or not bucket_region:
            return None
        arn = str(bucket.get("BucketArn") or f"arn:aws:s3:::{bucket_name}")
        return S3BucketIdentity(
            bucket_name=bucket_name,
            account_id=self.account_id,
            region=normalize_s3_location(bucket_region),
            arn=arn,
            creation_date=bucket.get("CreationDate"),
        )

    def _build_bucket_identity(self, bucket: dict[str, Any]) -> S3BucketIdentity:
        bucket_name = str(bucket.get("Name") or "")
        region, location_warning = self._get_bucket_region(bucket_name)
        return S3BucketIdentity(
            bucket_name=bucket_name,
            account_id=self.account_id,
            region=region,
            arn=f"arn:aws:s3:::{bucket_name}",
            creation_date=bucket.get("CreationDate"),
            warning=location_warning,
        )

    def _get_bucket_region(self, bucket_name: str) -> tuple[str, str | None]:
        client = self._create_s3_client("us-east-1")
        try:
            response = client.get_bucket_location(Bucket=bucket_name)
        except ClientError as exc:
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            return "us-east-1", (f"Could not determine S3 bucket region for {bucket_name}: {code}.")
        return normalize_s3_location(response.get("LocationConstraint")), None

    def _collect_tag_metadata(
        self,
        bucket: S3BucketIdentity,
    ) -> S3BucketMetadataResult:
        client = self._create_s3_client(bucket.region)
        tags, limitation = self._get_bucket_tags(client, bucket.bucket_name)
        return S3BucketMetadataResult(
            bucket_name=bucket.bucket_name,
            metadata_type="tags",
            tags=tags,
            collected=limitation is None,
            limitation=limitation,
        )

    def _collect_optional_metadata(
        self,
        bucket: S3BucketIdentity,
        *,
        metadata_type: str,
        method_name: str,
        absent_codes: set[str],
    ) -> S3BucketMetadataResult:
        client = self._create_s3_client(bucket.region)
        payload, limitation = self._get_optional_response(
            client,
            method_name,
            bucket.bucket_name,
            absent_codes=absent_codes,
        )
        return S3BucketMetadataResult(
            bucket_name=bucket.bucket_name,
            metadata_type=metadata_type,
            payload=payload,
            collected=limitation is None,
            limitation=limitation,
        )
