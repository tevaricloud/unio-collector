"""Actual S3 wrappers and SDK producers driven solely by synthetic responses."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics
from unio_collector.aws.s3.collector import S3InventoryCollector
from unio_collector.scanners.s3.incomplete_multipart.collector import S3IncompleteMultipartReviewCollector
from unio_collector.scanners.s3.lifecycle.collector import S3LifecycleCostReviewCollector
from unio_collector.scanners.s3.public_access.collector import S3PublicAccessSecurityReviewCollector
from unio_collector.scanners.s3.versioning_replication.collector import S3VersioningAndReplicationReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

COLLECTORS = {
    "s3-public-access-security-review": S3PublicAccessSecurityReviewCollector,
    "s3-lifecycle-cost-review": S3LifecycleCostReviewCollector,
    "s3-versioning-and-replication-review": S3VersioningAndReplicationReviewCollector,
    "s3-incomplete-multipart-review": S3IncompleteMultipartReviewCollector,
}
VARIANTS = (
    "success",
    "nullable",
    "empty",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "absent",
    "skipped",
    "capped",
    "collision",
    "metrics",
    "conditional",
)
ACCOUNT = "123456789012"
BUCKET = "synthetic-customer-bucket"
BLOCK = dict.fromkeys(("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"), True)


class SyntheticS3Session:
    """Reject unknown operations; never create a real SDK client."""

    def __init__(self, variant: str) -> None:
        """Select one deterministic provider response branch."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: object) -> SyntheticS3Session:
        """Only admit the three actual S3 producer endpoints."""
        del audit_context
        if service_name not in {"s3", "s3control", "cloudwatch"} or region_name not in {"eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic S3 endpoint."
            raise ValueError(message)
        return self

    def __getattr__(self, operation: str) -> Any:  # noqa: ANN401
        """Return explicit response data or bounded synthetic provider errors."""
        responses = self._responses()
        if operation not in responses:
            raise AttributeError(operation)

        def call(**_kwargs: object) -> dict[str, Any]:
            codes = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}
            code = codes.get(self.variant) if operation != "list_buckets" else None
            if self.variant == "partial" and operation in {"get_bucket_replication", "get_bucket_policy_status"}:
                code = "AccessDenied"
            if self.variant == "absent":
                code = {
                    "get_public_access_block": "NoSuchPublicAccessBlockConfiguration",
                    "get_bucket_lifecycle_configuration": "NoSuchLifecycleConfiguration",
                    "get_bucket_tagging": "NoSuchTagSet",
                    "get_bucket_replication": "ReplicationConfigurationNotFoundError",
                    "get_bucket_policy_status": "NoSuchBucketPolicy",
                }.get(operation)
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "Synthetic unavailable operation"}}, operation)
            if operation == "get_metric_data":
                queries = _kwargs.get("MetricDataQueries")
                if not isinstance(queries, list):
                    message = "Synthetic metric request must contain its query list."
                    raise ValueError(message)
                return {"MetricDataResults": [{"Id": query["Id"], "Values": [42], "Timestamps": [datetime(2026, 9, 1, tzinfo=UTC)]} for query in queries]}
            return responses[operation]

        return call

    def can_paginate(self, operation: str) -> bool:
        """Use the ordinary actual producer fallback page path."""
        del operation
        return False

    def _responses(self) -> dict[str, Any]:
        rule = {
            "ID": "Enabled" if self.variant == "collision" else "synthetic-customer-rule",
            "Status": "Enabled",
            "Filter": {"Prefix": "synthetic-customer/"},
            "Expiration": {"Days": 30},
            "Transitions": [{"Days": 20, "StorageClass": "GLACIER"}],
            "NoncurrentVersionExpiration": {"NoncurrentDays": 60},
            "NoncurrentVersionTransitions": [{"NoncurrentDays": 30, "StorageClass": "GLACIER"}],
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        }
        replication = {
            "ID": "synthetic-customer-replication",
            "Status": "Enabled",
            "Priority": 3,
            "Filter": {"Prefix": "synthetic-customer/"},
            "Destination": {
                "Bucket": "arn:aws:s3:::synthetic-customer-destination",
                "StorageClass": "STANDARD",
                "ReplicationTime": {"Status": "Enabled", "Time": {"Minutes": 15}},
                "Metrics": {"Status": "Enabled", "EventThreshold": {"Minutes": 15}},
            },
            "DeleteMarkerReplication": {"Status": "Enabled"},
        }
        nullable = self.variant == "nullable"
        return {
            "list_buckets": {
                "Buckets": [] if self.variant == "empty" else [{"Name": BUCKET, "BucketRegion": "eu-west-2", "CreationDate": datetime(2026, 9, 1, tzinfo=UTC)}]
            },
            "get_bucket_location": {"LocationConstraint": "eu-west-2"},
            "get_public_access_block": {**({} if nullable else {"PublicAccessBlockConfiguration": BLOCK})},
            "get_bucket_policy_status": {"PolicyStatus": {} if nullable else {"IsPublic": True}},
            "get_bucket_acl": {"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]},
            "get_bucket_tagging": {"TagSet": [{"Key": "synthetic-customer-key", "Value": "synthetic-customer-value"}]},
            "get_bucket_lifecycle_configuration": {
                "Rules": [{"Status": "Disabled"}] if nullable else [rule, {"ID": "synthetic-disabled", "Status": "Disabled"}]
            },
            "get_bucket_versioning": {} if nullable else {"Status": "Enabled"},
            "get_bucket_replication": {"ReplicationConfiguration": {"Rules": [{}] if nullable else [replication]}},
            "list_multipart_uploads": {
                "Uploads": [{"Key": "synthetic-customer/object.txt", **({} if nullable else {"Initiated": datetime(2026, 9, 1, tzinfo=UTC)})}],
                "IsTruncated": self.variant == "capped",
            },
            "get_metric_data": {"MetricDataResults": []},
        }


def s3_producer_case(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Execute the real wrapper, gateways, S3 collector and evidence serializer."""
    if scanner not in COLLECTORS or variant not in VARIANTS:
        message = "Unknown synthetic S3 producer case."
        raise ValueError(message)
    session = SyntheticS3Session(variant)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    warnings: list[str] = []
    notes: list[dict[str, object]] = []
    options: dict[str, object] = {"skip_buckets_with_abort_incomplete_rule": False, "collect_priority_metrics": False}
    if variant == "metrics":
        options.update(lifecycle_detail_mode="prioritized", prioritized_lifecycle_bucket_count=1)
    if variant == "conditional":
        options.update(conditional_versioning_collection=True)
    if variant == "skipped":
        options.update(collect_tags=False, collect_versioning=False, collect_replication=False)
    state = SimpleNamespace(
        account_id=ACCOUNT,
        session=session,
        config=SimpleNamespace(runtime=session.runtime_config),
        get_selected_regions=lambda: ["eu-west-2"],
        get_scanner_option=lambda _scanner, key, default: options.get(key, default),
    )
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())

    def lifecycle(_definition: object, **kwargs: Any) -> Any:  # noqa: ANN401
        collector = S3InventoryCollector(session, account_id=ACCOUNT, audit_context=audit, selected_regions=["eu-west-2"], max_bucket_workers=1)
        kwargs.pop("max_bucket_workers")
        return collector.collect_lifecycle_records(**kwargs)

    def multipart(_definition: object, **kwargs: Any) -> Any:  # noqa: ANN401
        kwargs.pop("max_bucket_workers")
        lifecycle_options = kwargs.pop("lifecycle_collection_options")
        cap = kwargs.pop("max_multipart_uploads_per_bucket")
        collector = S3InventoryCollector(
            session, account_id=ACCOUNT, audit_context=audit, selected_regions=["eu-west-2"], max_bucket_workers=1, max_multipart_uploads_per_bucket=cap
        )
        index = collector.collect_bucket_index()
        lifecycle_result = collector.collect_lifecycle_records(bucket_index=index, collection_options=lifecycle_options)
        return collector.collect_multipart_records(bucket_index=index, lifecycle_records=lifecycle_result.lifecycle_records, **kwargs)

    runtime: Any = SimpleNamespace(
        runtime_state=state,
        create_audit_context=lambda *_args: audit,
        add_scanner_warning=lambda _scanner, message: warnings.append(message),
        add_scanner_coverage_note=lambda _scanner, note: notes.append(note),
        collect_cached_s3_lifecycle_records=lifecycle,
        collect_cached_s3_multipart_records=multipart,
        collect_cached_service_costs=lambda _definition: SimpleNamespace(
            service_costs=[{"service_name": "Amazon Simple Storage Service", "current_cost": "123.45", "previous_cost": "67.89", "currency": "USD"}]
        ),
        collect_cached_daily_costs=lambda _definition, **_kwargs: [],
    )
    evidence = COLLECTORS[scanner](definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)


def add_s3_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Expand packaged smoke with real successful, nullable and failed S3 records."""
    from tools.collector_scanner_fixture import add_scanner_producer_payload  # noqa: PLC0415

    for scanner in COLLECTORS:
        row = s3_producer_case(scanner)
        key = "buckets" if scanner == "s3-public-access-security-review" else "records"
        for variant in VARIANTS:
            if variant == "success":
                continue
            extra = s3_producer_case(scanner, variant)["payload"]
            row["payload"][key].extend(extra[key])
            row["payload"]["warnings"].extend(extra["warnings"])
            if "bucket_contexts" in extra:
                row["payload"]["bucket_contexts"].extend(extra["bucket_contexts"])
        if unknown:
            row["payload"][key][0]["unknown_s3_field"] = {}
        add_scanner_producer_payload(files, row)
