from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import (
    iter_response_rows,
    require_complete_response,
    require_response_bool,
    require_response_mapping,
    require_response_rows,
    require_response_string,
)
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.ec2.ebs.encryption_region import EbsEncryptionRegionRecord
from unio_collector.scanners.ec2.ebs.snapshot_encryption import (
    EbsSnapshotEncryptionRecord,
)
from unio_collector.scanners.ec2.ebs.volume_encryption import EbsVolumeEncryptionRecord
from unio_collector.scanners.s3.encryption.bucket_record import S3BucketEncryptionRecord
from unio_collector.scanners.security_governance.collection.regions import get_selected_or_available_regions
from unio_collector.scanners.security_governance.collection.warnings import append_warning
from unio_collector.scanners.security_governance.encryption.evidence import (
    EncryptionBaselineEvidence,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class EncryptionBaselineReviewCollector(BaseUnioScanner):
    """Collect provider evidence for encryption-baseline-review."""

    def collect(self, context: ScannerContext) -> EncryptionBaselineEvidence:  # noqa: D102
        regions = get_selected_or_available_regions(context, "ec2")
        warnings: list[str] = []
        ebs_settings: list[EbsEncryptionRegionRecord] = []
        volumes: list[EbsVolumeEncryptionRecord] = []
        snapshots: list[EbsSnapshotEncryptionRecord] = []
        for region in regions:
            client = context.security.create_client(
                "ec2",
                region_name=region,
                collector_name="EncryptionBaselineReviewScanner",
            )
            ebs_settings.append(
                self._get_ebs_encryption_setting(client, region, warnings),
            )
            volumes.extend(self._list_ebs_volumes(client, region, warnings))
            snapshots.extend(self._list_ebs_snapshots(client, region, warnings))
        s3_buckets = self._list_s3_bucket_encryption(context, warnings)
        for warning in warnings:
            context.warnings.add(warning)
        return EncryptionBaselineEvidence(
            ebs_region_settings=tuple(ebs_settings),
            ebs_volumes=tuple(volumes),
            ebs_snapshots=tuple(snapshots),
            s3_buckets=tuple(s3_buckets),
            regions=tuple(regions),
            warnings=tuple(warnings),
        )

    def _get_ebs_encryption_setting(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> EbsEncryptionRegionRecord:
        try:
            enabled_response = client.get_ebs_encryption_by_default()
            key_response = client.get_ebs_default_kms_key_id()
            enabled = require_response_bool(require_response_mapping(enabled_response).get("EbsEncryptionByDefault"))
            key_id = require_response_string(require_response_mapping(key_response).get("KmsKeyId"))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"EBS encryption default in {region}", exc)
            return EbsEncryptionRegionRecord(region=region, enabled_by_default=None)
        return EbsEncryptionRegionRecord(
            region=region,
            enabled_by_default=enabled,
            default_kms_key_id=key_id,
        )

    def _list_ebs_volumes(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[EbsVolumeEncryptionRecord]:
        records: list[EbsVolumeEncryptionRecord] = []
        try:
            pages = client.get_paginator("describe_volumes").paginate()
        except Exception:  # noqa: BLE001
            try:
                pages = [client.describe_volumes()]
            except Exception as exc:  # noqa: BLE001
                append_warning(warnings, f"EBS volumes in {region}", exc)
                return records
        try:
            for volume in iter_response_rows(pages, "Volumes"):
                records.append(  # noqa: PERF401
                    EbsVolumeEncryptionRecord(
                        volume_id=require_response_string(volume.get("VolumeId")),
                        region=region,
                        encrypted=require_response_bool(volume.get("Encrypted")),
                        kms_key_id=volume.get("KmsKeyId"),
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"EBS volumes in {region}", exc)
        return records

    def _list_ebs_snapshots(
        self,
        client: Any,  # noqa: ANN401
        region: str,
        warnings: list[str],
    ) -> list[EbsSnapshotEncryptionRecord]:
        records: list[EbsSnapshotEncryptionRecord] = []
        try:
            pages = client.get_paginator("describe_snapshots").paginate(
                OwnerIds=["self"],
            )
        except Exception:  # noqa: BLE001
            try:
                pages = [client.describe_snapshots(OwnerIds=["self"])]
            except Exception as exc:  # noqa: BLE001
                append_warning(warnings, f"EBS snapshots in {region}", exc)
                return records
        try:
            for snapshot in iter_response_rows(pages, "Snapshots"):
                records.append(  # noqa: PERF401
                    EbsSnapshotEncryptionRecord(
                        snapshot_id=require_response_string(snapshot.get("SnapshotId")),
                        region=region,
                        encrypted=require_response_bool(snapshot.get("Encrypted")),
                        kms_key_id=snapshot.get("KmsKeyId"),
                    ),
                )
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, f"EBS snapshots in {region}", exc)
        return records

    def _list_s3_bucket_encryption(
        self,
        context: ScannerContext,
        warnings: list[str],
    ) -> list[S3BucketEncryptionRecord]:
        client = context.security.create_client(
            "s3",
            region_name="us-east-1",
            collector_name="EncryptionBaselineReviewScanner",
        )
        bucket_names: list[str] = []
        try:
            response = client.list_buckets()
            bucket_names.extend(require_response_string(bucket.get("Name")) for bucket in require_response_rows(response, "Buckets"))
            require_complete_response(response, cursor_keys=("ContinuationToken",))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "S3 bucket list for encryption baseline", exc)
        return [self._get_s3_bucket_encryption(client, bucket_name, warnings) for bucket_name in bucket_names]

    def _get_s3_bucket_encryption(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
        warnings: list[str] | None = None,
    ) -> S3BucketEncryptionRecord:
        try:
            response = require_response_mapping(client.get_bucket_encryption(Bucket=bucket_name))
            rules = require_response_rows(response.get("ServerSideEncryptionConfiguration"), "Rules")
            algorithms = [
                require_response_string(require_response_mapping(rule.get("ApplyServerSideEncryptionByDefault")).get("SSEAlgorithm")) for rule in rules
            ]
        except Exception as exc:  # noqa: BLE001
            if aws_errors.get_aws_error_code(exc) == "ServerSideEncryptionConfigurationNotFoundError":
                return S3BucketEncryptionRecord(
                    bucket_name=bucket_name,
                    encryption_configured=False,
                )
            if warnings is not None:
                append_warning(warnings, f"S3 bucket encryption {bucket_name}", exc)
            return S3BucketEncryptionRecord(
                bucket_name=bucket_name,
                encryption_configured=None,
            )
        return S3BucketEncryptionRecord(
            bucket_name=bucket_name,
            encryption_configured=bool(algorithms),
            encryption_rules=tuple(algorithms),
        )

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="EncryptionBaselineReviewScanner",
            implementation_module="unio_collector.scanners.security_governance.encryption.scanner",
        )
