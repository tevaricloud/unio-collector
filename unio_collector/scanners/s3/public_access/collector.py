from __future__ import annotations  # noqa: D100

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import require_complete_response, require_response_mapping, require_response_rows, require_response_string
from unio_collector.scanners.base.cloud_cost_scanner import BaseUnioScanner
from unio_collector.scanners.s3.public_access.bucket_record import S3PublicAccessBucketRecord
from unio_collector.scanners.s3.public_access.evidence import S3PublicAccessEvidence
from unio_collector.scanners.s3.public_access.response import (
    PUBLIC_ACCESS_BLOCK_KEYS,
    normalize_public_access_block,
    observed_public_acl_grant,
)
from unio_collector.scanners.security_governance.collection.warnings import append_warning

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import ScannerContext


from unio_collector.scanners.scanner.implementation import ScannerImplementation


class S3PublicAccessSecurityReviewCollector(BaseUnioScanner):
    """Collect provider evidence for s3-public-access-security-review."""

    def collect(self, context: ScannerContext) -> S3PublicAccessEvidence:  # noqa: D102
        warnings: list[str] = []
        account_id = context.security.account_id
        s3_client = context.security.create_client(
            "s3",
            region_name="us-east-1",
            collector_name="S3PublicAccessSecurityReviewScanner",
        )
        (
            account_public_access_block,
            account_public_access_block_status,
            account_public_access_block_error_code,
        ) = self._get_account_public_access_block(
            context,
            account_id,
            warnings,
        )
        buckets = self._list_bucket_records(
            s3_client,
            warnings,
            max_bucket_workers=self._get_max_bucket_workers(context),
        )
        for warning in warnings:
            context.warnings.add(warning)
        return S3PublicAccessEvidence(
            account_public_access_block=account_public_access_block,
            account_public_access_block_status=account_public_access_block_status,
            account_public_access_block_error_code=account_public_access_block_error_code,
            buckets=tuple(buckets),
            warnings=tuple(warnings),
            account_id=account_id,
        )

    def _get_account_public_access_block(
        self,
        context: ScannerContext,
        account_id: str,
        warnings: list[str],
    ) -> tuple[dict[str, bool] | None, str, str | None]:
        client = context.security.create_client(
            "s3control",
            region_name="us-east-1",
            collector_name="S3PublicAccessSecurityReviewScanner",
        )
        try:
            response = require_response_mapping(client.get_public_access_block(AccountId=account_id))
        except Exception as exc:  # noqa: BLE001
            code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
            if code == "NoSuchPublicAccessBlockConfiguration":
                return None, "not_configured", code
            append_warning(warnings, "S3 account public access block", exc)
            return None, "unavailable", code
        config = normalize_public_access_block(response.get("PublicAccessBlockConfiguration"))
        if config is None:
            append_warning(warnings, "S3 account public access block", ValueError())
            return None, "unavailable", "ValueError"
        return config, "configured", None

    def _list_bucket_records(
        self,
        client: Any,  # noqa: ANN401
        warnings: list[str],
        *,
        max_bucket_workers: int,
    ) -> list[S3PublicAccessBucketRecord]:
        bucket_names: list[str] = []
        try:
            response = client.list_buckets()
            bucket_names.extend(require_response_string(bucket.get("Name")) for bucket in require_response_rows(response, "Buckets"))
            require_complete_response(response, cursor_keys=("ContinuationToken",))
        except Exception as exc:  # noqa: BLE001
            append_warning(warnings, "S3 bucket list", exc)
        if not bucket_names:
            return []
        worker_count = min(max(1, max_bucket_workers), len(bucket_names))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(self._build_bucket_public_access_record, client, name) for name in bucket_names]
            records: list[S3PublicAccessBucketRecord] = []
            for bucket_name, future in zip(bucket_names, futures, strict=True):
                try:
                    record = future.result()
                    records.append(record)
                    for label, value in (
                        ("public access block", record.public_access_block),
                        ("policy status", record.policy_is_public),
                        ("ACL", record.acl_is_public),
                    ):
                        if value is None:
                            warnings.append(f"S3 {label} evidence was unavailable for bucket {bucket_name}.")
                except Exception as exc:  # noqa: BLE001
                    append_warning(
                        warnings,
                        f"S3 public access metadata for bucket {bucket_name}",
                        exc,
                    )
            return records

    def _build_bucket_public_access_record(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
    ) -> S3PublicAccessBucketRecord:
        return S3PublicAccessBucketRecord(
            bucket_name=bucket_name,
            public_access_block=self._get_bucket_public_access_block(
                client,
                bucket_name,
            ),
            policy_is_public=self._get_bucket_policy_status(
                client,
                bucket_name,
            ),
            acl_is_public=self._get_bucket_acl_public_state(
                client,
                bucket_name,
            ),
        )

    def _get_max_bucket_workers(self, context: ScannerContext) -> int:
        default_workers = self._get_default_bucket_workers(context)
        raw_value = context.options.get("max_bucket_workers", default_workers)
        try:
            return max(1, int(str(raw_value)))
        except (TypeError, ValueError):
            return default_workers

    def _get_default_bucket_workers(self, context: ScannerContext) -> int:
        runtime_config = getattr(context.security.session, "runtime_config", None)
        configured = getattr(runtime_config, "max_workers", 8)
        try:
            return max(1, min(16, int(configured)))
        except (TypeError, ValueError):
            return 8

    def _get_bucket_public_access_block(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
    ) -> dict[str, bool] | None:
        try:
            response = require_response_mapping(client.get_public_access_block(Bucket=bucket_name))
        except Exception as exc:  # noqa: BLE001
            if aws_errors.get_aws_error_code(exc) == "NoSuchPublicAccessBlockConfiguration":
                return dict.fromkeys(PUBLIC_ACCESS_BLOCK_KEYS, False)
            return None
        config = response.get("PublicAccessBlockConfiguration")
        return normalize_public_access_block(config)

    def _get_bucket_policy_status(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
    ) -> bool | None:
        try:
            response = require_response_mapping(client.get_bucket_policy_status(Bucket=bucket_name))
        except Exception as exc:  # noqa: BLE001
            if aws_errors.get_aws_error_code(exc) == "NoSuchBucketPolicy":
                return False
            return None
        status = response.get("PolicyStatus", {})
        if not isinstance(status, dict):
            return None
        value = status.get("IsPublic")
        return value if isinstance(value, bool) else None

    def _get_bucket_acl_public_state(
        self,
        client: Any,  # noqa: ANN401
        bucket_name: str,
    ) -> bool | None:
        try:
            response = client.get_bucket_acl(Bucket=bucket_name)
            grants = require_response_rows(response, "Grants")
        except Exception:  # noqa: BLE001
            return None
        states = [observed_public_acl_grant(grant) for grant in grants]
        if any(state is True for state in states):
            return True
        return None if any(state is None for state in states) else False

    def describe_implementation(self) -> ScannerImplementation:
        """Preserve the application identity in collection metadata."""
        return ScannerImplementation(
            implementation_type="native",
            implementation_class="S3PublicAccessSecurityReviewScanner",
            implementation_module="unio_collector.scanners.s3.public_access.scanner",
        )
