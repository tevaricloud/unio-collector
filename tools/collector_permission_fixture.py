"""Complete permission provenance from actual offline collector producers."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector.bundle.encoding import dump_json
from unio_collector.collector.bundle.payload_writer import EvidencePayloadWriter
from unio_collector.collector.bundle.source import EvidenceBundleSource
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.scanner.result import ScannerExecutionResult, ScannerStatus

LEDGER_CASES = (
    ("success", "ec2", "DescribeInstances", None, "none"),
    ("denied", "kms", "DescribeKey", "AccessDeniedException", "permission_denied"),
    ("absence", "s3", "GetBucketLifecycleConfiguration", "NoSuchLifecycleConfiguration", "expected_absence"),
    ("unavailable", "macie2", "GetMacieSession", "AccessDeniedException", "service_unavailable"),
    ("unsupported", "ec2", "DescribeInstances", "UnsupportedOperation", "unsupported_region"),
    ("unsupported_operation", "bedrock", "ListCustomModels", "UnknownOperationException", "unsupported_operation"),
    ("throttled", "ec2", "DescribeInstances", "ThrottlingException", "throttling"),
    ("failure", "ec2", "DescribeInstances", "InternalFailure", "failure"),
)
SCANNER_STATUSES: tuple[ScannerStatus, ...] = (
    "completed",
    "completed_with_warnings",
    "skipped",
    "disabled",
    "failed",
    "permission_denied",
    "unavailable",
)


def permission_producer_payloads(provenance: dict[str, Any]) -> dict[str, bytes]:
    """Serialize complete payload-writer output without an AWS session or client."""
    ledger = ApiCallLedger()
    ledger.set_identity({"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/synthetic", "UserId": "synthetic-user", "type": "AssumedRole"})
    for _, service, operation, code, _ in LEDGER_CASES:
        ledger.record(
            context=AwsAuditContext("root_advisory", "synthetic", (f"{service}:{operation}",)),
            service_name=service,
            operation_name=operation,
            region_name="us-east-1",
            request_parameters={},
            error=ClientError(
                {"Error": {"Code": code, "Message": "synthetic service is not enabled" if service == "macie2" else "synthetic provider diagnostic"}}, operation
            )
            if code
            else None,
            response={"ResponseMetadata": {"RequestId": "synthetic-request"}} if code is None else None,
        )

    for index, record in enumerate(ledger.records):
        record["eventTime"] = "2026-08-31T00:00:00+00:00"
        record["eventID"] = f"synthetic-permission-event-{index}"
    results = [
        ScannerExecutionResult(
            scanner_id="root_advisory",
            status=status,
            aws_api_calls=["ec2:DescribeInstances"],
            regions_scanned=["us-east-1"],
            errors=["synthetic failure for 123456789012"] if status == "failed" else [],
        )
        for status in SCANNER_STATUSES
    ]
    bundle = EvidenceBundleSource(
        datetime(2026, 8, 31, tzinfo=UTC),
        {"account_id": "123456789012"},
        ScanPeriodResolver().resolve(date_from="2026-08-01", date_to="2026-08-31"),
        {"run_id": "synthetic-run", "region_scope": {"limitations": ["Synthetic scope limitation for 123456789012"]}},
        {},
        0,
        [],
    )
    scan = SimpleNamespace(
        scanner_results=results,
        ledger=ledger,
        evidence_store=SimpleNamespace(get_records=list),
        provider_id="aws",
        scanner_evidence_payloads=[],
        pricing_context=provenance["pricing_context"],
    )
    writer = EvidencePayloadWriter()
    files = writer._build_payload_files(  # noqa: SLF001
        bundle=bundle,
        scan_result=scan,
        config=SimpleNamespace(profile=None, mode="read-only"),
        minimisation=EvidenceMinimisationOptions(),
        bundle_purpose="collector_evidence",
    )

    checksums = build_checksums(files)
    files["manifest.json"] = dump_json(
        writer._build_manifest(  # noqa: SLF001
            bundle=bundle,
            scan_result=scan,
            config=SimpleNamespace(profile=None, mode="read-only"),
            minimisation=EvidenceMinimisationOptions(),
            checksums=checksums,
            evidence_files=[name for name in sorted(files) if name.startswith(("evidence/", "scan-result/"))],
            bundle_purpose="collector_evidence",
        )
    )
    files["checksums.json"] = dump_json({"algorithm": "sha256", "checksums": checksums})
    return files
