"""Synthetic CUR bytes through the registered collector and real gateway callbacks."""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
from types import SimpleNamespace
from typing import Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scanners.cur_data_export.collector import CurDataExportAttributionCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "cur-data-export-attribution"
VARIANTS = (
    "success",
    "gzip",
    "manifest",
    "partial",
    "unsupported",
    "empty",
    "optional",
    "denied",
    "failure",
    "unavailable",
    "mixed_currency",
    "collision",
    "status_collision",
)


def cur_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Read populated synthetic billing rows; preserve actual supported exception outcomes."""
    if variant not in VARIANTS:
        message = "Unknown synthetic CUR case."
        raise ValueError(message)
    raw = _billing_bytes(variant)
    calls: list[dict[str, Any]] = []
    paths = ("s3://synthetic-customer-billing/export/billing.csv",)
    if variant == "gzip":
        paths = (paths[0] + ".gz",)
    elif variant == "manifest":
        paths = ("s3://synthetic-customer-billing/export/manifest.json",)
    elif variant in {"unsupported", "unavailable"}:
        paths = ("s3://synthetic-customer-billing/export/billing.parquet",) if variant == "unsupported" else ()
    audit = AwsAuditContext(scanner_id=SCANNER, collector="CurDataExportReader", allowed_api_calls=())

    def get_object(*, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        calls.append({"bucket": Bucket, "key": Key})
        if variant in {"denied", "failure"}:
            raise ClientError(
                {"Error": {"Code": "AccessDenied" if variant == "denied" else "InternalError", "Message": "synthetic-customer-error"}}, "GetObject"
            )
        data = (
            json.dumps({"reportKeys": ["billing.csv"]}).encode()
            if Key.endswith("manifest.json")
            else gzip.compress(raw, mtime=0)
            if Key.endswith(".gz")
            else raw
        )
        return {"Body": io.BytesIO(data)}

    def session_client(service: str, **kwargs: object) -> SimpleNamespace:
        if service != "s3" or kwargs.get("audit_context") is not audit:
            message = "Unexpected synthetic CUR gateway invocation."
            raise ValueError(message)
        return SimpleNamespace(get_object=get_object)

    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(
            config=SimpleNamespace(
                cur_paths=paths, scan_period=ScanPeriodResolver().resolve(date_from="2026-05-01", date_to="2026-05-31"), cost_grouping_tags=("Project",)
            ),
            session=SimpleNamespace(get_region_name=lambda: "eu-west-2", create_client=session_client),
        ),
        create_audit_context=lambda *_a: audit,
    )
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    collector = CurDataExportAttributionCollector(definition)
    try:
        evidence = collector.collect(ScannerContext(runtime=runtime, definition=definition))
    except (ClientError, ValueError) as error:
        return {
            "evidence": None,
            "operations": calls,
            "exception": type(error).__name__,
            "error_code": error.response["Error"]["Code"] if isinstance(error, ClientError) else None,
            "input_sha256": hashlib.sha256(raw).hexdigest(),
        }
    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)))
    return {"evidence": row, "operations": calls, "exception": None, "input_sha256": hashlib.sha256(raw).hexdigest()}


def add_cur_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Include actual populated CUR billing output in the shared native smoke input."""
    row = cur_producer_observation()["evidence"]
    if unknown:
        row["payload"]["billing_facts"]["top_resources"][0]["unknown_cur_field"] = None
    add_scanner_producer_payload(files, row)


def _billing_bytes(variant: str) -> bytes:
    """Serialize real CSV reader inputs including refunds and an excluded period."""
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("usage_start_date", "cost", "currency", "service", "region", "usage_type", "resource_id", "account_id", "resourceTags/user:Project"))
    if variant != "empty":
        for index in range(3):
            optional = variant == "optional"
            writer.writerow(
                (
                    "2026-05-01",
                    "12.345" if index != 1 else "-1.005",
                    "GBP" if variant == "mixed_currency" and index else "USD",
                    "synthetic-customer-service",
                    "eu-west-2",
                    "" if optional else "synthetic-customer-usage",
                    "CurDataExportEvidence"
                    if variant == "collision"
                    else "complete"
                    if variant == "status_collision"
                    else "synthetic-customer-resource-" + str(index),
                    "" if optional else "123456789012",
                    "" if optional or index == 1 else "synthetic-customer-project",
                )
            )
        writer.writerow(("2025-01-01", "99.0", "USD", "outside", "eu-west-2", "outside", "outside", "123456789012", ""))
        if variant == "partial":
            writer.writerow(("2026-05-01", "NaN", "USD", "invalid", "eu-west-2", "invalid", "invalid", "123456789012", ""))
    return stream.getvalue().encode()
