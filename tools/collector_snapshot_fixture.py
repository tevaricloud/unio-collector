"""Actual snapshot scanner wrapper driven solely by synthetic offline endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from tools.collector_scanner_fixture import add_scanner_producer_payload
from tools.collector_storage_fixture import SyntheticStorageSession
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.scanners.collection.snapshots import SnapshotAgeReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

SCANNER = "snapshot-age-review"
VARIANTS = ("success", "optional", "empty", "denied", "unsupported", "unavailable", "failure", "partial", "missing_time", "future")


class SyntheticSnapshotSession(SyntheticStorageSession):
    """Exercise populated, nullable and unavailable branches of the real producer."""

    def describe_snapshots(self, **kwargs: object) -> dict[str, Any]:
        """Return fixed provider shapes without constructing a network client."""
        self._fail("DescribeSnapshots", kwargs)
        row: dict[str, Any] = {
            "SnapshotId": "snap-00000000000000000",
            "VolumeId": "vol-00000000000000000",
            "VolumeSize": 100,
            "StartTime": datetime(2026, 9, 1, tzinfo=UTC),
            "Description": "synthetic-customer-snapshot-description",
            "Tags": [{"Key": "Name", "Value": "synthetic-customer-snapshot"}],
        }
        if self.variant == "optional":
            row = {"SnapshotId": "snap-00000000000000000", "StartTime": datetime(2026, 9, 1, tzinfo=UTC)}
        if self.variant == "missing_time":
            row.pop("StartTime")
        if self.variant == "future":
            row["StartTime"] = datetime(2026, 11, 1, tzinfo=UTC)
        return {"Snapshots": [] if self.variant == "empty" else [row], **({"NextToken": "synthetic-next"} if self.variant == "partial" else {})}


def snapshot_producer_case(variant: str = "success", threshold: int | None = None) -> tuple[dict[str, Any], list[str], list[str]]:
    """Run the actual scanner wrapper, gateways, DTO producer and serialization."""
    if variant not in VARIANTS:
        message = "Unknown synthetic snapshot variant."
        raise ValueError(message)
    session = SyntheticSnapshotSession(variant)
    definition: Any = SimpleNamespace(scanner_id=SCANNER)
    runtime: Any = SimpleNamespace(
        runtime_state=SimpleNamespace(
            session=session,
            account_id="123456789012",
            get_selected_regions=lambda: ["eu-west-2"],
            get_scanner_option=lambda _scanner, _key, default: default if threshold is None else threshold,
        ),
        create_audit_context=lambda _definition, name: AwsAuditContext(scanner_id=SCANNER, collector=name, allowed_api_calls=()),
    )
    context = ScannerContext(runtime=runtime, definition=definition)
    with patch("unio_collector.aws.snapshot.collector.datetime") as clock:
        clock.now.return_value = datetime(2026, 10, 1, tzinfo=UTC)
        evidence = SnapshotAgeReviewCollector(definition).collect(context)
    row = build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)
    diagnostics = session.collection_diagnostics
    return row, [result.status for result in diagnostics.get_results_since(0)], diagnostics.build_warning_messages_since(0)


def add_snapshot_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False) -> None:
    """Share populated and optional actual producer records with native smoke tests."""
    row, _, _ = snapshot_producer_case()
    optional, _, _ = snapshot_producer_case("optional")
    row["payload"]["records"].extend(optional["payload"]["records"])
    if unknown_field:
        row["payload"]["records"][0]["unknown_snapshot_field"] = {}
    add_scanner_producer_payload(files, row)
