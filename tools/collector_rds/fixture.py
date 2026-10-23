"""Actual RDS producer collection, callbacks and canonical serialization."""

from __future__ import annotations

from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

from tools.collector_rds.client import VARIANTS
from tools.collector_rds.session import SyntheticRdsSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.rds import collector as rds_module
from unio_collector.core.scan.period import ScanPeriod
from unio_collector.scan_workflow.scanner.collection.service import ScannerCollectionService
from unio_collector.scan_workflow.scanner.runtime.cancellation import ScannerCancellationToken
from unio_collector.scan_workflow.scanner.runtime.dependencies import ScannerRuntimeDependencies
from unio_collector.scanners.rds.collection.snapshots import RdsSnapshotRetentionReviewCollector
from unio_collector.scanners.rds.collection.utilization import RdsUtilizationReviewCollector

COLLECTORS = {"rds-snapshot-retention-review": RdsSnapshotRetentionReviewCollector, "rds-utilization-review": RdsUtilizationReviewCollector}

CASE_VARIANTS = {
    scanner: VARIANTS
    if scanner == "rds-utilization-review"
    else tuple(v for v in VARIANTS if not v.startswith("metrics_") and v not in {"statistics_fallback", "stopped", "stopping", "custom_status"})
    for scanner in COLLECTORS
}


def rds_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Drive the actual framework collector, callbacks and canonical serializer."""
    if variant not in VARIANTS:
        message = "Unsupported synthetic RDS variant"
        raise ValueError(message)
    wrapper = COLLECTORS[scanner]
    session = SyntheticRdsSession(variant)
    events = []
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        config=SimpleNamespace(scan_period=ScanPeriod("days", {"days": 2}, date(2026, 7, 1), date(2026, 7, 2), date(2026, 6, 29), date(2026, 6, 30))),
        collection_diagnostics=session.collection_diagnostics,
        ledger=ApiCallLedger(),
        get_selected_regions=lambda: session.get_available_regions("rds"),
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _s, _k, d: d,
    )
    runner = SimpleNamespace(
        runtime_state=state,
        note_state=SimpleNamespace(scanner_warnings={}, scanner_coverage_notes={}),
        output_state=SimpleNamespace(scanner_evidence_payloads=[], results=[], scanner_data={}),
        active_attempt=None,
        cancellation_token=ScannerCancellationToken(),
        evidence_gateway=SimpleNamespace(get_cached_ec2_regions=lambda _d: []),
    )
    deps = ScannerRuntimeDependencies(scanner_factory=lambda _id, d: wrapper(d), progress=events.append, scanner_total=1)
    clock = SimpleNamespace(now=lambda _zone: datetime(2026, 10, 1, tzinfo=UTC), combine=datetime.combine)
    with patch.object(rds_module, "datetime", clock):
        execution = ScannerCollectionService(deps).collect_scanner(cast("Any", runner), scanner)
    return {
        "evidence": runner.output_state.scanner_evidence_payloads[0] if runner.output_state.scanner_evidence_payloads else None,
        "execution": execution.convert_to_dict(),
        "operations": session.calls,
        "diagnostics": session.collection_diagnostics.convert_to_summary(),
        "events": [
            {
                "event_type": e.event_type,
                "scanner_status": e.scanner_status,
                "warning_count": e.warning_count,
                "error_count": e.error_count,
                "message": e.message,
            }
            for e in events
        ],
    }


def add_rds_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Include populated and conditional real producer records in packaged smoke."""
    for scanner in COLLECTORS:
        variants = ("success", "optional", "metrics_partial", "metrics_empty") if scanner == "rds-utilization-review" else ("success", "optional")
        observations = [rds_producer_observation(scanner, variant) for variant in variants]
        primary = observations[0]
        primary["evidence"]["payload"]["records"] = [record for observation in observations for record in observation["evidence"]["payload"]["records"]]
        if unknown:
            record = primary["evidence"]["payload"]["records"][0]
            if scanner == "rds-utilization-review":
                record["metrics"][0]["unknown_rds_metric"] = None
            else:
                record["unknown_rds_snapshot"] = None
        add_scanner_producer_payload(files, primary["evidence"], execution=primary["execution"])
