"""Actual registered Backup collector, callbacks and canonical wire serialization."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from tools.collector_backup.session import SyntheticBackupSession
from tools.collector_sdk_fixture import SyntheticWrapperRuntime, add_wrapper_observation
from unio_collector.scanners.collection.backup import BackupRetentionReviewCollector
from unio_collector.scanners.registry.catalog import get_scanner
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

SCANNER = "backup-retention-review"
VARIANTS = (
    "success",
    "empty",
    "denied",
    "unsupported",
    "failure",
    "unavailable",
    "partial",
    "nullable",
    "summary",
    "no_tags",
    "tag_denied",
    "selection_denied",
    "literal_collision",
)


def backup_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Invoke real metadata detail tasks and callback policies using only synthetic SDK responses."""
    options: dict[str, object] = {
        "max_detail_workers": 1,
        "selection_detail_mode": "summary" if variant == "summary" else "full",
        "collect_tags": variant != "no_tags",
    }
    session = SyntheticBackupSession(variant)
    runtime: Any = SyntheticWrapperRuntime(session, options=options, service_costs=None, daily_costs=[])
    instant = datetime(2026, 9, 30, tzinfo=UTC)
    runtime.analysis_reference_time = SimpleNamespace(instant=instant, date=instant.date(), source="synthetic")
    definition = get_scanner(SCANNER)
    wrapper = BackupRetentionReviewCollector(definition)
    evidence = wrapper.collect(ScannerContext(runtime=runtime, definition=definition))
    row = build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence)
    diagnostic_warnings = session.collection_diagnostics.build_warning_messages_since(0)
    warnings = [*runtime.warnings, *diagnostic_warnings]
    implementation = wrapper.describe_implementation()
    execution = ScannerExecutionResult(
        scanner_id=SCANNER,
        status="completed_with_warnings" if warnings else "completed",
        warnings=warnings,
        coverage_notes=runtime.notes,
        regions_scanned=evidence.regions,
        implementation_type=implementation.implementation_type,
        implementation_class=implementation.implementation_class,
        implementation_module=implementation.implementation_module,
    ).convert_to_dict()
    return {
        "evidence": row,
        "execution": execution,
        "callbacks": runtime.callbacks,
        "provider_calls": session.calls,
        "statuses": [result.status for result in session.collection_diagnostics.get_results_since(0)],
        "diagnostic_warnings": session.collection_diagnostics.build_warning_messages_since(0),
    }


def add_backup_producer_payload(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Reuse actual populated full and conditional backup source in packaged protection smoke."""
    observed = backup_producer_observation()
    for variant in ("summary", "no_tags"):
        observed["execution"]["coverage_notes"].extend(backup_producer_observation(variant)["execution"]["coverage_notes"][2:])
    if unknown:
        plan = next(record for record in observed["evidence"]["payload"]["records"] if "backup_plan_id" in record)
        plan["rules"][0]["unknown_backup_control"] = None
    add_wrapper_observation(files, observed)
