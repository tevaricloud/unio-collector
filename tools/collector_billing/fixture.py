"""Actual billing producer collection, callbacks and canonical serialization."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

from tools.collector_billing.response import VARIANTS
from tools.collector_billing.session import SyntheticBillingSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.scan_workflow.scanner.collection.service import ScannerCollectionService
from unio_collector.scan_workflow.scanner.runtime.cancellation import ScannerCancellationToken
from unio_collector.scan_workflow.scanner.runtime.dependencies import ScannerRuntimeDependencies
from unio_collector.scanners.billing.collector import BillingAlertsAndBudgetsCollector


def billing_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Drive the actual framework collector, callbacks and canonical serializer."""
    scanner = "billing-alerts-and-budgets-review"
    if variant not in VARIANTS:
        message = "Unsupported synthetic billing variant"
        raise ValueError(message)
    wrapper = BillingAlertsAndBudgetsCollector
    session = SyntheticBillingSession(variant)
    events = []
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        config=SimpleNamespace(),
        collection_diagnostics=session.collection_diagnostics,
        ledger=ApiCallLedger(),
        get_selected_regions=lambda: [] if variant == "missing_scope" else ["eu-west-2"],
        has_explicit_region_scope=lambda: variant != "missing_scope",
        get_scanner_option=lambda _s, k, d: (
            "summary"
            if k == "subscriber_detail_mode" and variant == "summary"
            else "budgets-only"
            if k == "monitor_detail_mode" and variant == "budgets_only"
            else d
        ),
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
    execution = ScannerCollectionService(deps).collect_scanner(cast("Any", runner), scanner)
    return {
        "evidence": runner.output_state.scanner_evidence_payloads[0] if runner.output_state.scanner_evidence_payloads else None,
        "execution": execution.convert_to_dict(),
        "operations": session.calls,
        "endpoints": session.endpoints,
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


def add_billing_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Add the actual full SDK billing shape to packaged protection smoke."""
    observed = billing_producer_observation()
    if unknown:
        observed["evidence"]["payload"]["budgets"][0]["budget"]["BudgetLimit"]["unknown_billing_control"] = None
    add_scanner_producer_payload(files, observed["evidence"], execution=observed["execution"])
