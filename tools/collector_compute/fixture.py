"""Actual EC2 wrappers, callbacks and serialization using synthetic providers."""

from __future__ import annotations

import json
from datetime import date
from types import SimpleNamespace
from typing import Any

from tools.collector_compute.session import SyntheticComputeSession
from tools.collector_nat_fixture import SyntheticNatSession
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.ec2 import Ec2InventoryCollector
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.core.scan.period_resolver import ScanPeriodResolver
from unio_collector.scan_workflow.evidence.network import NetworkEvidenceMixin
from unio_collector.scanners.ec2.idle_instance.collector import Ec2IdleInstanceReviewCollector
from unio_collector.scanners.idle.collector import IdleZombieResourceCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload

COLLECTORS = {"ec2-idle-instance-review": Ec2IdleInstanceReviewCollector, "idle-zombie-resource-detector": IdleZombieResourceCollector}
VARIANTS = ("success", "optional", "nullable", "empty", "partial", "denied", "unsupported", "unavailable", "failure", "collision", "identity_collision")
RUNNING_VARIANTS = ("metrics_partial", "metrics_failed", "metrics_empty", "capped", "scheduled", "schedule_empty", "schedule_collision")


def compute_producer_observation(scanner: str, variant: str = "success") -> dict[str, Any]:
    """Invoke actual provider collectors and cache callbacks, never hand-built evidence DTOs."""
    if scanner not in COLLECTORS or variant not in (*VARIANTS, *(RUNNING_VARIANTS if scanner == "ec2-idle-instance-review" else ())):
        message = "Unknown synthetic compute producer case."
        raise ValueError(message)
    session = SyntheticComputeSession(variant, scanner)
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    audit = AwsAuditContext(scanner_id=scanner, collector="synthetic", allowed_api_calls=())
    collector = Ec2InventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    nat_session = SyntheticNatSession(variant if variant in {"optional", "empty"} else "success")
    network = NetworkInventoryCollector(nat_session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    warnings: list[str] = []
    notes: list[dict[str, Any]] = []
    callbacks: list[str] = []
    options: dict[str, Any] = {"max_instances_per_region": 1 if variant == "capped" else 0}
    if variant in {"scheduled", "schedule_empty", "schedule_collision"}:
        options["scheduled_shutdown"] = (
            {}
            if variant == "schedule_empty"
            else {
                "schedule_tag_key": "synthetic-customer-schedule",
                "minimum_observation_days": 7,
                "minimum_hourly_coverage_percent": 90,
                "schedules": {
                    "synthetic-customer-weekdays": {"timezone": "Europe/London", "periods": [{"days": ["mon", "tue"], "start": "09:00", "stop": "17:00"}]}
                },
            }
        )
    if variant == "schedule_collision":
        schedules = options["scheduled_shutdown"]["schedules"]
        schedules["synthetic-customer.COST[0]"] = schedules.pop("synthetic-customer-weekdays")
    state = SimpleNamespace(
        account_id="123456789012",
        session=session,
        get_selected_regions=lambda: ["eu-west-2"],
        has_explicit_region_scope=lambda: True,
        get_scanner_option=lambda _s, key, default: options.get(key, default),
        config=SimpleNamespace(scan_period=ScanPeriodResolver().resolve(days=7, reference_date=date(2026, 5, 20))),
    )
    runtime: Any = SimpleNamespace(
        runtime_state=state,
        runner=SimpleNamespace(
            runtime_state=SimpleNamespace(
                account_id=state.account_id,
                cache=SimpleNamespace(get_or_load_with_status=lambda _ns, _key, load, **_kwargs: SimpleNamespace(status="loaded", value=load())),
            )
        ),
        create_audit_context=lambda *_args: audit,
        get_cached_ec2_regions=lambda _d: ["eu-west-2"],
        create_ec2_collector=lambda _d, **_kw: collector,
        collect_cached_ec2_items_by_region=lambda _d, **kw: _collect(callbacks, kw["collection_name"], kw["collect_items"], collector),
        collect_cached_ec2_records=lambda _d, **kw: _collect(callbacks, kw["collection_name"], kw["collect_records"], collector),
        add_scanner_warning=lambda _d, text: warnings.append(text),
        add_scanner_coverage_note=lambda _d, note: notes.append(note),
        ensure_can_start_evidence_collection=lambda *_args, **_kw: None,
        get_cached_network_regions=lambda _d: ["eu-west-2"],
        create_network_collector=lambda _d, **_kw: network,
        build_cache_access_policy=lambda **_kw: None,
        add_cached_evidence_note=lambda *_args, **_kw: None,
    )
    runtime.build_network_cache_keys = lambda: NetworkEvidenceMixin.build_network_cache_keys(runtime)
    runtime.build_network_labels = lambda: NetworkEvidenceMixin.build_network_labels(runtime)
    runtime.collect_cached_network_nat_gateway_records = lambda d: NetworkEvidenceMixin.collect_cached_network_nat_gateway_records(runtime, d)
    evidence = COLLECTORS[scanner](definition).collect(ScannerContext(runtime=runtime, definition=definition))
    row = json.loads(json.dumps(build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)))
    return {
        "evidence": row,
        "coverage_notes": notes,
        "warnings": warnings,
        "callbacks": callbacks,
        "operations": session.calls,
        "diagnostics": session.collection_diagnostics.convert_to_summary(),
    }


def _collect(callbacks: list[str], name: str, collect: Any, collector: Ec2InventoryCollector) -> Any:  # noqa: ANN401
    callbacks.append(name)
    return collect(collector)


def add_compute_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Share populated nullable and configured actual producer shapes with native smoke."""
    for scanner in COLLECTORS:
        observed = compute_producer_observation(scanner)
        row = observed["evidence"]
        for variant in ("optional", "nullable"):
            optional = compute_producer_observation(scanner, variant)["evidence"]
            for key, value in optional["payload"].items():
                if isinstance(value, list) and key != "regions":
                    row["payload"][key].extend(value)
        if scanner == "ec2-idle-instance-review":
            scheduled = compute_producer_observation(scanner, "schedule_collision")
            row["payload"]["metadata"] = scheduled["evidence"]["payload"]["metadata"]
            row["payload"]["records"].extend(scheduled["evidence"]["payload"]["records"])
            observed["coverage_notes"] = compute_producer_observation(scanner, "capped")["coverage_notes"]
        if unknown:
            key = "records" if scanner == "ec2-idle-instance-review" else "stopped_instances"
            row["payload"][key][0]["unknown_compute_field"] = {}
        add_scanner_producer_payload(files, row)
        results = json.loads(files["scan-result/scanner-results.json"])
        result = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
        result["coverage_notes"] = observed["coverage_notes"]
        result["warnings"] = observed["warnings"]
        files["scan-result/scanner-results.json"] = json.dumps(results).encode()
