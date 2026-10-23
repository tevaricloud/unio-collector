"""Actual missing-tag wrapper and cache callbacks over synthetic topology inputs."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from tools.collector_attribution.session import SyntheticAttributionSession
from tools.collector_sdk_fixture import SyntheticWrapperRuntime
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.aws.ec2 import Ec2InventoryCollector
from unio_collector.aws.network.inventory import NetworkInventoryCollector
from unio_collector.aws.resource_groups.tagging.collector import ResourceGroupsTaggingCollector
from unio_collector.scan_workflow.evidence.network import NetworkEvidenceMixin
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult
from unio_collector.scanners.tagging.collector import MissingCostTagsCollector

SCANNER = "tagging-missing-cost-tags"
VARIANTS = (
    "success",
    "empty",
    "nullable",
    "partial",
    "denied",
    "unavailable",
    "unsupported",
    "failure",
    "disabled",
    "collision",
    "deferred_defaults",
    "fast_denied",
    "direct_denied",
    "target_groups_denied",
    "target_health_denied",
    "asg_denied",
    "tags_denied",
)


def tagging_producer_observation(variant: str = "success") -> dict[str, Any]:
    """Exercise actual SDK collectors, merge decisions, callbacks and canonical evidence."""
    if variant not in VARIANTS:
        message = "Unknown synthetic tagging case"
        raise ValueError(message)
    session = SyntheticAttributionSession(variant)
    audit = AwsAuditContext(scanner_id=SCANNER, collector="synthetic", allowed_api_calls=())
    ec2 = Ec2InventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    network = NetworkInventoryCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    tagging = ResourceGroupsTaggingCollector(session, account_id="123456789012", audit_context=audit, selected_regions=["eu-west-2"])
    runtime: Any = SyntheticWrapperRuntime(session, options={"use_resource_groups_tagging_api": variant != "disabled"}, service_costs=[], daily_costs=[])
    runtime.runtime_state.config.required_tags = [] if variant == "deferred_defaults" else ["Owner", "Project"]
    runtime.runtime_state.config.analysis_defaults_deferred = variant == "deferred_defaults"
    runtime.scanner_data = {}
    runtime.get_cached_ec2_regions = lambda _d: ["eu-west-2"]
    runtime.collect_cached_ec2_records = lambda _d, **kw: _collect(runtime.callbacks, kw["collection_name"], kw["collect_records"], ec2)
    runtime.collect_cached_resource_groups_tagging_records = lambda _d, **_kw: _collect(
        runtime.callbacks, "tagging", lambda c: c.collect_taggable_resources(), tagging
    )
    runtime.runner = SimpleNamespace(
        runtime_state=SimpleNamespace(
            account_id="123456789012",
            cache=SimpleNamespace(get_or_load_with_status=lambda _ns, _key, load, **_kw: SimpleNamespace(status="loaded", value=load())),
        )
    )
    runtime.create_network_collector = lambda _d, **_kw: network
    runtime.get_cached_network_regions = lambda _d: ["eu-west-2"]
    runtime.ensure_can_start_evidence_collection = lambda *_a, **_kw: None
    runtime.build_cache_access_policy = lambda **_kw: None
    runtime.add_cached_evidence_note = lambda *_a, **_kw: None
    runtime.build_network_cache_keys = lambda: NetworkEvidenceMixin.build_network_cache_keys(runtime)
    runtime.build_network_labels = lambda: NetworkEvidenceMixin.build_network_labels(runtime)
    runtime.collect_cached_network_nat_gateway_records = lambda d: NetworkEvidenceMixin.collect_cached_network_nat_gateway_records(runtime, d)
    definition: Any = SimpleNamespace(scanner_id=SCANNER, display_name=SCANNER)
    evidence = MissingCostTagsCollector(definition).collect(ScannerContext(runtime=runtime, definition=definition))
    return {
        "evidence": build_scanner_evidence_payload(scanner_id=SCANNER, evidence=evidence),
        "execution": ScannerExecutionResult(
            scanner_id=SCANNER,
            status="completed_with_warnings" if runtime.warnings else "completed",
            warnings=runtime.warnings,
            coverage_notes=runtime.notes,
            regions_scanned=evidence.regions,
        ).convert_to_dict(),
        "callbacks": runtime.callbacks,
        "operations": session.calls,
        "scanner_data": runtime.scanner_data,
    }


def _collect(callbacks: list[str], name: str, callback: Any, collector: object) -> Any:  # noqa: ANN401
    callbacks.append(name)
    return callback(collector)
