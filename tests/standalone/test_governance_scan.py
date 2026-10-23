"""Finite governance vocabularies, identity collisions and actual callback rejection."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_governance.fixture import COLLECTORS, governance_producer_case, governance_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_literal_identifier_collision(profile: str) -> None:
    """Detector status is public; an equal detector identifier remains protected/scanned."""
    row = governance_producer_case("guardduty-cost-governance-review", "collision")
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    record = result["scanner_evidence"][0]["payload"]["records"][0]
    assert record["detector_status_values"] == ["DISABLED", "ENABLED"]
    assert record["sample_detector_ids"][0] != "ENABLED"
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"ENABLED"}).passed
    record["sample_detector_ids"][0] = "ENABLED"
    assert not scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"ENABLED"}).passed


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("scanner", "field", "value"),
    [
        ("config-cost-governance-review", "recording_strategy_types", ["unrecognised"]),
        ("guardduty-cost-governance-review", "feature_status_counts", {"UNRECOGNISED": 1}),
        ("guardduty-cost-governance-review", "feature_status_counts", {"ENABLED": True}),
        ("securityhub-inspector-macie-cost-review", "macie_job_status_counts", {"UNRECOGNISED": None}),
        ("securityhub-inspector-macie-cost-review", "inspector_enabled", 1),
        ("securityhub-inspector-macie-cost-review", "inspector_status", "unknown"),
        ("waf-cost-governance-review", "association_metadata_collected", "true"),
        ("waf-cost-governance-review", "sample_rate_limits", [-1]),
        ("waf-cost-governance-review", "service_current_cost", "NaN"),
    ],
)
def test_governance_malformed_rejected(profile: str, scanner: str, field: str, value: object) -> None:
    """Malformed nulls, finite keys, scalar types and money reject before strict removal."""
    row = governance_producer_case(scanner)
    row["payload"]["records"][0][field] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(field in path for path in t.summary.unclassified)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_foreign_note_counter(scanner: str, profile: str) -> None:
    """Execution-detail keys and WAF-only optional fields do not become union allowances."""
    notes = governance_producer_observation(scanner)["coverage_notes"]
    note = next(note for note in notes if note["note_type"] == "execution_detail")
    note["detail_counts"]["secret_count"] = 1
    if not scanner.startswith("waf"):
        note["association_detail_modes"] = ["full"]
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": notes}]}, file_name="scan-result/scanner-results.json")
    assert any("secret_count" in path for path in t.summary.unclassified)
    if not scanner.startswith("waf"):
        assert any("association_detail_modes" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("scanner", ["config-cost-governance-review", "waf-cost-governance-review"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_limit_wrong_scope(scanner: str, profile: str) -> None:
    """Each exact option note requires its own producing scanner's scope pair."""
    notes = governance_producer_observation(scanner, "summary")["coverage_notes"]
    note = next(note for note in notes if note["note_type"] == "configuration_limit")
    note["scope_area"] = "config_rule_metadata" if scanner.startswith("waf") else "waf_web_acl_associations"
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": notes}]}, file_name="scan-result/scanner-results.json")
    assert any("scope_area" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_waf_arn_service_metadata_is_finite(profile: str) -> None:
    """A derived AWS service name is fixed metadata; foreign service-like data rejects."""
    row = governance_producer_case("waf-cost-governance-review")
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert result["scanner_evidence"][0]["payload"]["records"][0]["associated_resource_types"] == ["apigateway", "elasticloadbalancing"]
    row["payload"]["records"][0]["associated_resource_types"] = ["synthetic-customer-service"]
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("associated_resource_types[]" in path for path in t.summary.unclassified)


@pytest.mark.parametrize(
    ("service", "shape", "kind"),
    [
        ("config", "RecordingStrategyType", "recording_strategy"),
        ("config", "RecordingFrequency", "recording_frequency"),
        ("config", "MaximumExecutionFrequency", "delivery_frequency"),
        ("config", "RecorderStatus", "recorder_status"),
        ("guardduty", "DetectorStatus", "detector_status"),
        ("guardduty", "FindingPublishingFrequency", "publishing_frequency"),
        ("securityhub", "StandardsStatus", "standard_status"),
        ("inspector2", "Status", "inspector_status"),
        ("macie2", "MacieStatus", "macie_status"),
        ("macie2", "JobStatus", "job_status"),
        ("wafv2", "Scope", "waf_scope"),
    ],
)
def test_governance_pinned_provider_vocabularies(service: str, shape: str, kind: str) -> None:
    """A changed pinned SDK enum fails independently of producer fixture coverage."""
    import botocore.session  # noqa: PLC0415

    from unio_collector.privacy.audit.governance.fields import VOCABULARIES  # noqa: PLC0415

    assert VOCABULARIES[kind] == set(botocore.session.get_session().get_service_model(service).shape_for(shape).enum)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("variant", ["success", "summary", "partial", "denied", "unavailable", "unsupported", "failure", "cost_unavailable"])
def test_governance_actual_operation_branches(scanner: str, variant: str) -> None:
    """Require actual work/limitations and option-controlled calls, not empty stub success."""
    observed = governance_producer_observation(scanner, variant)
    records = observed["evidence"]["payload"]["records"]
    assert observed["operations"]
    if variant in {"success", "partial", "summary", "cost_unavailable"}:
        assert records
    if variant in {"denied", "unavailable", "unsupported", "failure", "partial"}:
        assert observed["diagnostics"]["failed_task_count"] or any(record["permission_errors"] for record in records)
    if variant == "cost_unavailable":
        assert observed["warnings"]
        assert all(record["service_current_cost"] is None and record["regional_current_cost"] is None for record in records)
    if variant == "summary" and scanner.startswith("config"):
        assert not any(call.endswith(("describe_config_rules", "describe_conformance_packs")) for call in observed["operations"])
    if variant == "summary" and scanner.startswith("waf"):
        assert not any(call.endswith("list_resources_for_web_acl") for call in observed["operations"])
    if scanner.startswith("waf") and records:
        assert {record["scope"] for record in records} == {"REGIONAL", "CLOUDFRONT"}


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("kind", ["execution", "configuration"])
def test_governance_note_kind_cannot_bypass_preflight(profile: str, kind: str) -> None:
    """A malformed known producer's note discriminant remains inside its closed contract."""
    notes = governance_producer_observation("config-cost-governance-review", "summary")["coverage_notes"]
    note = next(note for note in notes if note["note_type"] == ("execution_detail" if kind == "execution" else "configuration_limit"))
    note["note_type"] = "synthetic-customer-invalid-kind"
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": notes}]}, file_name="scan-result/scanner-results.json")
    assert any("note_type" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_note_label_bound_to_producer(scanner: str, profile: str) -> None:
    """A neighboring admitted scanner's label is not metadata for this producer."""
    notes = governance_producer_observation(scanner)["coverage_notes"]
    note = next(note for note in notes if note["note_type"] == "execution_detail")
    note["resource_label"] = "secret"
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": notes}]}, file_name="scan-result/scanner-results.json")
    assert any("resource_label" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("scanner_id", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_public_identity_customer_name_collision(scanner_id: str, profile: str) -> None:
    """An exact admitted reference is metadata; the same spelling in a customer field is scanned."""
    row = governance_producer_case(scanner_id, "identity_collision")
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    leak = ProtectedArchiveLeakScanner()
    assert leak.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={scanner_id}).passed
    record = result["scanner_evidence"][0]["payload"]["records"][0]
    field = {
        "config-cost-governance-review": "sample_recorder_names",
        "guardduty-cost-governance-review": "sample_detector_ids",
        "securityhub-inspector-macie-cost-review": "sample_macie_job_ids",
        "waf-cost-governance-review": "sample_web_acl_names",
    }[scanner_id]
    assert scanner_id not in record[field]
    record[field][0] = scanner_id
    assert not leak.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={scanner_id}).passed
    record[field][0] = "RESOURCE-AAAAAAAAAAAAAAAA"
    result["scanner_evidence"][0]["evidence_module"] = "synthetic.untrusted"
    assert not leak.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={scanner_id}).passed
