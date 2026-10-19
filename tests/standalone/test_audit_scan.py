"""Regression proof for demonstrated audit-service scan and strict conflicts."""

from __future__ import annotations

import json

import pytest

from tools.collector_audit_fixture import audit_producer_case
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("value", [True, False, None])
def test_declared_multi_region_boolean(*, value: bool | None) -> None:
    """An admitted nullable governance boolean is not a geographic identifier."""
    row = audit_producer_case("cloudtrail-security-posture-review")
    row["payload"] = {"trails": [{"is_multi_region": value}]}
    StrictTransformationVerifier().verify(
        {"scan-result/scanner-evidence.json": json.dumps({"scanner_evidence": [row]}).encode()}, load_privacy_profile("strict")
    )


@pytest.mark.parametrize(("key", "value"), [("is_multi_region", "eu-west-2"), ("is_multi_region", 1), ("unknown_region", True), ("home_region", "eu-west-2")])
def test_strict_region_guard_remains_closed(key: str, value: object) -> None:
    """Wrong boolean types and actual or unknown region fields remain rejected."""
    row = audit_producer_case("cloudtrail-security-posture-review")
    row["payload"] = {"trails": [{key: value}]}
    with pytest.raises(ValueError, match="Strict privacy transformation verification failed"):
        StrictTransformationVerifier().verify(
            {"scan-result/scanner-evidence.json": json.dumps({"scanner_evidence": [row]}).encode()}, load_privacy_profile("strict")
        )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_audit_unknown_enum_and_cross_schema(profile: str) -> None:
    """Finite values and neighboring schemas never become a union allowance."""
    from tests.standalone.test_bedrock_producer import transformer  # noqa: PLC0415

    row = audit_producer_case("xray-tracing-cost-governance-review")
    row["payload"]["records"][0]["encryption_type"] = "unknown-synthetic"
    row["payload"]["records"][0]["secret_count"] = 1
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(p.endswith("encryption_type") for p in t.summary.unclassified)
    assert any(p.endswith("secret_count") for p in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_selector_context_preserves_metadata_and_protects_equal_identity(profile: str) -> None:
    """One spelling in different selector fields never shares a privacy decision."""
    from tests.standalone.test_bedrock_producer import transformer  # noqa: PLC0415

    row = audit_producer_case("cloudtrail-cost-governance-review")
    selector = row["payload"]["records"][0]["raw_selectors"][1]
    selector["field_conditions"] = [
        {"field": "eventCategory", "Equals": ["Data"]},
        {"field": "resources.ARN", "Equals": ["Data"]},
        {"field": "readOnly", "Equals": ["true"]},
    ]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    conditions = result["scanner_evidence"][0]["payload"]["records"][0]["raw_selectors"][1]["field_conditions"]
    assert conditions[0]["Equals"] == ["Data"]
    assert conditions[1]["Equals"] != ["Data"]
    assert conditions[2]["Equals"] == ["true"]
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"Data"})
    assert scan.passed
    conditions[1]["Equals"] = ["Data"]
    assert (
        not ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"Data"}).passed
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_mirrored_warning_protection(profile: str) -> None:
    """The same actual warning in evidence and execution results protects identically."""
    from tests.standalone.test_bedrock_producer import transformer  # noqa: PLC0415
    from tools.collector_audit_fixture import audit_producer_observation  # noqa: PLC0415

    observed = audit_producer_observation("cloudtrail-security-posture-review", "partial")
    assert observed["warnings"]
    t = transformer(profile)
    result = t.transform({"scanner_results": [{"warnings": observed["warnings"]}]}, file_name="scan-result/scanner-results.json")
    assert not t.summary.unclassified
    assert result["scanner_results"][0]["warnings"] != observed["warnings"]
    scan = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-results.json", content=json.dumps(result), known_original_values=set(observed["warnings"])
    )
    assert scan.passed


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown", "wrong_counter", "boolean_counter", "wrong_literal"])
def test_actual_note_closed_paths(profile: str, mutation: str) -> None:
    """Actual notes reject unknown nulls, foreign counters and malformed fixed metadata."""
    from tests.standalone.test_bedrock_producer import transformer  # noqa: PLC0415
    from tools.collector_audit_fixture import audit_producer_observation  # noqa: PLC0415

    notes = audit_producer_observation("cloudtrail-cost-governance-review")["coverage_notes"]
    note = notes[0]
    if mutation == "unknown":
        note["unknown_note"] = None
    elif mutation == "wrong_counter":
        note["detail_counts"]["secret_count"] = 1
    elif mutation == "boolean_counter":
        note["detail_counts"]["trail_count"] = True
    else:
        note["scope_area"] = "synthetic-private-scope"
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": notes}]}, file_name="scan-result/scanner-results.json")
    assert t.summary.unclassified
