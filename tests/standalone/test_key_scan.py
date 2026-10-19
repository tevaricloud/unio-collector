"""Key/control finite vocabularies and adversarial identity/text rejection."""

from __future__ import annotations

import copy
import json

import pytest
from botocore.session import Session

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_key_fixture import COLLECTORS, key_producer_observation
from unio_collector.privacy.key_controls.fields import VOCABULARIES
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", ["collision", "identity_collision"])
def test_key_customer_collision_remains_scanned(scanner: str, profile: str, variant: str) -> None:
    """Public metadata may equal a customer ID; restored plaintext still rejects."""
    row = key_producer_observation(scanner, variant)["evidence"]
    original = scanner if variant == "identity_collision" else "Enabled"
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    scanner_service = ProtectedArchiveLeakScanner()
    assert scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed
    payload = result["scanner_evidence"][0]["payload"]
    record = payload.get("keys", payload.get("ebs_volumes", payload.get("records")))[0]
    field = {
        "kms-cost-governance-review": "sample_key_ids",
        "kms-key-posture-review": "key_id",
        "encryption-baseline-review": "volume_id",
        "securityhub-control-summary-review": "control_id",
    }[scanner]
    assert original not in json.dumps(record[field])
    record[field] = [original] if isinstance(record[field], list) else original
    assert not scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed
    record[field] = ["RESOURCE-AAAAAAAAAAAAAAAA"] if isinstance(record[field], list) else "RESOURCE-AAAAAAAAAAAAAAAA"
    result["scanner_evidence"][0]["evidence_module"] = "synthetic.untrusted"
    if variant == "identity_collision":
        assert not scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={scanner}).passed


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("identity", ["evidence_module", "evidence_type", "provider_id", "evidence_schema_id"])
def test_key_identity_conflicts(scanner: str, identity: str) -> None:
    """Conflicting registered identities reject before producer imports."""
    row = key_producer_observation(scanner)["evidence"]
    row[identity] = "untrusted"
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize(
    ("kind", "shape"),
    [
        ("manager", "KeyManagerType"),
        ("state", "KeyState"),
        ("spec", "KeySpec"),
        ("usage", "KeyUsageType"),
        ("origin", "OriginType"),
        ("multi_kind", "MultiRegionKeyType"),
    ],
)
def test_key_sdk_vocabularies(kind: str, shape: str) -> None:
    """Enumerations match the pinned SDK independently of emitted fixtures."""
    assert VOCABULARIES[kind] == set(Session().get_service_model("kms").shape_for(shape).enum)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("scanner", "container", "field", "value"),
    [
        ("kms-cost-governance-review", "records", "key_count", True),
        ("kms-cost-governance-review", "records", "service_current_cost", "NaN"),
        ("kms-key-posture-review", "keys", "rotation_enabled", 1),
        ("kms-key-posture-review", "keys", "key_state", "customer-controlled-state"),
        ("encryption-baseline-review", "ebs_volumes", "encrypted", "true"),
        ("securityhub-control-summary-review", "records", "severity_label", "customer-severity"),
        ("securityhub-control-summary-review", "records", "failed_finding_count", -1),
    ],
)
def test_key_malformed_fields(profile: str, scanner: str, container: str, field: str, value: object) -> None:
    """Incorrect types and nonfinite financial values remain unclassified."""
    row = copy.deepcopy(key_producer_observation(scanner)["evidence"])
    row["payload"][container][0][field] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(field in p for p in t.summary.unclassified)


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_key_actual_populated_operations(scanner: str) -> None:
    """Success is populated and limited branches retain actual diagnostics."""
    observed = key_producer_observation(scanner)
    assert observed["operations"]
    payload = observed["evidence"]["payload"]
    assert payload.get("keys", payload.get("ebs_volumes", payload.get("records")))
    if scanner == "kms-cost-governance-review":
        assert payload["records"][0]["raw_keys"]
        assert observed["coverage_notes"]
    if scanner == "securityhub-control-summary-review":
        assert payload["records"][0]["failed_finding_count"] == 2  # noqa: PLR2004
        assert payload["records"][0]["standard_arns"]
    partial = key_producer_observation(scanner, "partial")
    assert partial["warnings"] or partial["evidence"]["payload"]["records"][0]["permission_errors"]


@pytest.mark.parametrize("value", [None, 0, 2])
def test_key_nullable_summary_count_strict(value: int | None) -> None:
    """Only this explicitly nullable count preserves unavailable tag-read information."""
    from unio_collector.privacy.profiles import load_privacy_profile  # noqa: PLC0415
    from unio_collector.privacy.strict_verifier import StrictTransformationVerifier  # noqa: PLC0415

    row = key_producer_observation("kms-cost-governance-review", "partial")["evidence"]
    next(record for record in row["payload"]["records"] if record["raw_keys"])["raw_keys"][0]["tag_count"] = value
    t = transformer("strict")
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    StrictTransformationVerifier().verify({"scan-result/scanner-evidence.json": json.dumps(result).encode()}, load_privacy_profile("strict"))


@pytest.mark.parametrize("value", [True, -1, "2", float("nan")])
def test_key_nullable_count_invalid_still_rejects(value: object) -> None:
    """A nullable integer contract never admits booleans, text or invalid numbers."""
    from unio_collector.privacy.profiles import load_privacy_profile  # noqa: PLC0415
    from unio_collector.privacy.strict_verifier import StrictTransformationVerifier  # noqa: PLC0415

    row = key_producer_observation("kms-cost-governance-review")["evidence"]
    next(record for record in row["payload"]["records"] if record["raw_keys"])["raw_keys"][0]["tag_count"] = value
    t = transformer("strict")
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("tag_count" in path for path in t.summary.unclassified)
    with pytest.raises(ValueError, match="Strict privacy transformation verification failed"):
        StrictTransformationVerifier().verify(
            {"scan-result/scanner-evidence.json": json.dumps({"scanner_evidence": [row]}).encode()}, load_privacy_profile("strict")
        )


@pytest.mark.parametrize("field", ["key_count", "foreign_count"])
def test_key_null_count_not_universally_admitted(field: str) -> None:
    """Nonnullable and unknown counts stay blocked instead of gaining null admission."""
    row = key_producer_observation("kms-cost-governance-review")["evidence"]
    row["payload"]["records"][0][field] = None
    t = transformer("strict")
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(field in path for path in t.summary.unclassified)


@pytest.mark.parametrize("variant", ["denied", "unavailable", "unsupported", "failure", "partial", "malformed", "truncated"])
@pytest.mark.parametrize("scanner", COLLECTORS)
def test_key_real_limited_shapes(scanner: str, variant: str) -> None:
    """Limited provider branches must retain limitations, never empty clean success."""
    observed = key_producer_observation(scanner, variant)
    payload = observed["evidence"]["payload"]
    assert observed["operations"]
    assert observed["warnings"] or any(row["permission_errors"] for row in payload.get("records", []) if "permission_errors" in row)


def test_key_actual_securityhub_absence_and_rotation() -> None:
    """Service-not-enabled and disabled rotation are actual supported producer branches."""
    absent = key_producer_observation("securityhub-control-summary-review", "not_enabled")["evidence"]["payload"]
    assert absent["not_enabled_regions"]
    assert not absent["enabled_regions"]
    cost = key_producer_observation("kms-cost-governance-review", "rotation_off")["evidence"]["payload"]
    assert any(key["rotation_enabled"] is False for key in cost["records"][0]["raw_keys"])
    posture = key_producer_observation("kms-key-posture-review", "rotation_off")["evidence"]["payload"]
    assert any(key["rotation_enabled"] is False for key in posture["keys"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["foreign_counter", "wrong_label", "wrong_note_type"])
def test_key_execution_note_contract_closed(profile: str, mutation: str) -> None:
    """Mirrored callback identities and counters cannot borrow another producer's fields."""
    note = key_producer_observation("kms-cost-governance-review")["coverage_notes"][0]
    if mutation == "foreign_counter":
        note["detail_counts"]["detector_count"] = 1
    elif mutation == "wrong_label":
        note["resource_label"] = "detector or protection feature"
    else:
        note["note_type"] = "unknown-note"
    t = transformer(profile)
    t.transform({"scanner_results": [{"coverage_notes": [note]}]}, file_name="scan-result/scanner-results.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("scanner", "container", "field"),
    [
        ("kms-cost-governance-review", "records", "sample_key_states"),
        ("kms-key-posture-review", "keys", "key_state"),
    ],
)
def test_key_empty_enum_only_raw_defaults(scanner: str, container: str, field: str) -> None:
    """Empty defaults are admitted only in raw inventory fields that actually emit them."""
    row = key_producer_observation(scanner)["evidence"]
    row["payload"][container][0][field] = [""] if field.startswith("sample_") else ""
    t = transformer("standard")
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(field in path for path in t.summary.unclassified)
