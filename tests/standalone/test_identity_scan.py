"""Key/control finite vocabularies and adversarial identity/text rejection."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_identity_fixture import COLLECTORS, identity_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", ["collision", "identity_collision", "policy_collision"])
def test_identity_customer_collision_remains_scanned(scanner: str, profile: str, variant: str) -> None:
    """Public metadata may equal a customer ID; restored plaintext still rejects."""
    row = identity_producer_observation(scanner, variant)["evidence"]
    original = scanner if variant == "identity_collision" else "Allow" if variant == "policy_collision" else "ACTIVE"
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    scanner_service = ProtectedArchiveLeakScanner()
    assert scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed
    payload = result["scanner_evidence"][0]["payload"]
    container, field = {
        "iam-account-security-review": ("users", "user_name"),
        "iam-access-analyzer-evidence-review": ("analyzers", "analyzer_name"),
        "iam-identity-center-visibility-review": ("instances", "name"),
        "aws-security-service-coverage-review": ("records", "detail"),
    }[scanner]
    record = payload[container][0]
    assert original not in json.dumps(record[field])
    record[field] = [original] if isinstance(record[field], list) else original
    assert not scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed
    record[field] = ["RESOURCE-AAAAAAAAAAAAAAAA"] if isinstance(record[field], list) else "RESOURCE-AAAAAAAAAAAAAAAA"
    result["scanner_evidence"][0]["evidence_module"] = "synthetic.untrusted"
    if variant == "identity_collision":
        assert not scanner_service.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={scanner}).passed


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("identity", ["evidence_module", "evidence_type", "provider_id", "evidence_schema_id"])
def test_identity_conflicts(scanner: str, identity: str) -> None:
    """Conflicting registered identities reject before producer imports."""
    row = identity_producer_observation(scanner)["evidence"]
    row[identity] = "untrusted"
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("variant", ["denied", "unavailable", "unsupported", "failure", "partial", "malformed", "truncated"])
def test_identity_actual_limits(scanner: str, variant: str) -> None:
    """Supported failures retain warnings and requested operations."""
    observed = identity_producer_observation(scanner, variant)
    assert observed["operations"]
    assert observed["warnings"]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("field", ["unknown", "aws:UnknownCustomerField", "aws:PrincipalArn.child"])
def test_identity_unknown_policy(profile: str, field: str) -> None:
    """Unknown policy/condition descendants reject before transformations."""
    row = identity_producer_observation("iam-account-security-review", "full")["evidence"]
    grant = next(g for g in row["payload"]["policy_grants"] if g["policy_document"])
    grant["policy_document"]["Statement"][0]["Condition"]["StringEquals"][field] = None
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, True, -1, "one", float("nan")])
def test_identity_required_count_malformed(profile: str, value: object) -> None:
    """Nullable admission cannot extend to mandatory integer summaries."""
    row = identity_producer_observation("iam-account-security-review")["evidence"]
    row["payload"]["account_summary"]["Users"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("Users" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [{"unknown": "complete"}, {"eu-west-2": None}, {"eu-west-2": "customer prose"}, {"eu-west-2.child": "complete"}])
def test_identity_regional_map_unknown(profile: str, value: object) -> None:
    """Region map admission is typed and finite, never a descendant wildcard."""
    row = identity_producer_observation("iam-access-analyzer-evidence-review")["evidence"]
    row["payload"]["analyzer_inventory_status"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("analyzer_inventory_status" in path for path in t.summary.unclassified)


def test_identity_regional_map_profiles() -> None:
    """Standard retains exact map keys; strict withdraws regional inventory detail."""
    from unio_collector.privacy.profiles import load_privacy_profile  # noqa: PLC0415
    from unio_collector.privacy.strict_verifier import StrictTransformationVerifier  # noqa: PLC0415

    row = identity_producer_observation("iam-access-analyzer-evidence-review")["evidence"]
    standard = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert standard["scanner_evidence"][0]["payload"]["analyzer_inventory_status"] == {"eu-west-2": "complete"}
    strict = transformer("strict").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert strict["scanner_evidence"][0]["payload"]["analyzer_inventory_status"] == {}
    strict["scanner_evidence"][0]["payload"]["analyzer_inventory_status"] = {"eu-west-2": "complete"}
    with pytest.raises(ValueError, match="Strict privacy transformation verification failed"):
        StrictTransformationVerifier().verify({"scan-result/scanner-evidence.json": json.dumps(strict).encode()}, load_privacy_profile("strict"))


@pytest.mark.parametrize("scanner", ["iam-account-security-review", "untrusted"])
def test_identity_callback_parent(scanner: str) -> None:
    """A real note cannot borrow a different parent scanner identity."""
    from unio_collector.privacy.identity.notes import IdentityNoteContract, unknown_identity_notes  # noqa: PLC0415

    note = identity_producer_observation("iam-identity-center-visibility-review")["coverage_notes"][0]
    assert IdentityNoteContract.for_note(note, scanner_id="iam-identity-center-visibility-review")
    assert unknown_identity_notes({"scanner_results": [{"scanner_id": scanner, "coverage_notes": [note]}]}, "scan-result/scanner-results.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["missing_statement", "missing_effect", "conflicting_action", "empty_resource"])
def test_identity_policy_shape(profile: str, mutation: str) -> None:
    """Closed policy structure rejects incomplete or contradictory statements."""
    row = identity_producer_observation("iam-account-security-review", "full")["evidence"]
    policy = next(g["policy_document"] for g in row["payload"]["policy_grants"] if g["policy_document"])
    statement = policy["Statement"][0]
    if mutation == "missing_statement":
        del policy["Statement"]
    elif mutation == "missing_effect":
        del statement["Effect"]
    elif mutation == "conflicting_action":
        statement["NotAction"] = "iam:DeleteUser"
    else:
        statement["Resource"] = []
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


def test_identity_populated_branches() -> None:
    """Actual collectors retain populated primary, optional and mirrored output."""
    account = identity_producer_observation("iam-account-security-review", "full")
    assert account["evidence"]["payload"]["users"][0]["access_keys"]
    assert any(g["policy_document"] for g in account["evidence"]["payload"]["policy_grants"])
    assert account["coverage_notes"]
    assert account["operations"]
    analyzer = identity_producer_observation("iam-access-analyzer-evidence-review")
    assert analyzer["evidence"]["payload"]["analyzers"]
    assert analyzer["evidence"]["payload"]["findings"]
    center = identity_producer_observation("iam-identity-center-visibility-review")
    permission = center["evidence"]["payload"]["instances"][0]["permission_sets"][0]
    assert permission["managed_policy_arns"]
    assert permission["customer_managed_policy_names"]
    assert center["coverage_notes"]
    coverage = identity_producer_observation("aws-security-service-coverage-review")
    assert {r["service_name"] for r in coverage["evidence"]["payload"]["records"]} == {"CloudTrail", "AWS Config", "GuardDuty", "Security Hub"}
