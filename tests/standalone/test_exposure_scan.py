"""Actual exposure contracts retain customer leak rejection and strict boundaries."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_exposure.fixture import COLLECTORS, exposure_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_exposure_customer_collision(scanner: str, profile: str) -> None:
    """Finite public controls never exempt plaintext in customer identifier fields."""
    row = exposure_producer_observation(scanner, "success" if scanner == "root-account-recovery-advisory" else "collision")["evidence"]
    original = {
        "root-account-recovery-advisory": "123456789012",
        "ecr-image-scan-posture-review": "ENHANCED",
        "public-service-exposure-review": "application",
        "ec2-security-group-exposure-review": "tcp",
    }[scanner]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    leak = ProtectedArchiveLeakScanner()
    assert leak.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed
    payload = result["scanner_evidence"][0]["payload"]
    container, key = {
        "ec2-security-group-exposure-review": ("public_ingress_rules", "group_name"),
        "ecr-image-scan-posture-review": ("repositories", "repository_name"),
        "public-service-exposure-review": ("records", "resource_name"),
        "root-account-recovery-advisory": (None, "account_id"),
    }[scanner]
    target = payload[container][0] if container else payload
    assert original != target[key]
    target[key] = original
    assert not leak.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={original}).passed


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("identity", ["evidence_module", "evidence_type", "provider_id", "evidence_schema_id"])
def test_exposure_conflicting_identity(scanner: str, identity: str) -> None:
    """A familiar scanner ID does not admit foreign DTO/provider/schema identity."""
    row = exposure_producer_observation(scanner)["evidence"]
    row[identity] = "untrusted"
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [True, -2, 65536, "443", {}])
def test_ingress_malformed_port(profile: str, value: object) -> None:
    """Port controls are bounded integers, never booleans or private free text."""
    row = exposure_producer_observation("ec2-security-group-exposure-review")["evidence"]
    row["payload"]["public_ingress_rules"][0]["from_port"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, True, "customer", "256", "tcp.customer"])
def test_ingress_unknown_protocol(profile: str, value: object) -> None:
    """Malformed protocols cannot borrow finite public-control treatment."""
    row = exposure_producer_observation("ec2-security-group-exposure-review")["evidence"]
    row["payload"]["public_ingress_rules"][0]["protocol"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_exposure_wrong_service_metadata(profile: str) -> None:
    """Typed metadata from another record family is still an unknown field."""
    row = exposure_producer_observation("public-service-exposure-review")["evidence"]
    row["payload"]["records"][0]["metadata"]["type"] = "application"
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["parent", "scope", "counter", "unknown"])
def test_exposure_note_identity(profile: str, mutation: str) -> None:
    """Callback classification cannot migrate to foreign parents or malformed keys."""
    observed = exposure_producer_observation("ecr-image-scan-posture-review")
    note = observed["coverage_notes"][0]
    scanner = "ecr-image-scan-posture-review"
    if mutation == "parent":
        scanner = "ec2-security-group-exposure-review"
    elif mutation == "scope":
        note["scope_area"] = "unknown"
    elif mutation == "counter":
        note["repository_count"] = True
    else:
        note["unknown_exposure"] = None
    t = transformer(profile)
    t.transform({"scanner_results": [{"scanner_id": scanner, "coverage_notes": [note]}]}, file_name="scan-result/scanner-results.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_exposure_foreign_metadata_remains_scanned(profile: str) -> None:
    """A literal belonging to another service is plaintext at an unknown RDS path."""
    row = exposure_producer_observation("public-service-exposure-review")["evidence"]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    result["scanner_evidence"][0]["payload"]["records"][0]["metadata"]["type"] = "application"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"application"})
        .passed
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_exposure_port_identifier_collision(profile: str) -> None:
    """An actual security-group name equal to its public port remains protectable."""
    row = exposure_producer_observation("ec2-security-group-exposure-review", "port_collision")["evidence"]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"443"}).passed
    result["scanner_evidence"][0]["payload"]["public_ingress_rules"][0]["group_name"] = "443"
    assert (
        not ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"443"}).passed
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown", "malformed", "module", "provider", "text"])
def test_exposure_port_collision_still_rejects_leaks(profile: str, mutation: str) -> None:
    """Bounded port treatment cannot mask unknown fields, text or forged identities."""
    row = exposure_producer_observation("ec2-security-group-exposure-review", "port_collision")["evidence"]
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    record = result["scanner_evidence"][0]
    rule = record["payload"]["public_ingress_rules"][0]
    if mutation == "unknown":
        rule["unknown_port"] = "443"
    elif mutation == "malformed":
        rule["from_port"] = "443"
    elif mutation == "module":
        record["evidence_module"] = "untrusted"
    elif mutation == "provider":
        record["provider_id"] = "untrusted"
    else:
        rule["group_name"] += "443"
    assert (
        not ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(result), known_original_values={"443"}).passed
    )
