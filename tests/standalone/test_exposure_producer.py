"""Actual populated exposure/account-posture producers through protection and final receipt gates."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_exposure.fixture import CASE_VARIANTS, COLLECTORS, exposure_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
EXPECTED_PUBLIC_RULES = 4
EXPECTED_REGIONAL_RECORDS = 6
EXTRA_PROTOCOL_RULES = 5


@pytest.mark.parametrize(("scanner", "variant"), [(s, v) for s in COLLECTORS for v in CASE_VARIANTS[s]])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_exposure_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str) -> None:
    """Exercise real wrappers, callback mirrors, validation and verified receipts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, variant)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "nested_null", "nested_boolean", "nested"])
def test_exposure_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, mutation: str) -> None:
    """Unknown nulls, booleans and containers reject with no completion artifacts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_exposure_note_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Unknown callback metadata rejects without output, vault or receipt."""
    _bundle_case(tmp_path, monkeypatch, "ecr-image-scan-posture-review", profile, "success", "note")


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_shared_exposure_producer_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """The native/standalone shared input includes every supported producer variant."""
    _bundle_case(tmp_path, monkeypatch, "root-account-recovery-advisory", profile, "success", aggregate=True)


def _bundle_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str, mutation: str | None = None, *, aggregate: bool = False
) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    if aggregate:
        _assert_shared_fixture(files)
    observed = exposure_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    if mutation and mutation != "note":
        keys = {
            "ec2-security-group-exposure-review": "public_ingress_rules",
            "ecr-image-scan-posture-review": "repositories",
            "public-service-exposure-review": "records",
        }
        target = payload
        if mutation != "root" and scanner in keys:
            target = payload[keys[scanner]][0]
            if scanner == "public-service-exposure-review":
                target = next(r for r in payload["records"] if r["metadata"])["metadata"]
        target["unknown_exposure_control"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result_record = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    result_record["coverage_notes"] = observed["coverage_notes"]
    result_record["warnings"] = observed["warnings"]
    if mutation == "note":
        result_record["coverage_notes"][0]["unknown_exposure_control"] = None
    files["scan-result/scanner-results.json"] = json.dumps(results).encode()
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    with ZipFile(source, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    assert main(["validate-bundle", str(source)]) == 0
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    result = main(
        [
            "privacy",
            "protect",
            "--bundle",
            str(source),
            "--output",
            str(output),
            "--vault",
            str(vault),
            "--profile",
            profile,
            "--passphrase-stdin",
            "--acknowledge-vault-loss-risk",
        ]
    )
    assert result == (1 if mutation else 0)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    if mutation:
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
        return
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    leak_scan = inspected.summary["leak_scan"]
    assert isinstance(leak_scan, dict)
    assert leak_scan["passed"] is True
    assert leak_scan["findings"] == []
    with ZipFile(output) as archive:
        transformed = json.loads(archive.read("scan-result/scanner-evidence.json"))
    protected = next(r["payload"] for r in transformed["scanner_evidence"] if r["scanner_id"] == scanner)
    encoded = json.dumps(protected)
    assert "synthetic-customer" not in encoded
    assert "123456789012" not in encoded
    if profile == "strict":
        assert "eu-west-2" not in encoded
    _assert_actual_shape(scanner, variant, payload, observed)


def _assert_actual_shape(scanner: str, variant: str, payload: dict[str, Any], observed: dict[str, Any]) -> None:
    """Expect populated producer branches independently of the privacy registry."""
    if scanner == "root-account-recovery-advisory":
        assert observed["operations"] == []
        assert set(payload) == {"account_id"}
        return
    assert observed["operations"]
    assert set(payload["warnings"]) == set(observed["warnings"])
    if variant in {"denied", "unavailable", "unsupported", "failure", "partial"}:
        assert payload["warnings"]
    if variant in {"success", "collision", "protocols", "port_collision", "basic"}:
        _assert_populated_shape(scanner, variant, payload)
    if scanner == "ecr-image-scan-posture-review":
        note = observed["coverage_notes"][0]
        assert note["repository_count"] == len(payload["repositories"])
        assert note["registry_configuration_count"] == len(payload["registries"])
        assert note["warning_count"] == len(payload["warnings"])


def _assert_populated_shape(scanner: str, variant: str, payload: dict[str, Any]) -> None:
    """Assert independent expected populated branches, including zero and false."""
    if scanner == "ec2-security-group-exposure-review":
        expected = EXPECTED_PUBLIC_RULES + EXTRA_PROTOCOL_RULES if variant == "protocols" else EXPECTED_PUBLIC_RULES
        assert len(payload["public_ingress_rules"]) == expected
        if variant == "protocols":
            assert all(rule["name_contains_lightsail"] for rule in payload["public_ingress_rules"])
            assert {"udp", "icmp", "icmpv6", "0", "255"} <= {rule["protocol"] for rule in payload["public_ingress_rules"]}
    elif scanner == "public-service-exposure-review":
        assert len(payload["records"]) == EXPECTED_REGIONAL_RECORDS
        assert len(payload["global_records"]) == 1
    elif scanner == "ecr-image-scan-posture-review":
        assert len(payload["repositories"]) == len(payload["registries"]) == 1
        if variant == "basic":
            assert payload["repositories"][0]["scan_on_push"] is False
            assert payload["repositories"][0]["kms_key"] is None
            assert payload["registries"][0]["scan_type"] == "BASIC"
            assert payload["registries"][0]["rule_count"] == 0


def _assert_shared_fixture(files: dict[str, bytes]) -> None:
    """Independently assert newer variants did not disappear from distributed input."""
    rows = {row["scanner_id"]: row["payload"] for row in json.loads(files["scan-result/scanner-evidence.json"])["scanner_evidence"]}
    rules = rows["ec2-security-group-exposure-review"]["public_ingress_rules"]
    assert "443" in {rule["group_name"] for rule in rules}
    assert {"udp", "icmp", "icmpv6", "0", "255"} <= {rule["protocol"] for rule in rules}
    ecr = rows["ecr-image-scan-posture-review"]
    assert {"BASIC", "ENHANCED"} <= {record["scan_type"] for record in ecr["registries"]}
    assert any(record["scan_on_push"] is False for record in ecr["repositories"])
    assert any(record["scan_on_push"] is None for record in ecr["repositories"])
    assert rows["public-service-exposure-review"]["global_records"]
