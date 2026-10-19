"""Actual populated key/control producers through protection and final receipt gates."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import fields
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_key_fixture import COLLECTORS, VARIANTS, key_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit_cost.kms.key_evidence import KmsKeyEvidence
from unio_collector.aws.audit_cost.kms.record import KmsCostGovernanceRecord
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.key_controls.fields import CONTROL_SUMMARY, ENCRYPTION, KMS_COST, KMS_POSTURE
from unio_collector.scanners.ec2.ebs.encryption_region import EbsEncryptionRegionRecord
from unio_collector.scanners.ec2.ebs.snapshot_encryption import EbsSnapshotEncryptionRecord
from unio_collector.scanners.ec2.ebs.volume_encryption import EbsVolumeEncryptionRecord
from unio_collector.scanners.kms.cost_governance.evidence import KmsCostGovernanceEvidence
from unio_collector.scanners.kms.key_posture.evidence import KmsKeyPostureEvidence
from unio_collector.scanners.kms.key_posture.record import KmsKeyPostureRecord
from unio_collector.scanners.s3.encryption.bucket_record import S3BucketEncryptionRecord
from unio_collector.scanners.security_governance.encryption.evidence import EncryptionBaselineEvidence
from unio_collector.scanners.security_governance.security_hub.control_record import SecurityHubControlRecord
from unio_collector.scanners.security_governance.security_hub.summary.evidence import SecurityHubControlSummaryEvidence

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_key_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str) -> None:
    """Exercise real wrappers, callback mirrors, validation and verified receipts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, variant)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "nested_null", "nested_boolean", "nested"])
def test_key_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, mutation: str) -> None:
    """Unknown nulls, booleans and containers reject with no completion artifacts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_key_execution_note_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Unknown nested counters in the actual KMS callback block protection."""
    _bundle_case(tmp_path, monkeypatch, "kms-cost-governance-review", profile, "success", "note")


def _bundle_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    observed = key_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    if mutation and mutation not in {"note", "limit"}:
        records = payload.get("records", payload.get("keys", payload.get("ebs_volumes")))
        target = payload if mutation == "root" else records[0]
        if mutation.startswith("nested"):
            target = records[0]["raw_keys"][0] if scanner == "kms-cost-governance-review" else records[0]
        target["unknown_key_control"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result_record = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    result_record["coverage_notes"] = observed["coverage_notes"]
    result_record["warnings"] = observed["warnings"]
    if mutation == "note":
        next(note for note in result_record["coverage_notes"] if note["note_type"] == "execution_detail")["detail_counts"]["unknown_key_control"] = None
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
        assert "123.45" not in encoded
        assert "2026-01-02" not in encoded
        assert set(protected["regions"]) == {"aws-region"}
        for record in protected.get("records", protected.get("keys", protected.get("ebs_volumes", []))):
            assert record["region"] == "aws-region"
            if "home_region" in record:
                assert record["home_region"] in (None, "aws-region")


@pytest.mark.parametrize(
    ("mapping", "prefix", "dto"),
    [
        (KMS_COST, "", KmsCostGovernanceEvidence),
        (KMS_COST, "records[].", KmsCostGovernanceRecord),
        (KMS_COST, "records[].raw_keys[].", KmsKeyEvidence),
        (KMS_POSTURE, "", KmsKeyPostureEvidence),
        (KMS_POSTURE, "keys[].", KmsKeyPostureRecord),
        (ENCRYPTION, "", EncryptionBaselineEvidence),
        (ENCRYPTION, "ebs_region_settings[].", EbsEncryptionRegionRecord),
        (ENCRYPTION, "ebs_volumes[].", EbsVolumeEncryptionRecord),
        (ENCRYPTION, "ebs_snapshots[].", EbsSnapshotEncryptionRecord),
        (ENCRYPTION, "s3_buckets[].", S3BucketEncryptionRecord),
        (CONTROL_SUMMARY, "", SecurityHubControlSummaryEvidence),
        (CONTROL_SUMMARY, "records[].", SecurityHubControlRecord),
    ],
)
def test_key_dto_inventory(mapping: dict, prefix: str, dto: type) -> None:
    """Independent DTO additions fail even if fixture and classifier were simplified."""
    declared = {p[len(prefix) :] for p in mapping if p.startswith(prefix) and p[len(prefix) :] and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
    assert declared == {field.name for field in fields(dto)}
