"""Actual audit-service producer branches through final protected bundle gates."""

from __future__ import annotations

import copy
import hashlib
import io
import json
from dataclasses import fields
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from tools.collector_audit_fixture import COLLECTORS, VARIANTS, audit_producer_case, audit_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit_cost.cloudtrail.record import CloudTrailCostGovernanceRecord
from unio_collector.aws.audit_cost.cloudtrail.selector_evidence import CloudTrailSelectorEvidence
from unio_collector.aws.audit_cost.cloudtrail.store_evidence import CloudTrailEventDataStoreEvidence
from unio_collector.aws.audit_cost.secrets_manager.record import SecretsManagerCostGovernanceRecord
from unio_collector.aws.audit_cost.secrets_manager.secret_evidence import SecretEvidence
from unio_collector.aws.xray.cost.signal import XRayCostSignal
from unio_collector.aws.xray.region_record import XRayRegionRecord
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.audit.fields import SECRETS, SELECTOR, TRAIL_COST, TRAIL_SECURITY, XRAY
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.scanners.audit_cost.cloudtrail.cost.evidence import CloudTrailCostGovernanceEvidence
from unio_collector.scanners.audit_cost.cloudtrail.security.evidence import CloudTrailSecurityPostureEvidence
from unio_collector.scanners.audit_cost.cloudtrail.trail_record import CloudTrailSecurityTrailRecord
from unio_collector.scanners.security_governance.secrets_manager.evidence import SecretsManagerCostGovernanceEvidence
from unio_collector.scanners.xray.cost_evidence import XRayCostGovernanceEvidence

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_audit_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str) -> None:
    """Real populated producers pass protection, independent validation and receipts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, variant)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "nested", "nested_null", "nested_boolean"])
def test_audit_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, mutation: str) -> None:
    """Unknown descendants including null and empty containers reject atomically."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", mutation)


@pytest.mark.parametrize("scanner", ["secrets-manager-cost-governance-review", "cloudtrail-cost-governance-review"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_audit_note_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str) -> None:
    """Actual callback notes reject undeclared null counters without completed artifacts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", "note")


def _bundle_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    observed = audit_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    if mutation and mutation != "note":
        records = payload.get("records", payload.get("trails"))
        target = payload if mutation == "root" else records[0]
        if mutation.startswith("nested"):
            target = (
                target["raw_secrets"][0]
                if scanner.startswith("secrets")
                else target["raw_selectors"][1]["field_conditions"][0]
                if scanner.startswith("cloudtrail-cost")
                else payload["cost_signal"]
                if scanner.startswith("xray")
                else records[0]
            )
        target["unknown_audit_field"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result_record = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    result_record["coverage_notes"] = observed["coverage_notes"]
    result_record["warnings"] = observed["warnings"]
    if mutation == "note":
        result_record["coverage_notes"][0]["detail_counts"]["unknown_audit_field"] = None
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
        for record in protected.get("records", protected.get("trails", [])):
            assert record["region"] == "aws-region"
            if "home_region" in record:
                assert record["home_region"] in (None, "aws-region")


@pytest.mark.parametrize(
    ("mapping", "prefix", "dto"),
    [
        (SECRETS, "", SecretsManagerCostGovernanceEvidence),
        (SECRETS, "records[].", SecretsManagerCostGovernanceRecord),
        (SECRETS, "records[].raw_secrets[].", SecretEvidence),
        (TRAIL_COST, "", CloudTrailCostGovernanceEvidence),
        (TRAIL_COST, "records[].", CloudTrailCostGovernanceRecord),
        (TRAIL_COST, "records[].raw_event_data_stores[].", CloudTrailEventDataStoreEvidence),
        (SELECTOR, "", CloudTrailSelectorEvidence),
        (TRAIL_SECURITY, "", CloudTrailSecurityPostureEvidence),
        (TRAIL_SECURITY, "trails[].", CloudTrailSecurityTrailRecord),
        (XRAY, "", XRayCostGovernanceEvidence),
        (XRAY, "records[].", XRayRegionRecord),
        (XRAY, "cost_signal.", XRayCostSignal),
    ],
)
def test_audit_dto_inventory(mapping: dict, prefix: str, dto: type) -> None:
    """DTO additions fail independently of fixture omissions or registry rewrites."""
    declared = {
        path[len(prefix) :]
        for path in mapping
        if path.startswith(prefix) and path[len(prefix) :] and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
    }
    assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_audit_identity_rejection(scanner: str) -> None:
    """Conflicting legacy module identities reject before payload traversal."""
    row = copy.deepcopy(audit_producer_case(scanner))
    row["evidence_module"] = "untrusted.module"
    with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
