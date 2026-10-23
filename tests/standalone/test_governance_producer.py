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
from tools.collector_governance.fixture import COLLECTORS, VARIANTS, governance_producer_case, governance_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit_cost.config.record import ConfigCostGovernanceRecord
from unio_collector.aws.audit_cost.guardduty.record import GuardDutyCostGovernanceRecord
from unio_collector.aws.audit_cost.security_services.record import SecurityHubInspectorMacieCostGovernanceRecord
from unio_collector.aws.audit_cost.waf.record import WafCostGovernanceRecord
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.audit.governance.fields import CONFIG, GUARDDUTY, SECURITY, WAF
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.scanners.config.cost_governance.evidence import ConfigCostGovernanceEvidence
from unio_collector.scanners.security_governance.guardduty.evidence import GuardDutyCostGovernanceEvidence
from unio_collector.scanners.security_governance.securityhub_inspector_macie.evidence import SecurityHubInspectorMacieCostGovernanceEvidence
from unio_collector.scanners.security_governance.waf.evidence import WafCostGovernanceEvidence

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_governance_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str) -> None:
    """Real populated producers pass protection, independent validation and receipts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, variant)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "nested", "nested_null", "nested_boolean"])
def test_governance_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, mutation: str) -> None:
    """Unknown descendants including null and empty containers reject atomically."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", mutation)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_note_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str) -> None:
    """Actual callback notes reject undeclared null counters without completed artifacts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", "note")


def _bundle_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    observed = governance_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    if mutation and mutation not in {"note", "limit"}:
        records = payload.get("records", payload.get("trails"))
        target = payload if mutation == "root" else records[0]
        if mutation.startswith("nested"):
            target = (
                target["feature_status_counts"]
                if scanner.startswith("guardduty")
                else target["macie_job_status_counts"]
                if scanner.startswith("securityhub")
                else records[0]
            )
        target["unknown_governance_field"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result_record = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    result_record["coverage_notes"] = observed["coverage_notes"]
    result_record["warnings"] = observed["warnings"]
    if mutation == "note":
        next(note for note in result_record["coverage_notes"] if note["note_type"] == "execution_detail")["detail_counts"]["unknown_governance_field"] = None
    if mutation == "limit":
        next(note for note in result_record["coverage_notes"] if note["note_type"] == "configuration_limit")["unknown_governance_field"] = {}
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
        (CONFIG, "", ConfigCostGovernanceEvidence),
        (CONFIG, "records[].", ConfigCostGovernanceRecord),
        (GUARDDUTY, "", GuardDutyCostGovernanceEvidence),
        (GUARDDUTY, "records[].", GuardDutyCostGovernanceRecord),
        (SECURITY, "", SecurityHubInspectorMacieCostGovernanceEvidence),
        (SECURITY, "records[].", SecurityHubInspectorMacieCostGovernanceRecord),
        (WAF, "", WafCostGovernanceEvidence),
        (WAF, "records[].", WafCostGovernanceRecord),
    ],
)
def test_governance_dto_inventory(mapping: dict, prefix: str, dto: type) -> None:
    """DTO additions fail independently of fixture omissions or registry rewrites."""
    declared = {
        path[len(prefix) :]
        for path in mapping
        if path.startswith(prefix) and path[len(prefix) :] and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
    }
    assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_governance_identity_rejection(scanner: str) -> None:
    """Conflicting legacy module identities reject before payload traversal."""
    row = copy.deepcopy(governance_producer_case(scanner))
    row["evidence_module"] = "untrusted.module"
    with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("scanner", ["config-cost-governance-review", "waf-cost-governance-review"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_limit_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str) -> None:
    """Actual summary-mode callbacks reject unknown descendants before success."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "summary", "limit")


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_governance_packaged_unknown_recipe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], profile: str) -> None:
    """The exact expanded future native negative input rejects all four actual producers."""
    from subprocess import CompletedProcess  # noqa: PLC0415

    from tools.build_native_collector import _add_synthetic_region_scope, _verify_unknown_smoke  # noqa: PLC0415

    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    from pathlib import Path  # noqa: PLC0415

    fixture = Path(__file__).parent / "fixtures/region-scope.json"
    namespace = _add_synthetic_region_scope(source, fixture, unknown_governance_field=True)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    source.rename(tmp_path / "unknown-governance.zip")
    output = tmp_path / f"unknown-governance-{profile}.zip"
    vault = tmp_path / f"private-unknown-governance-{profile}/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    code = main(
        [
            "privacy",
            "protect",
            "--bundle",
            str(tmp_path / "unknown-governance.zip"),
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
    assert code == 1
    completed = CompletedProcess(args=[], returncode=code, stdout=capsys.readouterr().out, stderr="")
    _verify_unknown_smoke(tmp_path, "governance-" + profile, completed, digest, namespace)
