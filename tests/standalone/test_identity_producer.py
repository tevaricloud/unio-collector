"""Actual populated identity/security producers through protection and final receipt gates."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_identity_fixture import COLLECTORS, VARIANTS, identity_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_identity_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str) -> None:
    """Exercise real wrappers, callback mirrors, validation and verified receipts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, variant)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "nested_null", "nested_boolean", "nested"])
def test_identity_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, mutation: str) -> None:
    """Unknown nulls, booleans and containers reject with no completion artifacts."""
    _bundle_case(tmp_path, monkeypatch, scanner, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_identity_note_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Unknown nested counters in the actual IAM callback block protection."""
    _bundle_case(tmp_path, monkeypatch, "iam-account-security-review", profile, "success", "note")


def _bundle_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    observed = identity_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row["serialization_status"] == "serialized"
    payload = row["payload"]
    if mutation and mutation not in {"note", "limit", "policy"}:
        key = {
            "iam-account-security-review": "users",
            "iam-access-analyzer-evidence-review": "analyzers",
            "iam-identity-center-visibility-review": "instances",
            "aws-security-service-coverage-review": "records",
        }[scanner]
        records = payload[key]
        target = payload if mutation == "root" else records[0]
        if mutation.startswith("nested"):
            target = (
                records[0]["access_keys"][0]
                if scanner == "iam-account-security-review"
                else records[0]["permission_sets"][0]
                if scanner == "iam-identity-center-visibility-review"
                else records[0]
            )
        target["unknown_identity_control"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    if mutation == "policy":
        policy = next(g["policy_document"] for g in payload["policy_grants"] if g["policy_document"])
        policy["Statement"][0]["Condition"]["StringEquals"]["aws:UnknownCustomerField"] = "synthetic-customer"
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result_record = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    result_record["coverage_notes"] = observed["coverage_notes"]
    result_record["warnings"] = observed["warnings"]
    if mutation == "note":
        result_record["coverage_notes"][0]["unknown_identity_control"] = None
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
        _assert_strict_payload(scanner, protected, encoded)


def _assert_strict_payload(scanner: str, protected: dict, encoded: str) -> None:
    """Require every declared strict timestamp and regional field treatment."""
    assert "123.45" not in encoded
    assert "2026-01-02" not in encoded
    if scanner == "iam-access-analyzer-evidence-review":
        assert set(protected["regions"]) == {"aws-region"}
        for record in protected["analyzers"] + protected["findings"]:
            assert record["region"] == "aws-region"
    elif scanner == "aws-security-service-coverage-review":
        assert set(protected["regions"]) == {"aws-region"}
        for record in protected["records"]:
            assert record["region"] == "aws-region"
    elif scanner == "iam-account-security-review":
        assert "regions" not in protected
        for user in protected["users"]:
            for access_key in user["access_keys"]:
                assert access_key["last_used_region"] in (None, "aws-region")
    else:
        assert scanner == "iam-identity-center-visibility-review"
        assert "regions" not in protected


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_identity_policy_unknown_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Unknown populated inline-policy conditions leave no completion artifacts."""
    _bundle_case(tmp_path, monkeypatch, "iam-account-security-review", profile, "full", "policy")
