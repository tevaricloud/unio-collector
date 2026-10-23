"""Actual populated SDK recommendations through offline protection and receipts."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_recommendation.fixture import CASE_VARIANTS, COLLECTORS, recommendation_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
EXPECTED_RDS_BRANCHES = 2
CASES = [(scanner, variant) for scanner in COLLECTORS for variant in CASE_VARIANTS[scanner]]


@pytest.fixture(scope="module")
def recommendation_base_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Collect immutable actual shared input once, retaining all earlier producer cases."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("recommendations"))) as archive:
        return {n: archive.read(n) for n in archive.namelist()}


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(("scanner", "variant"), CASES)
def test_actual_recommendation_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recommendation_base_files: dict[str, bytes], scanner: str, variant: str, profile: str
) -> None:
    """Every supported SDK/nullable/limitation branch verifies without invented success."""
    _case(tmp_path, monkeypatch, recommendation_base_files, scanner, variant, profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("mutation", ["root", "nested", "null_unknown", "count", "count_null", "summary", "money", "enum", "sibling_kind", "header", "missing"])
def test_recommendation_unknown_malformed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recommendation_base_files: dict[str, bytes], scanner: str, profile: str, mutation: str
) -> None:
    """Unknown financial descendants and malformed controls reject before strict omission."""
    _case(tmp_path, monkeypatch, recommendation_base_files, scanner, "success", profile, mutation)


def _case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: dict[str, bytes], scanner: str, variant: str, profile: str, mutation: str | None = None
) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = recommendation_producer_observation(scanner, variant)
    row = observed["evidence"]
    _verify_observation(scanner, variant, observed)
    if mutation:
        _mutate(row, scanner, mutation)
    files = dict(base)
    add_scanner_producer_payload(files, row, execution=observed["execution"])
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    source = tmp_path / "input.zip"
    with ZipFile(source, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    assert main(["validate-bundle", str(source)]) == 0
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-recommendation-only\n"))
    code = main(
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
    assert code == (1 if mutation else 0)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    if mutation:
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
        return
    assert main(["validate-bundle", str(output)]) == 0
    inspection = ProtectedBundleInspector().inspect(output)
    assert inspection.validation_passed
    receipt = inspection.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    leak_scan = inspection.summary["leak_scan"]
    assert isinstance(leak_scan, dict)
    assert leak_scan["passed"]
    assert leak_scan["findings"] == []
    with ZipFile(output) as archive:
        rows = json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        protected = next(r["payload"] for r in rows if r["scanner_id"] == scanner)
        results = json.loads(archive.read("scan-result/scanner-results.json"))["scanner_results"]
        execution = next(r for r in results if r["scanner_id"] == scanner)
        assert execution["status"] == observed["execution"]["status"]
    assert protected["status"] == row["payload"]["status"]
    assert protected["recommendation_count"] == len(row["payload"]["records"])
    for original, result in zip(row["payload"]["records"], protected["records"], strict=True):
        assert result["resource_id"] != original["resource_id"]
        assert result["estimated_monthly_savings"] == (
            "" if profile == "strict" and original["estimated_monthly_savings"] is not None else original["estimated_monthly_savings"]
        )
        assert result["currency"] == ("" if profile == "strict" and original["currency"] is not None else original["currency"])
        assert result["region"] == ("aws-region" if profile == "strict" else original["region"])


def _mutate(row: dict[str, Any], scanner: str, mutation: str) -> None:
    payload = row["payload"]
    record = payload["records"][0]
    if mutation == "root":
        payload["unknown_recommendation_control"] = {}
    elif mutation in {"nested", "null_unknown"}:
        record["recommended_configuration"]["unknown_recommendation_control"] = None if mutation == "null_unknown" else {"customer": "synthetic"}
    elif mutation == "count":
        payload["metadata"]["record_budget_used"] = True
    elif mutation == "count_null":
        payload["recommendation_count"] = None
    elif mutation == "summary":
        payload["summaries"][0]["confidence"] = None
    elif mutation == "money":
        record["estimated_monthly_savings"] = "NaN"
    elif mutation == "enum":
        payload["status"] = "customer-unknown-status"
    elif mutation == "sibling_kind":
        record["recommended_configuration"]["instanceClass" if scanner.startswith("cost-") else "volumeBaselineIOPS"] = {"customer": "synthetic"}
    elif mutation == "header":
        row["evidence_type"] = "UntrustedRecommendationType"
    else:
        record.pop("resource_id")


def _verify_observation(scanner: str, variant: str, observed: dict[str, Any]) -> None:
    """Verify real operation and normalized producer contracts."""
    assert [event["event_type"] for event in observed["events"]] == ["scanner_started", "scanner_completed"]
    assert observed["events"][-1]["scanner_status"] == observed["execution"]["status"]
    assert observed["execution"]["evidence_count"] == 1
    payload = observed["evidence"]["payload"]
    assert payload["recommendation_count"] == len(payload["records"])
    assert payload["summary_count"] == len(payload["summaries"])
    expected = {
        "denied": "permission_limited",
        "not_enabled": "not_enabled",
        "unavailable": "unavailable",
        "unsupported": "unavailable",
        "failure": "unavailable",
        "missing_page": "unavailable",
        "missing_scope": "unavailable",
        "partial": "partial",
        "malformed_record": "partial",
        "malformed_identity": ("partial" if scanner.startswith("compute-") else "unavailable"),
        "capped": "capped",
        "oversized": "capped",
        "empty": "recorded_no_recommendations",
    }
    assert payload["status"] == expected.get(variant, "recorded")
    if variant == "missing_scope":
        assert observed["operations"] == []
    else:
        assert observed["operations"]
    if variant in {
        "denied",
        "not_enabled",
        "unavailable",
        "unsupported",
        "failure",
        "missing_page",
        "partial",
        "malformed_record",
        "malformed_identity",
        "capped",
        "oversized",
        "missing_scope",
    }:
        assert payload["warnings"]
    if variant == "success" and scanner.startswith("compute-"):
        assert {r["recommendation_type"] for r in payload["records"]} == {
            "ec2_instance",
            "ebs_volume",
            "lambda_function",
            "rds_database",
            "ecs_service",
            "idle",
        }
        assert all(r["estimated_monthly_savings"] == "12.25" for r in payload["records"])
        assert next(r for r in payload["records"] if r["recommendation_type"] == "rds_database")["finding"]
        rds = [r for r in payload["records"] if r["recommendation_type"] == "rds_database"]
        assert len(rds) == EXPECTED_RDS_BRANCHES
        assert any("storageConfiguration" in r["recommended_configuration"] for r in rds)
        assert any("dbInstanceClass" in r["recommended_configuration"] for r in rds)
