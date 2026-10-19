"""Full bundle publication and cleanup for actual populated Bedrock producers."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from tools.build_native_collector import _add_synthetic_region_scope
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

pytestmark = pytest.mark.offline
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("unknown", [False, True])
def test_actual_bedrock_bundle_protection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], profile: str, *, unknown: bool
) -> None:
    """Use the exact native smoke input; validate independently or publish nothing."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    source = tmp_path / "input.zip"
    assert main(["collect", "--fixture", str(FIXTURES / "cost.json"), "--output", str(source), "--quiet"]) == 0
    _add_synthetic_region_scope(source, FIXTURES / "region-scope.json")

    _add_synthetic_region_scope(source, FIXTURES / "region-scope.json")
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    evidence = json.loads(files["scan-result/scanner-evidence.json"])
    assert sum(row["scanner_id"] == "bedrock-cost-review" for row in evidence["scanner_evidence"]) == 1
    results = json.loads(files["scan-result/scanner-results.json"])["scanner_results"]
    assert sum(row["scanner_id"] == "bedrock-cost-review" for row in results) == 1
    for scanner in (
        "secrets-manager-cost-governance-review",
        "cloudtrail-cost-governance-review",
        "cloudtrail-security-posture-review",
        "xray-tracing-cost-governance-review",
    ):
        actual = next(row["payload"] for row in evidence["scanner_evidence"] if row["scanner_id"] == scanner)
        assert len(actual.get("records", actual.get("trails", []))) >= 5  # noqa: PLR2004
        metadata = next(row for row in results if row["scanner_id"] == scanner)
        if scanner in {"secrets-manager-cost-governance-review", "cloudtrail-cost-governance-review"}:
            assert len(metadata["coverage_notes"]) == 10  # noqa: PLR2004
        if scanner == "cloudtrail-security-posture-review":
            assert metadata["warnings"]
            assert actual["warnings"]
    for scanner in (
        "config-cost-governance-review",
        "guardduty-cost-governance-review",
        "securityhub-inspector-macie-cost-review",
        "waf-cost-governance-review",
    ):
        actual = next(row["payload"] for row in evidence["scanner_evidence"] if row["scanner_id"] == scanner)
        assert len(actual["records"]) >= 5  # noqa: PLR2004
        metadata = next(row for row in results if row["scanner_id"] == scanner)
        assert len(metadata["coverage_notes"]) >= 12  # noqa: PLR2004
    _assert_key_smoke(evidence, results)
    _assert_identity_smoke(evidence, results)
    bedrock = next(row for row in evidence["scanner_evidence"] if row["scanner_id"] == "bedrock-cost-review")
    assert len(bedrock["payload"]["records"]) == 5  # noqa: PLR2004
    if unknown:
        bedrock["payload"]["records"][0]["top_usage_type_costs"][0]["unknown_synthetic_field"] = {}
        files["scan-result/scanner-evidence.json"] = json.dumps(evidence).encode()
        checksums = build_checksums(files)
        manifest = json.loads(files["manifest.json"])
        manifest["checksums"] = checksums
        files["manifest.json"] = json.dumps(manifest).encode()
        files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
        with ZipFile(source, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
        _add_synthetic_region_scope(source, FIXTURES / "region-scope.json", unknown_audit_field=True)
    assert main(["validate-bundle", str(source)]) == 0
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
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
    assert code == (1 if unknown else 0)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    if unknown:
        diagnostics = "".join(capsys.readouterr().out.split())
        for field in ("unknown_secrets_audit", "unknown_cloudtrail_cost", "unknown_cloudtrail_security", "unknown_xray_audit"):
            assert field in diagnostics
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
    else:
        assert main(["validate-bundle", str(output)]) == 0
        inspected = ProtectedBundleInspector().inspect(output)
        assert inspected.validation_passed
        receipt = inspected.summary["receipt"]
        assert isinstance(receipt, dict)
        assert receipt["verified"]
        with ZipFile(output) as archive:
            protected = archive.read("scan-result/scanner-evidence.json").decode()
        assert "synthetic-customer-model" not in protected
        if profile == "strict":
            assert "17.25" not in protected


def _assert_key_smoke(evidence: dict, results: list) -> None:
    """Require actual populated conditional key records and mirrored callbacks."""
    for scanner, collection in (
        ("kms-cost-governance-review", "records"),
        ("kms-key-posture-review", "keys"),
        ("encryption-baseline-review", "ebs_volumes"),
        ("securityhub-control-summary-review", "records"),
    ):
        actual = next(row["payload"] for row in evidence["scanner_evidence"] if row["scanner_id"] == scanner)
        assert len(actual[collection]) >= 5  # noqa: PLR2004
        metadata = next(row for row in results if row["scanner_id"] == scanner)
        if scanner == "kms-cost-governance-review":
            assert actual["records"][0]["raw_keys"]
            assert len(metadata["coverage_notes"]) == 15  # noqa: PLR2004
        else:
            assert actual["warnings"]
            assert metadata["warnings"]


def _assert_identity_smoke(evidence: dict, results: list) -> None:
    """Assert the packaged input contains actual populated IAM and service shapes."""
    for scanner, key in (
        ("iam-account-security-review", "users"),
        ("iam-access-analyzer-evidence-review", "analyzers"),
        ("iam-identity-center-visibility-review", "instances"),
        ("aws-security-service-coverage-review", "records"),
    ):
        payload = next(row["payload"] for row in evidence["scanner_evidence"] if row["scanner_id"] == scanner)
        assert len(payload[key]) >= 5  # noqa: PLR2004
        metadata = next(row for row in results if row["scanner_id"] == scanner)
        assert payload["warnings"]
        assert metadata["warnings"]
        if scanner == "iam-account-security-review":
            assert payload["users"][0]["access_keys"]
            assert any(row["policy_document"] for row in payload["policy_grants"])
            assert metadata["coverage_notes"]
        if scanner == "iam-identity-center-visibility-review":
            assert payload["instances"][0]["permission_sets"][0]["customer_managed_policy_names"]
            assert metadata["coverage_notes"]
