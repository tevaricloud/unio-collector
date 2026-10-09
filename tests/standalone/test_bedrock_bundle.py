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
def test_actual_bedrock_bundle_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, *, unknown: bool) -> None:
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
