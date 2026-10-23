"""Actual collector minimisation explanations remain protected across mirrors."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector.minimisation import EvidenceMinimisationOptions
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.producer_fields import unknown_producer_paths

pytestmark = pytest.mark.offline
FIXTURE = Path(__file__).parent / "fixtures/cost.json"


def _collect(target: Path) -> Path:
    source = target / "source.zip"
    assert main(["collect", "--fixture", str(FIXTURE), "--output", str(source), "--no-cost-data", "--quiet"]) == 0
    return source


def _protect(source: Path, target: Path, profile: str, monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-test-only-input\n"))
    return main(
        [
            "privacy",
            "protect",
            "--bundle",
            str(source),
            "--output",
            str(target / "protected.zip"),
            "--vault",
            str(target / "vault.json"),
            "--profile",
            profile,
            "--passphrase-stdin",
            "--acknowledge-vault-loss-risk",
        ]
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_no_cost_collection_protects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """The actual duplicated producer reason must not survive as plaintext."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = _collect(tmp_path)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    reason = EvidenceMinimisationOptions(no_cost_data=True).build_limitations()[0]["reason"]
    assert isinstance(reason, str)
    with ZipFile(source) as archive:
        assert json.loads(archive.read("evidence/cost-explorer.json"))["limitations"][0]["reason"] == reason
    assert _protect(source, tmp_path, profile, monkeypatch) == 0
    output = tmp_path / "protected.zip"
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    with ZipFile(output) as archive:
        assert reason not in archive.read("evidence/cost-explorer.json").decode()
        assert json.loads(archive.read("privacy/leak-scan-summary.json"))["findings"] == []
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


@pytest.mark.parametrize(("field", "value"), [("type", "unknown"), ("service", "other-service"), ("reason", None), ("unknown_nested", {})])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_no_cost_unknown_or_malformed_rejects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object, profile: str) -> None:
    """Finite metadata and unknown descendants reject before strict treatment."""
    source = _collect(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    payload = json.loads(files["evidence/cost-explorer.json"])
    payload["limitations"][0][field] = value
    files["evidence/cost-explorer.json"] = json.dumps(payload).encode()
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    with ZipFile(source, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    assert _protect(source, tmp_path, profile, monkeypatch) == 1
    assert not (tmp_path / "protected.zip").exists()
    assert not (tmp_path / "protected.zip.receipt.json").exists()
    assert not (tmp_path / "vault.json").exists()
    assert not list(tmp_path.rglob("*.tmp"))
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def test_actual_minimisation_variants_have_closed_contract() -> None:
    """Every emitted variant is typed; arbitrary explanations remain free text."""
    options = EvidenceMinimisationOptions(no_cost_data=True, exclude_services=("cost-explorer",), redact_before_export=True, minimise_export="summary")
    limitations = options.build_limitations()
    assert {row["type"] for row in limitations} == {"service_excluded", "cost_data_excluded", "redacted_before_export", "minimised_export"}
    assert unknown_producer_paths({"limitations": limitations}, "evidence/cost-explorer.json") == []
    assert (
        unknown_producer_paths(
            {"limitations": [{"type": "cost_data_excluded", "service": "cost-explorer", "reason": "Synthetic customer 123456789012"}]},
            "evidence/cost-explorer.json",
        )
        == []
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_no_cost_collect_protected_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Exercise the failed installed-wheel subcommand, not only protect-existing."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    output = tmp_path / "protected.zip"
    assert (
        main(
            [
                "collect-protected",
                "--fixture",
                str(FIXTURE),
                "--output",
                str(output),
                "--vault",
                str(tmp_path / "vault.json"),
                "--recovery-mode",
                "recovery-key",
                "--recovery-key",
                str(tmp_path / "recovery.key"),
                "--privacy-profile",
                profile,
                "--no-cost-data",
                "--token-scope",
                "engagement",
                "--engagement-id",
                "synthetic-engagement",
                "--acknowledge-vault-loss-risk",
                "--quiet",
                "--json",
            ]
        )
        == 0
    )
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    with ZipFile(output) as archive:
        assert json.loads(archive.read("privacy/leak-scan-summary.json"))["findings"] == []
