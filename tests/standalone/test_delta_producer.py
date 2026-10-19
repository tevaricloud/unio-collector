"""Actual service-delta SDK producers through protection and completion."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import FIXTURES, producer_bundle
from tools.build_native_collector import _add_synthetic_region_scope
from tools.collector_delta_fixture import SCANNER, VARIANTS, delta_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.fixture(scope="module")
def delta_base_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Collect immutable shared input once; every case gets a fresh archive."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("delta-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_delta_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delta_base_files: dict[str, bytes], profile: str, variant: str) -> None:
    """Actual supported successes and isolated SDK failures remain truthful."""
    _case(tmp_path, monkeypatch, delta_base_files, profile, variant)


@pytest.mark.parametrize("mutation", ["root", "nested", "nested_null", "threshold", "flag", "version", "date", "currency", "missing", "list", "header"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_delta_unknown_and_malformed_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delta_base_files: dict[str, bytes], profile: str, mutation: str
) -> None:
    """Unknown descendants and malformed contracts reject before strict omission."""
    _case(tmp_path, monkeypatch, delta_base_files, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_packaged_delta_unknown_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, delta_base_files: dict[str, bytes], profile: str) -> None:
    """Drive the actual packaged smoke enrichment switch and negative input."""
    _case(tmp_path, monkeypatch, delta_base_files, profile, "pagination", "native")


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: dict[str, bytes], profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = delta_producer_observation(variant)
    _verify_actual(observed, variant)
    row = observed["evidence"]
    if mutation and mutation != "native":
        _mutate(row, mutation)
    files = dict(base)
    add_scanner_producer_payload(files, row, scanner_id=SCANNER, execution=observed["execution"])
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    source = tmp_path / "delta.zip"
    with ZipFile(source, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    if mutation == "native":
        _add_synthetic_region_scope(source, FIXTURES / "region-scope.json", unknown_delta_field=True)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    assert main(["validate-bundle", str(source)]) == 0
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-delta-only\n"))
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
        records = json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        protected = next((r["payload"] for r in records if r["scanner_id"] == SCANNER), None)
        results = json.loads(archive.read("scan-result/scanner-results.json"))["scanner_results"]
        result = next(r for r in results if r["scanner_id"] == SCANNER)
        assert result["status"] == observed["execution"]["status"]
        assert result["evidence_count"] == observed["execution"]["evidence_count"]
    if row is None:
        assert protected is None
        if profile == "strict":
            assert result["errors"] == []
        else:
            assert result["errors"]
        assert result["limitations"]
    else:
        assert isinstance(protected, dict)
        _verify_financial(row["payload"], protected, profile)


def _mutate(row: dict[str, Any], mutation: str) -> None:
    payload = row["payload"]
    record = payload["result"]["service_costs"][0]
    if mutation == "root":
        payload["unknown_delta_control"] = {}
    elif mutation.startswith("nested"):
        record["unknown_delta_control"] = None if mutation == "nested_null" else {}
    elif mutation == "threshold":
        payload["absolute_threshold"] = "NaN"
    elif mutation == "flag":
        payload["absolute_threshold_supplied"] = "true"
    elif mutation == "version":
        payload["analysis_inputs_version"] = True
    elif mutation == "date":
        payload["result"]["current_period"]["start_date"] = "2026-09-99"
    elif mutation == "currency":
        record["currency"] = None
    elif mutation == "missing":
        record.pop("current_cost")
    elif mutation == "list":
        payload["result"]["service_costs"] = None
    else:
        row["evidence_type"] = "UntrustedCostDeltaType"


def _verify_actual(observed: dict[str, Any], variant: str) -> None:
    """No successful DTO is invented for unsupported provider-failure shapes."""
    execution = observed["execution"]
    assert [event["event_type"] for event in observed["events"]] == ["scanner_started", "scanner_completed"]
    assert observed["events"][0]["event_type"] == "scanner_started"
    assert observed["events"][1]["event_type"] == "scanner_completed"
    assert observed["events"][1]["scanner_status"] == execution["status"]
    if variant in {"denied", "unavailable", "unsupported", "failure", "interrupted"}:
        assert observed["evidence"] is None
        assert execution["evidence_count"] == 0
        assert execution["status"] == ("permission_denied" if variant == "denied" else "failed")
        assert execution["errors"]
    else:
        assert execution["status"] == "completed"
        assert execution["evidence_count"] == 1
        payload = observed["evidence"]["payload"]
        assert len(payload["result"]["service_costs"]) == (0 if variant == "empty" else 2)
        assert len(observed["calls"]) == (4 if variant == "pagination" else 2)
        if variant == "deferred_missing":
            assert payload["analysis_inputs_version"] == 1
            assert payload["absolute_threshold_supplied"] is False
            assert payload["percent_threshold_supplied"] is False


def _verify_financial(original: dict[str, Any], protected: dict[str, Any], profile: str) -> None:
    """Keep standard financial meaning and strict precision limitations distinct."""
    assert "Synthetic customer service" not in json.dumps(protected)
    for key in ("absolute_threshold", "percent_threshold"):
        assert protected[key] == ("" if profile == "strict" else original[key])
    for period in ("previous_period", "current_period"):
        expected = original["result"][period]
        actual = protected["result"][period]
        assert actual["total_cost"] == ("" if profile == "strict" else expected["total_cost"])
        assert actual["currency"] == ("" if profile == "strict" else expected["currency"])
    if profile == "strict":
        assert protected["result"]["service_costs"] is None
        return
    for expected, actual in zip(original["result"]["service_costs"], protected["result"]["service_costs"], strict=True):
        assert actual["previous_cost"] == ("" if profile == "strict" else expected["previous_cost"])
        assert actual["current_cost"] == ("" if profile == "strict" else expected["current_cost"])
        if profile == "strict":
            assert actual["region"] == "aws-region"
            assert actual["service_name"] != expected["service_name"]
