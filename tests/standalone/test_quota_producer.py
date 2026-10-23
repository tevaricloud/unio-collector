"""Actual quota collection, serialization, protection and completion contracts."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from unittest.mock import patch
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import FIXTURES, producer_bundle
from tools.build_native_collector import _add_synthetic_region_scope
from tools.collector_quota_fixture import SCANNER, VARIANTS, quota_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.fixture(scope="module")
def quota_base_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Collect unchanged shared baseline once; each case has fresh actual producer data."""
    with (
        patch("boto3.session.Session.client", side_effect=AssertionError("AWS forbidden")),
        patch("boto3.session.Session.resource", side_effect=AssertionError("AWS forbidden")),
        ZipFile(producer_bundle(tmp_path_factory.mktemp("quota-base"))) as archive,
    ):
        return {name: archive.read(name) for name in archive.namelist()}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_quota_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quota_base_files: dict[str, bytes], profile: str, variant: str) -> None:
    """Actual facts, optional values and supported failure branches survive protection."""
    _case(tmp_path, monkeypatch, quota_base_files, profile, variant)


@pytest.mark.parametrize(
    "mutation", ["root", "nested", "nested_null", "nested_boolean", "quantity", "count", "status", "check", "method", "service", "date", "version"]
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_quota_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quota_base_files: dict[str, bytes], profile: str, mutation: str) -> None:
    """Unknown/type/value/cross-check failures reject before strict omissions."""
    _case(tmp_path, monkeypatch, quota_base_files, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_packaged_quota_unknown_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, quota_base_files: dict[str, bytes], profile: str) -> None:
    """Drive the exact native enrichment unknown switch, not a rewritten DTO."""
    _case(tmp_path, monkeypatch, quota_base_files, profile, "success", "native")


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base_files: dict[str, bytes], profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = quota_producer_observation(variant)
    row = observed["evidence"]
    payload = row["payload"]
    assert row["evidence_type"] == "dict"
    assert row["evidence_module"] == "builtins"
    expected = 0 if variant == "no_regions" else 12 if variant in {"partial", "region_failure"} else 6
    assert len(payload["quota_records"]) == expected
    assert payload["expected_record_count"] == payload["attempted_record_count"] == expected
    assert observed["coverage_notes"] == []
    if variant == "region_failure":
        assert len(observed["warnings"]) == 1
        assert "region discovery was unavailable (ValueError)" in observed["warnings"][0]
    else:
        assert observed["warnings"] == []
    if variant == "success":
        nat = next(r for r in payload["quota_records"] if r["resource_type"] == "NAT gateway")
        assert nat["quota_found"]
        assert nat["current_usage"] is None
        assert "zone evidence was missing" in nat["limitation"]
        assert all(c["operation"] != "describe_subnets" for c in observed["operations"])
    if variant == "empty":
        assert payload["status"] == "completed"
        assert all(r["current_usage"] == 0 for r in payload["quota_records"])
    if variant in {"partial", "denied", "unavailable", "unsupported", "failure", "malformed", "missing_quota", "nullable"}:
        assert payload["status"] == "completed_with_warnings"
        assert payload["unavailable_record_count"] > 0
    _verify_nullable_quota_names(payload, variant)
    if mutation and mutation != "native":
        _mutate(payload, mutation)
    files = dict(base_files)
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    result = next(r for r in results["scanner_results"] if r["scanner_id"] == SCANNER)
    result["warnings"] = observed["warnings"]
    result["coverage_notes"] = observed["coverage_notes"]
    files["scan-result/scanner-results.json"] = json.dumps(results).encode()
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    source = tmp_path / "quota.zip"
    with ZipFile(source, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    if mutation == "native":
        _add_synthetic_region_scope(source, FIXTURES / "region-scope.json", unknown_quota_field=True)
        with ZipFile(source) as archive:
            native_payload = next(
                r["payload"] for r in json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"] if r["scanner_id"] == SCANNER
            )
        assert len(native_payload["quota_records"]) == 2 * len(quota_producer_observation()["evidence"]["payload"]["quota_records"])
        assert "unknown_quota_control" in native_payload["quota_records"][0]
    assert main(["validate-bundle", str(source)]) == 0
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-quota-test-only\n"))
    exit_code = main(
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
    assert exit_code == (1 if mutation else 0)
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
        protected = next(r["payload"] for r in json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"] if r["scanner_id"] == SCANNER)
    encoded = json.dumps(protected)
    assert "123456789012" not in encoded
    assert "synthetic-customer" not in encoded
    if profile == "strict":
        assert "eu-west-2" not in encoded
        assert protected["period"]["total_cost"] == ""
        assert protected["period"]["currency"] == ""
    else:
        assert protected["period"]["total_cost"] == payload["period"]["total_cost"]


def _mutate(payload: dict[str, Any], mutation: str) -> None:
    record = payload["quota_records"][0]
    if mutation == "root":
        payload["unknown_quota_control"] = {}
    elif mutation.startswith("nested"):
        record["unknown_quota_control"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    elif mutation == "quantity":
        record["quota_value"] = "NaN"
    elif mutation == "count":
        record["current_usage"] = True
    elif mutation == "status":
        payload["status"] = "untrusted"
    elif mutation == "check":
        record["check_id"] = "untrusted"
    elif mutation == "method":
        record["resource_count_method"] = "ec2:DescribeVpcs count"
    elif mutation == "service":
        record["service"] = "Amazon VPC"
    elif mutation == "date":
        payload["period"]["start_date"] = "2026-01-99"
    else:
        payload["collection_evidence_version"] = True


def _verify_nullable_quota_names(payload: dict[str, Any], variant: str) -> None:
    """Verify an absent provider name never becomes the fictitious string None."""
    if variant == "nullable":
        assert all(record["quota_name"] == "" for record in payload["quota_records"])
