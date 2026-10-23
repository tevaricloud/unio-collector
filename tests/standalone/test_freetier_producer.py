"""Actual freetier collection, serialization, protection and completion contracts."""

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
from tools.collector_freetier_fixture import SCANNER, VARIANTS, freetier_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline


@pytest.fixture(scope="module")
def freetier_base_files(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Collect unchanged shared baseline once; each case has fresh actual producer data."""
    with (
        patch("boto3.session.Session.client", side_effect=AssertionError("AWS forbidden")),
        patch("boto3.session.Session.resource", side_effect=AssertionError("AWS forbidden")),
        ZipFile(producer_bundle(tmp_path_factory.mktemp("freetier-base"))) as archive,
    ):
        return {name: archive.read(name) for name in archive.namelist()}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_freetier_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, freetier_base_files: dict[str, bytes], profile: str, variant: str) -> None:
    """Actual facts, optional values and supported failure branches survive protection."""
    _case(tmp_path, monkeypatch, freetier_base_files, profile, variant)


@pytest.mark.parametrize(
    "mutation",
    [
        "root",
        "nested",
        "nested_null",
        "nested_boolean",
        "quantity",
        "count",
        "status",
        "plan_type",
        "plan_unknown",
        "list",
        "date",
        "missing",
        "plan_null_type",
    ],
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_freetier_rejection_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, freetier_base_files: dict[str, bytes], profile: str, mutation: str
) -> None:
    """Unknown/type/value/cross-check failures reject before strict omissions."""
    _case(tmp_path, monkeypatch, freetier_base_files, profile, "success", mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_packaged_freetier_unknown_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, freetier_base_files: dict[str, bytes], profile: str) -> None:
    """Drive the exact native enrichment unknown switch, not a rewritten DTO."""
    _case(tmp_path, monkeypatch, freetier_base_files, profile, "success", "native")


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base_files: dict[str, bytes], profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = freetier_producer_observation(variant)
    row = observed["evidence"]
    payload = row["payload"]
    _verify_provider_shape(observed, variant)
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
    source = tmp_path / "freetier.zip"
    with ZipFile(source, "w") as archive:
        for name, value in files.items():
            archive.writestr(name, value)
    if mutation == "native":
        _add_synthetic_region_scope(source, FIXTURES / "region-scope.json", unknown_freetier_field=True)
        with ZipFile(source) as archive:
            native_payload = next(
                r["payload"] for r in json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"] if r["scanner_id"] == SCANNER
            )
        assert len(native_payload["usage_records"]) == 1
        assert native_payload["api_errors"]
        assert "unknown_freetier_control" in native_payload["usage_records"][0]
    assert main(["validate-bundle", str(source)]) == 0
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-freetier-test-only\n"))
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
    _verify_protected_fields(payload, protected, profile)


def _mutate(payload: dict[str, Any], mutation: str) -> None:
    """Inject one concrete unknown, malformed or incomplete DTO shape."""
    record = payload["usage_records"][0]
    if mutation == "root":
        payload["unknown_freetier_control"] = {}
    elif mutation.startswith("nested"):
        record["unknown_freetier_control"] = None if mutation == "nested_null" else True if mutation == "nested_boolean" else {}
    elif mutation == "quantity":
        record["actual_usage_amount"] = "NaN"
    elif mutation == "count":
        payload["page_count"] = True
    elif mutation in {"status", "plan_type"}:
        payload["account_plan"][{"status": "account_plan_status", "plan_type": "account_plan_type"}[mutation]] = "untrusted"
    elif mutation == "plan_unknown":
        payload["account_plan"]["unknown_freetier_control"] = None
    elif mutation == "list":
        payload["usage_records"] = {}
    elif mutation == "date":
        payload["account_plan"]["expiration_date"] = "2026-01-99"
    elif mutation == "missing":
        record.pop("description")
    else:
        payload["account_plan"] = False


def _verify_provider_shape(observed: dict[str, Any], variant: str) -> None:
    """Check independent counts, callbacks and actual limitation outcomes."""
    row = observed["evidence"]
    payload = row["payload"]
    assert row["evidence_type"] == "FreeTierCollectionResult"
    assert row["evidence_module"].endswith(".aws.free_tier.collection_result")
    expected = (
        2
        if variant == "success"
        else 0
        if variant in {"empty", "denied", "unavailable", "unsupported", "failure", "partial", "usage_denied", "malformed_usage", "interrupted"}
        else 1
    )
    assert len(payload["usage_records"]) == expected
    pages = (
        2
        if variant in {"success", "page_partial"}
        else 0
        if variant in {"denied", "unavailable", "unsupported", "failure", "partial", "usage_denied", "interrupted"}
        else 1
    )
    assert payload["page_count"] == pages
    assert observed["warnings"] == observed["coverage_notes"] == []
    if variant in {"denied", "plan_denied", "usage_denied"}:
        assert payload["permission_errors"]
        assert observed["status"] == "permission_limited"
    if variant in {"unavailable", "unsupported", "failure"}:
        assert payload["api_errors"]
        assert observed["status"] == "unavailable"
    if variant in {"partial", "expected_absence", "malformed_plan", "malformed_usage", "page_partial", "interrupted"}:
        assert payload["api_errors"]
    if variant == "page_partial":
        assert payload["account_plan"] is not None
        assert expected == 1
    if variant == "nullable":
        assert payload["usage_records"][0]["actual_usage_amount"] is None
        assert payload["account_plan"]["remaining_credit_amount"] is None


def _verify_protected_fields(payload: dict[str, Any], protected: dict[str, Any], profile: str) -> None:
    """Preserve standard values while enforcing strict financial/unit removal."""
    encoded = json.dumps(protected)
    assert "123456789012" not in encoded
    assert "Synthetic customer" not in encoded
    if profile == "strict":
        assert "eu-west-2" not in encoded
        for original, transformed in zip(payload["usage_records"], protected["usage_records"], strict=True):
            for key in ("actual_usage_amount", "forecasted_usage_amount", "limit"):
                assert transformed[key] == (None if original[key] is None else "")
            assert transformed["unit"] == ""
        if payload["account_plan"] is not None:
            assert protected["account_plan"]["remaining_credit_amount"] == (None if payload["account_plan"]["remaining_credit_amount"] is None else "")
            assert protected["account_plan"]["remaining_credit_unit"] in (None, "")
    else:
        for original, transformed in zip(payload["usage_records"], protected["usage_records"], strict=True):
            assert transformed["actual_usage_amount"] == original["actual_usage_amount"]
            public_reference = (original["service"], original["operation"], original["usage_type"], original["unit"]) in {
                ("Amazon S3", "TimedStorage-ByteHrs", "TimedStorage-ByteHrs", "GB-Mo"),
                ("Amazon S3", "TimedStorage-ByteHrs", "TimedStorage-ByteHrs", ""),
                ("Amazon Simple Storage Service", "Requests-Tier1", "Requests-Tier1", "Requests"),
            }
            if public_reference:
                assert transformed["unit"] == original["unit"]
                assert transformed["usage_type"] == original["usage_type"]
            elif original["unit"]:
                assert transformed["unit"] != original["unit"]
        if payload["account_plan"] is not None:
            assert protected["account_plan"]["remaining_credit_amount"] == payload["account_plan"]["remaining_credit_amount"]
