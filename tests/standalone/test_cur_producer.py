"""Actual CUR reader/gateway privacy through protection, receipts and cleanup."""

from __future__ import annotations

import copy
import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from tools.collector_cur_fixture import VARIANTS, add_cur_producer_payload, cur_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.cur import FIELDS, CurPrivacyContract
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
MINIMUM_ROWS = 4
MATCHED_ROWS = 3
MANIFEST_READS = 2


@pytest.fixture(scope="module")
def cur_base(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Share immutable expanded producer bytes, never a mutable archive."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("cur-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_cur_shape(variant: str) -> None:
    """Distinguish supported billing observations from actual propagated failures."""
    observed = cur_producer_observation(variant)
    if variant in {"denied", "failure", "mixed_currency"}:
        assert observed["evidence"] is None
        assert observed["exception"] == ("ValueError" if variant == "mixed_currency" else "ClientError")
        assert observed["operations"]
        if variant in {"denied", "failure"}:
            assert observed["error_code"] == ("AccessDenied" if variant == "denied" else "InternalError")
        return
    row = observed["evidence"]
    contract = CurPrivacyContract.for_record(row)
    assert contract
    assert not contract.unknown_record_paths(row, "scan-result/scanner-evidence.json")
    facts = row["payload"]["billing_facts"]
    assert set(facts) == {path.split(".")[1] for path in FIELDS if path.startswith("billing_facts.") and path.count(".") == 1 and "[" not in path}
    if variant not in {"empty", "unsupported", "unavailable"}:
        assert facts["rows_read"] >= MINIMUM_ROWS
        assert facts["rows_matched"] == MATCHED_ROWS
        assert facts["total_cost"] == "23.685"
        assert facts["top_resources"]
        assert facts["top_usage_types"]
        assert facts["collection_status"] == ("partial" if variant == "partial" else "complete")
    else:
        assert facts["collection_status"] == "unavailable"
    assert facts["rows_skipped"] == (1 if variant == "partial" else 0)
    if variant == "manifest":
        assert len(observed["operations"]) == MANIFEST_READS
    elif variant in {"unsupported", "unavailable"}:
        assert not observed["operations"]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    "variant", ["success", "gzip", "manifest", "partial", "optional", "empty", "unsupported", "unavailable", "collision", "status_collision"]
)
def test_actual_cur_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cur_base: dict[str, bytes], profile: str, variant: str) -> None:
    """Actual producer output survives complete protection and independent inspection."""
    _case(tmp_path, monkeypatch, cur_base, profile, variant)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["unknown_null", "unknown_empty", "count", "money", "status", "issue", "missing", "foreign", "version", "nonnull_summary"])
def test_cur_invalid_rejects_and_cleans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cur_base: dict[str, bytes], profile: str, mutation: str) -> None:
    """Null, container, finite vocabulary and identity errors cannot hide in strict output."""
    _case(tmp_path, monkeypatch, cur_base, profile, "success", mutation)


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: dict[str, bytes], profile: str, variant: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row = cur_producer_observation(variant)["evidence"]
    facts = row["payload"]["billing_facts"]
    _mutate(row, mutation)
    files = dict(base)
    add_scanner_producer_payload(files, row)
    checks = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checks
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checks}).encode()
    source = tmp_path / "source.zip"
    with ZipFile(source, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output, vault = tmp_path / "transfer/protected.zip", tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-cur-only\n"))
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    if mutation:
        assert code == 1
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
        return
    assert code == 0
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    leak_scan = inspected.summary["leak_scan"]
    assert isinstance(receipt, dict)
    assert isinstance(leak_scan, dict)
    assert receipt["verified"]
    assert leak_scan["passed"]
    assert leak_scan["findings"] == []
    with ZipFile(output) as archive:
        protected = next(
            record["payload"]["billing_facts"]
            for record in json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
            if record["scanner_id"] == row["scanner_id"]
        )
    if profile == "strict":
        assert protected is None
        return
    assert protected["rows_matched"] == facts["rows_matched"]
    assert protected["source_files"] != facts["source_files"] or not facts["source_files"]
    for original, actual in zip(facts["top_resources"], protected["top_resources"], strict=True):
        assert actual["resource_id"] != original["resource_id"]
        assert actual["region"] == ("aws-region" if profile == "strict" else original["region"])
    if profile == "standard":
        assert protected["total_cost"] == facts["total_cost"]
    else:
        for name in ("total_cost", "assigned_cost", "unassigned_cost", "tag_assignment_percentage", "currency"):
            assert not protected.get(name)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("path", "value"),
    [("rows_read", -1), ("rows_read", None), ("rows_read", "4"), ("currency", None), ("top_resources", {}), ("source_files", None), ("total_cost", "Infinity")],
)
def test_cur_malformed_contract(profile: str, path: str, value: object) -> None:
    """Reject malformed scalars and containers before strict profile omission."""
    row = cur_producer_observation()["evidence"]
    row["payload"]["billing_facts"][path] = value
    checked = transformer(profile)
    checked.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert checked.summary.unclassified


@pytest.mark.parametrize("binding", ["trusted", "foreign", "unknown"])
@pytest.mark.parametrize("literal", ["CurDataExportEvidence", "complete", "source_resolution_incomplete"])
def test_cur_customer_leaks_still_reject(binding: str, literal: str) -> None:
    """Customer plaintext remains visible even when equal to a public DTO name."""
    row = copy.deepcopy(cur_producer_observation("collision")["evidence"])
    row["payload"]["billing_facts"]["top_resources"][0]["resource_id"] = literal
    if binding == "foreign":
        row["provider_id"] = "untrusted"
    elif binding == "unknown":
        row["payload"]["customer_note"] = literal
    scan = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={literal}
    )
    assert not scan.passed
    assert any(finding.category == "known_original_value" for finding in scan.findings)


def _mutate(row: dict[str, Any], mutation: str | None) -> None:
    """Apply one isolated adversarial contract mutation to real serialized output."""
    facts = row["payload"]["billing_facts"]
    if mutation == "unknown_null":
        facts["top_resources"][0]["unknown_cur_field"] = None
    elif mutation == "unknown_empty":
        facts["top_resources"][0]["unknown_cur_field"] = {}
    elif mutation == "count":
        facts["rows_read"] = True
    elif mutation == "money":
        facts["total_cost"] = "NaN"
    elif mutation == "status":
        facts["collection_status"] = "synthetic-customer-status"
    elif mutation == "issue":
        facts["collection_issues"] = [{"error_code": "synthetic-customer-error"}]
    else:
        _mutate_identity(row, mutation)


def _mutate_identity(row: dict[str, Any], mutation: str | None) -> None:
    """Change an identity or a required object member without broad fixture rewriting."""
    facts = row["payload"]["billing_facts"]
    if mutation == "missing":
        del facts["top_resources"][0]["resource_id"]
    elif mutation == "foreign":
        row["provider_id"] = "untrusted"
    elif mutation == "version":
        row["payload"]["collection_evidence_version"] = True
    elif mutation == "nonnull_summary":
        row["payload"]["summary"] = {"unknown": None}


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_packaged_cur_negative_uses_actual_nested_null(cur_base: dict[str, bytes], profile: str) -> None:
    """The future packaged smoke carries this same populated actual billing envelope."""
    files = dict(cur_base)
    add_cur_producer_payload(files, unknown=True)
    checked = transformer(profile)
    checked.transform(json.loads(files["scan-result/scanner-evidence.json"]), file_name="scan-result/scanner-evidence.json")
    assert "scan-result/scanner-evidence.json.scanner_evidence[].payload.billing_facts.top_resources[].unknown_cur_field" in checked.summary.unclassified


def test_cur_legacy_fallback_remains_separate() -> None:
    """Do not reinterpret existing version-zero summaries as current billing observations."""
    row = cur_producer_observation()["evidence"]
    row["payload"]["collection_evidence_version"] = 0
    assert CurPrivacyContract.for_record(row) is None


@pytest.mark.parametrize("value", [False, True, "1", None, 2])
def test_cur_malformed_version_does_not_borrow_legacy_fallback(value: object) -> None:
    """Only integer version zero may use the established historical fallback."""
    row = cur_producer_observation()["evidence"]
    row["payload"]["collection_evidence_version"] = value
    with pytest.raises(ValueError, match="integer collection version"):
        CurPrivacyContract.for_record(row)
