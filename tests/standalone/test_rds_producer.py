"""Actual RDS SDK producers through standard/strict privacy and receipt gates."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_rds.fixture import CASE_VARIANTS, COLLECTORS, rds_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path
pytestmark = pytest.mark.offline
EXPECTED_POINTS = 2
SNAPSHOT_KINDS = ("db_instance_snapshot", "db_cluster_snapshot")


@pytest.fixture(scope="module")
def rds_base(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Use the complete existing actual-producer bundle and pricing readiness."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("rds-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


CASES = [(scanner, variant) for scanner in COLLECTORS for variant in CASE_VARIANTS[scanner]]


@pytest.mark.parametrize(("scanner", "variant"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_rds_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rds_base: dict[str, bytes], scanner: str, variant: str, profile: str) -> None:
    """Retain limitations and actual fields; no AWS constructor is usable."""
    _case(tmp_path, monkeypatch, rds_base, scanner, variant, profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "unknown_null",
        "metric_unknown",
        "literal_key",
        "boolean_count",
        "bad_timestamp",
        "month_input",
        "bad_parts",
        "foreign_identity",
        "malformed_status",
        "leaked_text",
    ],
)
def test_rds_rejection_cleanup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rds_base: dict[str, bytes], profile: str, mutation: str) -> None:
    """Reject malformed/unknown fields and customer plaintext before publishing."""
    _case(tmp_path, monkeypatch, rds_base, "rds-utilization-review", "success", profile, mutation)


def _case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base: dict[str, bytes], scanner: str, variant: str, profile: str, mutation: str | None = None
) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = rds_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert row is not None
    assert row["evidence_type"] == "InventoryEvidence"
    _assert_producer_shape(scanner, variant, row, observed)
    if mutation:
        _mutate(row, mutation)
    files = dict(base)
    add_scanner_producer_payload(files, row, execution=observed["execution"])
    checks = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checks
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checks}).encode()
    source = tmp_path / "source.zip"
    with ZipFile(source, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    original = hashlib.sha256(source.read_bytes()).hexdigest()
    assert main(["validate-bundle", str(source)]) == 0
    output, vault = (tmp_path / "transfer/protected.zip", tmp_path / "private/vault.json")
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-rds-only-input\n"))
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original
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
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert inspected.validation_passed
    assert receipt["verified"]
    leak = inspected.summary["leak_scan"]
    assert isinstance(leak, dict)
    assert leak["passed"]
    assert leak["findings"] == []
    if scanner == "rds-utilization-review" and variant in {"stopped", "stopping", "custom_status"}:
        with ZipFile(output) as archive:
            evidence = json.loads(archive.read("scan-result/scanner-evidence.json"))["scanner_evidence"]
        protected = next(r for r in evidence if r["scanner_id"] == scanner)["payload"]["records"][0]
        if variant == "custom_status":
            assert protected["status"] != "synthetic-customer-status"
        else:
            assert protected["status"] == variant


def _assert_producer_shape(scanner: str, variant: str, row: dict[str, Any], observed: dict[str, Any]) -> None:
    records = row["payload"]["records"]
    if variant in {"success", "collision", "optional"}:
        assert len(records) == (len(SNAPSHOT_KINDS) if scanner == "rds-snapshot-retention-review" else 1)
    if scanner == "rds-utilization-review" and variant == "success":
        assert {m["metric_name"] for m in records[0]["metrics"]} == {"CPUUtilization", "DatabaseConnections", "ReadIOPS", "WriteIOPS", "FreeStorageSpace"}
        assert all(m["collection_context"] is not None and len(m["datapoints"]) == EXPECTED_POINTS for m in records[0]["metrics"])
    if variant in {"denied", "unavailable", "unsupported", "failure", "partial_page"}:
        assert not records
        assert observed["execution"]["status"] == "completed_with_warnings"


def _mutate(row: dict[str, Any], mutation: str) -> None:
    record = row["payload"]["records"][0]
    metric = record["metrics"][0]
    record_changes = {
        "unknown": {"unknown_rds_control": {}},
        "unknown_null": {"unknown_rds_control": None},
        "literal_key": {"unknown.rds": "synthetic-customer"},
        "boolean_count": {"allocated_storage_gib": True},
        "malformed_status": {"status": {"customer": "synthetic-customer"}},
    }
    metric_changes = {
        "metric_unknown": {"unknown_metric_control": None},
        "bad_timestamp": {"start_time": "not-a-date"},
        "month_input": {"start_time": "2026-07"},
        "bad_parts": {"observed_average_parts": [0, [99], 0]},
        "leaked_text": {"namespace": "synthetic-customer-db"},
    }
    if mutation in record_changes:
        record.update(record_changes[mutation])
    elif mutation in metric_changes:
        metric.update(metric_changes[mutation])
    elif mutation == "foreign_identity":
        row["provider_id"] = "untrusted"
    else:
        raise AssertionError(mutation)
