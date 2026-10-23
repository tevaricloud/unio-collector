"""Actual NAT inventory branch payloads through final bundle privacy gates."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_nat_fixture import SCANNER, VARIANTS, nat_producer_case
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("variant", "mutation"),
    [(variant, None) for variant in VARIANTS]
    + [
        ("success", "root"),
        ("empty", "root"),
        ("success", "record"),
        ("success", "tags"),
        ("success", "literal"),
        ("legacy_metrics", "metric"),
        ("legacy_metrics", "point"),
    ],
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_nat_branch_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, profile: str, mutation: str | None) -> None:
    """Validate actual conditional shapes through leak scanning and receipt verification."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    envelope = json.loads(files["scan-result/scanner-evidence.json"])
    row, _ = nat_producer_case(variant)
    if mutation:
        payload = row["payload"]
        if mutation == "root":
            payload["unknown_nat_container"] = {}
        elif mutation == "literal":
            payload["records[].region"] = "eu-west-2"
        else:
            record = payload["records"][0]
            target = (
                record
                if mutation == "record"
                else record["tags"]
                if mutation == "tags"
                else record["metric_summaries"][0]
                if mutation == "metric"
                else record["metric_summaries"][0]["datapoints"][0]
            )
            target["unknown_nat_container"] = {}
    for entry in envelope["scanner_evidence"]:
        if entry["scanner_id"] == SCANNER:
            entry["payload"] = row["payload"]
            entry["evidence_type"] = row["evidence_type"]
            entry["evidence_module"] = row["evidence_module"]
    files["scan-result/scanner-evidence.json"] = json.dumps(envelope).encode()
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
    assert main(
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
    ) == (1 if mutation else 0)
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
