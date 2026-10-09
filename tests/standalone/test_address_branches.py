"""Actual Elastic IP branch payloads through final bundle privacy gates."""

from __future__ import annotations

import hashlib
import io
import json
import re
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_address_fixture import SCANNER, VARIANTS, address_producer_case
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_address_branch_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, profile: str) -> None:
    """Validate actual conditional shapes through leak scanning and receipt verification."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    envelope = json.loads(files["scan-result/scanner-evidence.json"])
    row, _ = address_producer_case(variant)
    for entry in envelope["scanner_evidence"]:
        if entry["scanner_id"] == SCANNER:
            entry["payload"] = row["payload"]
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
    assert (
        main(
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
        == 0
    )
    assert main(["validate-bundle", str(output)]) == 0
    inspected = ProtectedBundleInspector().inspect(output)
    assert inspected.validation_passed
    receipt = inspected.summary["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["verified"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_registered_token_substring_collision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """A real token suffix containing the Route53 original HTTPS is not plaintext."""
    monkeypatch.setattr(
        "unio_collector.privacy.state_factory.generate_root_key",
        lambda: hashlib.sha256(b"Unio-anomaly-synthetic-seed-8891").digest(),
    )
    test_actual_address_branch_bundle(tmp_path, monkeypatch, "classic", profile)
    with ZipFile(tmp_path / "transfer/protected.zip") as archive:
        content = archive.read("scan-result/scanner-evidence.json").decode()
    assert re.search(r"RESOURCE-[A-Z2-7]*HTTPS[A-Z2-7]*", content)
