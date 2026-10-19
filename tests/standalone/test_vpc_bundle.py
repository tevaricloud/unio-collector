"""Actual VPC endpoint branch payloads through final bundle privacy gates."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.collector_scanner_fixture import add_scanner_producer_payload
from tools.collector_vpc_fixture import VARIANTS, vpc_producer_case
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize(
    ("variant", "mutation"),
    [(variant, None) for variant in VARIANTS]
    + [("success", mutation) for mutation in ("root", "facts", "route", "association", "nested", "state")]
    + [("empty", "root")],
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_vpc_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, profile: str, mutation: str | None) -> None:
    """Validate actual conditional shapes through leak scanning and receipt verification."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    row = vpc_producer_case(variant)
    if mutation:
        payload = row["payload"]
        if mutation == "root":
            target = payload
        else:
            resource = next(r for r in payload["topology"][0]["resources"] if r["kind"] == "route_tables")
            target = resource["facts"]
            if mutation == "route":
                target = target["Routes"][0]
            elif mutation in {"association", "nested", "state"}:
                target = target["Associations"][0]
                if mutation in {"nested", "state"}:
                    target = target["AssociationState"]
        target["State" if mutation == "state" else "unknown_vpc_container"] = "future-state" if mutation == "state" else {}
    add_scanner_producer_payload(files, row)
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
