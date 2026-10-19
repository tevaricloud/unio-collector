"""Actual account-risk envelope protection, independent validation and failure cleanup."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_producers import producer_bundle
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", [None, "daily", "iam", "trail"])
def test_populated_account_bundle_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, location: str | None) -> None:
    """Exercise the distributed fixture itself; unknown fields cannot leave success files."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    rows = json.loads(files["scan-result/scanner-evidence.json"])
    payload = next(row["payload"] for row in rows["scanner_evidence"] if row["scanner_id"] == "account-cost-risk-signal-review")
    risk = payload["account_risk"]
    assert len(risk["trails"]) == 26  # noqa: PLR2004
    assert len(risk["trail_statuses"]) == 25  # noqa: PLR2004
    assert risk["trail_status_omitted_count"] == 1
    assert risk["trail_statuses_complete"] is False
    assert risk["trail_statuses"][0]["is_logging"] is None
    assert len(payload["daily_costs"]) == 2  # noqa: PLR2004
    if location:
        target = {"daily": payload["daily_costs"][0], "iam": risk["iam_summary"], "trail": risk["trails"][0]}[location]
        target["unknown_synthetic_field"] = {}
        files["scan-result/scanner-evidence.json"] = json.dumps(rows).encode()
        checksums = build_checksums(files)
        manifest = json.loads(files["manifest.json"])
        manifest["checksums"] = checksums
        files["manifest.json"] = json.dumps(manifest).encode()
        files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
        with ZipFile(source, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
    assert main(["validate-bundle", str(source)]) == 0
    before = hashlib.sha256(source.read_bytes()).hexdigest()
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
    assert code == (1 if location else 0)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    if location:
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
        assert "synthetic-customer" not in protected
