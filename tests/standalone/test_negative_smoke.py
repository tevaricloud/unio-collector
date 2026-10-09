"""Actual CLI diagnostics must satisfy each bounded native negative batch."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.build_native_collector import _add_synthetic_region_scope, _verify_unknown_smoke
from unio_collector.collector_cli.app import main

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("batch", ["", "logs-", "nat-", "network-"])
def test_actual_negative_batches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], profile: str, batch: str) -> None:
    """Real formatted errors fit the display bound and prove rejection plus cleanup."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    positive = producer_bundle(tmp_path)
    source = tmp_path / (f"unknown-{batch[:-1]}.zip" if batch else "unknown.zip")
    shutil.copyfile(positive, source)
    namespace = _add_synthetic_region_scope(
        source,
        Path("tests/standalone/fixtures/region-scope.json"),
        unknown_ledger_field=not batch,
        unknown_logs_field=batch == "logs-",
        unknown_nat_field=batch == "nat-",
        unknown_network_field=batch == "network-",
    )
    assert main(["validate-bundle", str(source)]) == 0
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    identity = batch + profile
    command = [
        "privacy",
        "protect",
        "--bundle",
        str(source),
        "--output",
        str(tmp_path / f"unknown-{identity}.zip"),
        "--vault",
        str(tmp_path / f"private-unknown-{identity}/vault.json"),
        "--profile",
        profile,
        "--passphrase-stdin",
        "--acknowledge-vault-loss-risk",
    ]
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-negative-smoke-only\n"))
    capsys.readouterr()
    code = main(command)
    captured = capsys.readouterr()
    assert code == 1
    assert "additionaldistinctpaths" not in "".join((captured.out + captured.err).split())
    completed = subprocess.CompletedProcess(command, code, captured.out, captured.err)
    _verify_unknown_smoke(tmp_path, identity, completed, digest, namespace)
    with pytest.raises(RuntimeError, match="unrelated reason"):
        _verify_unknown_smoke(tmp_path, identity, subprocess.CompletedProcess(command, 1, "unrelated error", ""), digest, namespace)
    artifact = tmp_path / f"unknown-{identity}.zip.receipt.json"
    artifact.write_text("synthetic stale receipt", encoding="utf-8")
    with pytest.raises(RuntimeError, match="published an artifact"):
        _verify_unknown_smoke(tmp_path, identity, completed, digest, namespace)
