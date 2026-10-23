"""Exercise native guard orchestration with the actual offline Python CLI."""

from __future__ import annotations

import contextlib
import hashlib
import io
import subprocess
from pathlib import Path

import pytest

from tests.standalone.test_producers import producer_bundle
from tools.native_protection import NativeProtectionGuards
from unio_collector.collector_cli.app import main

pytestmark = pytest.mark.offline


def test_actual_packaged_guard_contracts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Use actual populated producers and CLI returns; reject unrelated failures and artifacts."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    producer_bundle(tmp_path).rename(tmp_path / "evidence.zip")
    captured: list[subprocess.CompletedProcess[str]] = []

    def run(command: list[str], **options: object) -> subprocess.CompletedProcess[str]:
        output, error = io.StringIO(), io.StringIO()
        with monkeypatch.context() as context, contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            context.setattr("sys.stdin", io.StringIO(str(options.get("input", ""))))
            code = main(command[1:])
        result = subprocess.CompletedProcess(command, code, output.getvalue(), error.getvalue())
        captured.append(result)
        return result

    monkeypatch.setattr("tools.native_protection.subprocess.run", run)
    guard = NativeProtectionGuards()
    evidence = guard.run(Path("synthetic-cli"), tmp_path, {})
    assert isinstance(evidence["checks"], dict)
    assert set(evidence["checks"]) == {"malformed-standard", "malformed-strict", "plaintext-standard"}
    assert evidence["source_preserved"] is True
    rejected = next(row for row in captured if row.returncode == 1)
    fixture = tmp_path / "guard-malformed.zip"
    output, vault = tmp_path / "absent.zip", tmp_path / "absent-vault.json"
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="unrelated reason"):
        guard.verify(subprocess.CompletedProcess([], 1, "unrelated error", ""), "malformed", fixture, digest, output, vault)
    output.write_bytes(b"synthetic unexpected output")
    with pytest.raises(RuntimeError, match="published an artifact"):
        guard.verify(rejected, "malformed", fixture, digest, output, vault)
