"""Literal path syntax cannot impersonate fixed provenance producer fields."""

from __future__ import annotations

import hashlib
import io
import json
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector.protocol import DEFAULT_PROTOCOL
from unio_collector.collector_cli.app import main
from unio_collector.privacy.producer_fields import producer_category

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
CASES = [
    ("account-scope.json", "scan_period.duration_days", 30),
    ("account-scope.json", "region_scope.discovery_status", "completed"),
    ("collection-summary.json", "limitation_counts.partial", 1),
    ("collection-log.jsonl", f"{DEFAULT_PROTOCOL.namespace}.destructive", False),
    ("collection-summary.json", "api_runtime_summary.records[].failure_count", 1),
    ("collection-summary.json", "billing_region_coverage.region_scope_derivation.enabled", True),
]


@pytest.mark.parametrize(("member", "key", "value"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_literal_producer_keys_reject(member: str, key: str, value: object, profile: str) -> None:
    """Reject both root-prefix impersonation and indexed record impersonation."""
    t = transformer(profile)
    t.transform({key: value}, file_name=member)
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_nested_owned_key_rejects(profile: str) -> None:
    """A literal dotted child inside a valid owned subtree is still unknown."""
    t = transformer(profile)
    t.transform({"scan_period": {"raw_input.days": 30}}, file_name="account-scope.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("$.limitation_counts.partial", "summary_count"),
        ("$.limitation_countspartial", None),
        ("$.api_runtime_summary.enabled", "safe_metadata"),
        ("$.api_runtime_summaryenabled", None),
    ],
)
def test_producer_prefix_requires_boundary(path: str, expected: str | None) -> None:
    """A matching prefix string is not a matching schema subtree."""
    assert producer_category("collection-summary.json", path) == expected


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(("member", "key", "value"), CASES)
def test_actual_producer_bundle_path_rejection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, member: str, key: str, value: object) -> None:
    """Inject one unknown into actual producer output and require safe cleanup."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    if member.endswith(".jsonl"):
        lines = files[member].decode().splitlines()
        row = json.loads(lines[0])
        row[key] = value
        lines[0] = json.dumps(row)
        files[member] = ("\n".join(lines) + "\n").encode()
    else:
        row = json.loads(files[member])
        row[key] = value
        files[member] = json.dumps(row).encode()
    checksums = build_checksums(files)
    manifest = json.loads(files["manifest.json"])
    manifest["checksums"] = checksums
    files["manifest.json"] = json.dumps(manifest).encode()
    files["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    with ZipFile(source, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    assert main(["validate-bundle", str(source)]) == 0
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    output, vault = tmp_path / "transfer/protected.zip", tmp_path / "private/vault.json"
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
        == 1
    )
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
    assert not output.exists()
    assert not vault.exists()
    assert not output.with_suffix(".zip.receipt.json").exists()
    assert not list(tmp_path.rglob("*.tmp"))
