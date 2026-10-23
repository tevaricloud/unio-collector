"""Actual log-retention legacy admission, protection, receipts and cleanup."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import fields
from typing import TYPE_CHECKING, Any
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from tools.collector_logs_fixture import SyntheticLogsSession, add_logs_producer_payload, logs_producer_case
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.log.group.record import LogGroupRecord
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.retention import FIELDS
from unio_collector.scanners.cloudwatch.log_retention.evidence import CloudWatchLogRetentionEvidence

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.offline
SCANNER = "cloudwatch-log-groups-without-retention"


@pytest.fixture(scope="module")
def retention_base(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """Reuse one complete canonical synthetic input without sharing mutable rows."""
    with ZipFile(producer_bundle(tmp_path_factory.mktemp("retention-base"))) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def test_retention_contract_matches_actual_dtos() -> None:
    """Detect new DTO fields independently of fixture and schema rewrites."""
    for prefix, model in (("", CloudWatchLogRetentionEvidence), ("records[].", LogGroupRecord)):
        declared = {
            path[len(prefix) :]
            for path in FIELDS
            if path.startswith(prefix) and path != prefix and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
        }
        assert declared == {field.name for field in fields(model)}


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("identity", ["versioned", "legacy", "fixture", "schema_only"])
@pytest.mark.parametrize("variant", ["success", "optional", "empty"])
def test_actual_retention_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, identity: str, variant: str
) -> None:
    """Current, schema-only and registered historical shapes remain usable."""
    _case(tmp_path, monkeypatch, retention_base, profile, identity, variant)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-unknown"])
def test_legacy_unknowns_reject_and_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, location: str, value: object
) -> None:
    """Nulls and empty containers cannot bypass legacy privacy preflight."""
    _case(tmp_path, monkeypatch, retention_base, profile, "legacy", "success", (location, value))


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [True, -1, "123", {}, []])
def test_legacy_malformed_count_rejects(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, value: object) -> None:
    """Stored bytes is nullable nonnegative integral data, never arbitrary text."""
    _case(tmp_path, monkeypatch, retention_base, profile, "legacy", "success", ("count", value))


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(("location", "value"), [("missing_record", "stored_bytes"), ("records", None), ("regions", [1])])
def test_legacy_required_shape_rejects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, location: str, value: object
) -> None:
    """Missing required members and malformed containers fail before publication."""
    _case(tmp_path, monkeypatch, retention_base, profile, "legacy", "success", (location, value))


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("missing", ["records", "regions", "both"])
def test_legacy_defaulted_root_lists_remain_compatible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, missing: str
) -> None:
    """The established dataclass decoder supplies omitted defaulted root lists."""
    _case(tmp_path, monkeypatch, retention_base, profile, "legacy", "success", ("defaulted", missing))


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("identity", ["versioned", "legacy"])
@pytest.mark.parametrize("literal", ["CloudWatchLogRetentionEvidence", "cloudwatch-log-groups-without-retention", "aws.cloudwatch.log-retention"])
def test_actual_retention_literal_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, retention_base: dict[str, bytes], profile: str, identity: str, literal: str
) -> None:
    """Customer names equal to protocol literals still pass through real SDK parsing."""
    original = SyntheticLogsSession.describe_log_groups

    def response(session: SyntheticLogsSession, **kwargs: object) -> dict[str, Any]:
        observed = original(session, **kwargs)
        if observed["logGroups"]:
            observed["logGroups"][0]["logGroupName"] = literal
        return observed

    monkeypatch.setattr(SyntheticLogsSession, "describe_log_groups", response)
    _case(tmp_path, monkeypatch, retention_base, profile, identity, "success")


def _case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base: dict[str, bytes],
    profile: str,
    identity: str,
    variant: str,
    mutation: tuple[str, object] | None = None,
) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, _, _ = logs_producer_case(SCANNER, variant)
    if identity in {"legacy", "fixture"}:
        row.pop("evidence_schema_id")
        row.pop("evidence_schema_version")
    if identity == "fixture":
        row.update(evidence_module="unio_collector.scanners.fixture_parity.synthetic_types", evidence_type="CloudWatchLogRetentionFixtureEvidence")
    if identity == "schema_only":
        row.pop("evidence_module")
        row.pop("evidence_type")
    if mutation:
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
    assert main(["validate-bundle", str(source)]) == 0
    output = tmp_path / "transfer/protected.zip"
    vault = tmp_path / "private/vault.json"
    monkeypatch.setattr("sys.stdin", io.StringIO("synthetic-retention-only\n"))
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
    if mutation and mutation[0] != "defaulted":
        assert code == 1
        assert not output.exists()
        assert not vault.exists()
        assert not output.with_suffix(".zip.receipt.json").exists()
        assert not list(tmp_path.rglob("*.tmp"))
    else:
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
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before


def _mutate(row: dict[str, Any], mutation: tuple[str, object]) -> None:
    """Change one real serialized producer field for a precise negative case."""
    location, value = mutation
    if location == "count":
        row["payload"]["records"][0]["stored_bytes"] = value
    elif location == "defaulted":
        for name in ("records", "regions") if value == "both" else (str(value),):
            del row["payload"][name]
    elif location == "missing_record":
        del row["payload"]["records"][0][str(value)]
    elif location in {"records", "regions"}:
        row["payload"][location] = value
    else:
        target = row["payload"] if location == "root" else row["payload"]["records"][0]
        target["unknown_retention_field"] = value


@pytest.mark.parametrize("literal", ["CloudWatchLogRetentionEvidence", "cloudwatch-log-groups-without-retention", "aws.cloudwatch.log-retention"])
@pytest.mark.parametrize("binding", ["trusted", "foreign_provider", "foreign_type", "unknown_leaf"])
def test_retention_control_views_still_reject_customer_leaks(literal: str, binding: str) -> None:
    """Identity metadata never exempts equal customer plaintext at data positions."""
    row, _, _ = logs_producer_case(SCANNER)
    row["payload"]["records"][0]["log_group_name"] = literal
    if binding == "foreign_provider":
        row["provider_id"] = "untrusted"
    elif binding == "foreign_type":
        row["evidence_type"] = "UntrustedEvidence"
    elif binding == "unknown_leaf":
        row["payload"]["customer_note"] = literal
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={literal}
    )
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("member", ["analysis-readiness.json", "collection-summary.json", "scan-result/scanner-results.json"])
@pytest.mark.parametrize("scanner", [SCANNER, "synthetic-unregistered-scanner"])
def test_retention_reference_views_keep_customer_text(member: str, scanner: str) -> None:
    """Finite public reference positions do not hide equal text in unknown fields."""
    coverage = {"scanner_evidence_coverage": {"selected_scanner_ids": [scanner], "customer_note": scanner}}
    document = (
        {"scanner_results": [{"scanner_id": scanner, "customer_note": scanner}]}
        if member.endswith("scanner-results.json")
        else coverage
        if member.startswith("analysis-")
        else {"strict_analysis_readiness": coverage}
    )
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={scanner})
    assert not result.passed
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_packaged_logs_negative_contains_legacy_null(retention_base: dict[str, bytes], profile: str) -> None:
    """The shared packaged input exercises privacy rejection beyond v1 admission."""
    files = dict(retention_base)
    add_logs_producer_payload(files, unknown_field=True)
    envelope = json.loads(files["scan-result/scanner-evidence.json"])
    row = next(row for row in envelope["scanner_evidence"] if row["scanner_id"] == SCANNER)
    assert "evidence_schema_id" not in row
    assert "evidence_schema_version" not in row
    assert row["payload"]["unknown_retention_field"] is None
    checked = transformer(profile)
    checked.transform(envelope, file_name="scan-result/scanner-evidence.json")
    assert "scan-result/scanner-evidence.json.scanner_evidence[].payload.unknown_retention_field" in checked.summary.unclassified
