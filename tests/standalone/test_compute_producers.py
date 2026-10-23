"""Actual EC2 producer contracts through full protection and independent receipts."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import fields
from typing import TYPE_CHECKING
from zipfile import ZipFile

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_producers import producer_bundle
from tools.collector_compute.fixture import COLLECTORS, RUNNING_VARIANTS, VARIANTS, compute_producer_observation
from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.ec2.running_instance_record import RunningInstanceRecord
from unio_collector.collector.bundle.checksums import build_checksums
from unio_collector.collector_cli.app import main
from unio_collector.privacy.ec2.running import FIELDS
from unio_collector.privacy.inspector import ProtectedBundleInspector
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.token.codec import TokenV1Codec

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.privacy.canonicalization import CanonicalValue
    from unio_collector.privacy.token.domain import TokenDomain

pytestmark = pytest.mark.offline
CASES = [(scanner, variant) for scanner in COLLECTORS for variant in (*VARIANTS, *(RUNNING_VARIANTS if scanner == "ec2-idle-instance-review" else ()))]


def test_running_dto_fields_have_explicit_contracts() -> None:
    """A new record field cannot silently enter the populated producer fixture."""
    assert {field.name for field in fields(RunningInstanceRecord)} == {
        path.removeprefix("records[].")
        for path in FIELDS
        if path.startswith("records[].") and "." not in path.removeprefix("records[].") and "[]" not in path.removeprefix("records[].")
    }


@pytest.mark.parametrize(("scanner", "variant"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_compute_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, variant: str, profile: str) -> None:
    """Retain actual callbacks, warnings, serialization, receipts and unchanged inputs."""
    _case(tmp_path, monkeypatch, scanner, variant, profile)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    "mutation", ["root", "nested", "null_unknown", "tags", "metric", "foreign", "schedule", "clock", "count", "note", "note_pair", "note_limit", "note_foreign"]
)
def test_compute_rejects_and_cleans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, mutation: str) -> None:
    """Malformed and unknown conditional children cannot leave a successful artifact."""
    variant = "scheduled" if mutation in {"schedule", "clock", "count"} else "capped" if mutation.startswith("note") else "success"
    _case(tmp_path, monkeypatch, "ec2-idle-instance-review", variant, profile, mutation)


@pytest.mark.parametrize("value", ["synthetic-customer-marker", "AWS/EC2", "running", "InventoryEvidence", "available", "m6i.large"])
def test_compute_plaintext_leaks_still_reject(value: str) -> None:
    """Explicit schemas do not exempt customer values or untrusted producers."""
    source = compute_producer_observation("ec2-idle-instance-review")["evidence"]
    for provider in ("aws", "untrusted-provider"):
        source["provider_id"] = provider
        source["payload"]["records"][0]["platform_details"] = value
        result = ProtectedArchiveLeakScanner().scan_text(
            path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [source]}), known_original_values={value}
        )
        assert not result.passed


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanner: str, variant: str, profile: str, mutation: str | None = None) -> None:
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    observed = compute_producer_observation(scanner, variant)
    row = observed["evidence"]
    assert "instances" in observed["callbacks"]
    if scanner == "ec2-idle-instance-review" and variant == "success":
        assert row["payload"]["records"][0]["metric_summaries"]
        assert "GetMetricData" in observed["operations"]
    _mutate(row, mutation)
    source = producer_bundle(tmp_path)
    with ZipFile(source) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    add_scanner_producer_payload(files, row)
    results = json.loads(files["scan-result/scanner-results.json"])
    execution = next(item for item in results["scanner_results"] if item["scanner_id"] == scanner)
    execution["coverage_notes"] = observed["coverage_notes"]
    execution["warnings"] = observed["warnings"]
    _mutate_note(results, execution, mutation)
    files["scan-result/scanner-results.json"] = json.dumps(results).encode()
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
    output, vault = tmp_path / "transfer/protected.zip", tmp_path / "private/vault.json"
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
    assert code == (1 if mutation else 0)
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
    receipt, leak_scan = inspected.summary["receipt"], inspected.summary["leak_scan"]
    assert isinstance(receipt, dict)
    assert isinstance(leak_scan, dict)
    assert receipt["verified"]
    assert leak_scan["passed"]
    assert leak_scan["findings"] == []
    with ZipFile(output) as archive:
        payload = json.loads(archive.read("scan-result/scanner-evidence.json"))
    protected = next(item["payload"] for item in payload["scanner_evidence"] if item["scanner_id"] == scanner)
    encoded = json.dumps(protected)
    assert "synthetic-customer" not in encoded
    assert "123456789012" not in encoded
    if profile == "strict":
        assert "eu-west-2" not in encoded
        assert "2026-05-01" not in encoded
    transformed = transformer(profile)
    transformed.transform({"scanner_evidence": [observed["evidence"]]}, file_name="scan-result/scanner-evidence.json")
    assert not transformed.summary.unclassified


def _mutate(row: dict, mutation: str | None) -> None:
    """Mutate only one supported source surface for each negative case."""
    records = row["payload"].get("records", row["payload"].get("stopped_instances", []))
    if mutation == "root":
        row["payload"]["unknown_compute_control"] = {}
    elif mutation in {"nested", "null_unknown"}:
        records[0]["unknown_compute_control"] = None if mutation == "null_unknown" else {}
    elif mutation == "tags":
        records[0]["tags"]["unknown_nested_tag"] = {}
    elif mutation == "metric":
        records[0]["metric_summaries"][0]["collection_status"] = "future-state"
    elif mutation == "foreign":
        row["provider_id"] = "untrusted-provider"
    elif mutation in {"schedule", "clock", "count"}:
        schedule = row["payload"]["metadata"]["scheduled_shutdown"]
        if mutation == "schedule":
            next(iter(schedule["schedules"].values()))["unknown_compute_control"] = {}
        elif mutation == "clock":
            next(iter(schedule["schedules"].values()))["periods"][0]["start"] = "99:00"
        else:
            schedule["minimum_observation_days"] = True


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_schedule_ids_with_cost_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Actual punctuated IDs remain data when authenticated generated keys contain COST."""
    _force_cost_tokens(monkeypatch, "resource_id")
    _case(tmp_path, monkeypatch, "ec2-idle-instance-review", "schedule_collision", profile)


def _mutate_note(results: dict, execution: dict, mutation: str | None) -> None:
    if mutation == "note":
        execution["coverage_notes"][0]["unknown_compute_control"] = None
    elif mutation == "note_pair":
        execution["coverage_notes"][0]["config_key"] = "synthetic-customer-option"
    elif mutation == "note_limit":
        execution["coverage_notes"][0]["configured_limit"] = True
    elif mutation == "note_foreign":
        foreign = next(row for row in results["scanner_results"] if row["scanner_id"] != execution["scanner_id"])
        foreign["coverage_notes"] = execution["coverage_notes"]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "nested", "null_unknown", "tags", "foreign"])
def test_idle_unknowns_reject_and_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, mutation: str) -> None:
    """Aggregate collection children retain independent fail-closed preflight and cleanup."""
    _case(tmp_path, monkeypatch, "idle-zombie-resource-detector", "success", profile, mutation)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_idle_tag_keys_with_cost_tokens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    """Nested delegated tag maps retain independent validation and opaque-key semantics."""
    _force_cost_tokens(monkeypatch, "tag_key")
    _case(tmp_path, monkeypatch, "idle-zombie-resource-detector", "success", profile)


@pytest.mark.parametrize("field", ["provider_id", "evidence_module", "evidence_type", "scanner_id"])
def test_untrusted_identity_metadata_remains_scanned(field: str) -> None:
    """An invalid producer cannot claim the exact admitted envelope metadata view."""
    source = compute_producer_observation("ec2-idle-instance-review")["evidence"]
    source[field] = "synthetic-untrusted-identity"
    content = json.dumps({"scanner_evidence": [source]})
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=content, known_original_values={"synthetic-untrusted-identity"}
    )
    assert not result.passed


def _force_cost_tokens(monkeypatch: pytest.MonkeyPatch, category: str) -> None:
    """Force one key role without changing token registration or scanner behaviour."""
    original = TokenV1Codec.candidate

    def candidate(
        self: TokenV1Codec, *, token_key: bytes, provider: str, domain: TokenDomain, canonical: CanonicalValue, collision_index: int, suffix_bytes: int
    ) -> str:
        token = original(
            self, token_key=token_key, provider=provider, domain=domain, canonical=canonical, collision_index=collision_index, suffix_bytes=suffix_bytes
        )
        return token.split("-", 1)[0] + "-COST" + token.split("-", 1)[1][:12] if canonical.category == category else token

    monkeypatch.setattr(TokenV1Codec, "candidate", candidate)
