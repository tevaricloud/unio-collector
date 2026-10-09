"""Populated permission producer contracts survive private and public protection."""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from tools.collector_permission_fixture import LEDGER_CASES, SCANNER_STATUSES, permission_producer_payloads
from unio_collector.collector.protocol import DEFAULT_PROTOCOL
from unio_collector.evidence.permission.planning.degradation import PermissionDegradationRecord
from unio_collector.evidence.permission.planning.outcome_effect import confidence_effect_for_outcome, evidence_interpretation_for_outcome
from unio_collector.evidence.permission.planning.summary_stats import LIMITATION_CATEGORY_BY_OUTCOME
from unio_collector.privacy.crypto import derive_subkey, generate_root_key
from unio_collector.privacy.permission_fields import PERMISSION_COUNTS
from unio_collector.privacy.producer_fields import reduce_strict_pricing_context
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder
from unio_collector.privacy.transform import PrivacyTransformer
from unio_collector.scanners.scanner.permission_summary import ScannerPermissionSummary

pytestmark = pytest.mark.offline
FIXTURES = Path(__file__).parent / "fixtures"


def actual_payloads() -> dict[str, bytes]:
    """Use the same complete writer output as packaged protection smoke."""
    return permission_producer_payloads(json.loads((FIXTURES / "protection-producers.json").read_text()))


def test_permission_contract_uses_populated_actual_producers() -> None:
    """Expect producer DTO fields and categories independently of registry entries."""
    files = actual_payloads()
    events = [json.loads(line) for line in files["collection-log.jsonl"].splitlines()]
    assert [event[DEFAULT_PROTOCOL.namespace]["error_category"] for event in events] == [case[4] for case in LEDGER_CASES]
    summary = json.loads(files["permissions-summary.json"])
    assert summary["available_actions"]
    assert summary["missing_actions"]
    assert summary["service_unavailable_actions"]
    assert set(summary["scanner_permissions"][0]) == {field.name for field in fields(ScannerPermissionSummary)}
    assert {row["scanner_status"] for row in summary["scanner_permissions"]} == set(SCANNER_STATUSES)
    records = json.loads(files["permissions/degradation-records.json"])["records"]
    assert records
    assert all(set(record) == {field.name for field in fields(PermissionDegradationRecord)} - {"technical_detail"} for record in records)
    outcomes = {"available", *LIMITATION_CATEGORY_BY_OUTCOME}
    assert set(PERMISSION_COUNTS["outcomes"]) == outcomes
    assert set(PERMISSION_COUNTS["confidence_effects"]) == {confidence_effect_for_outcome(outcome) for outcome in outcomes}
    assert set(PERMISSION_COUNTS["evidence_interpretations"]) == {evidence_interpretation_for_outcome(outcome) for outcome in outcomes}


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_complete_writer_output_has_explicit_privacy_coverage(profile: str) -> None:
    """Classify real populated writer output, including repeated readiness views."""
    transformer = PrivacyTransformer(
        token_service=TokenService(
            token_key=derive_subkey(generate_root_key(), "token-hmac"),
            provider="aws",
            token_scope="engagement",  # noqa: S106
            engagement_id="synthetic",
            vault_builder=TokenVaultBuilder(),
        ),
        profile=load_privacy_profile(profile),
        allow_unknown_fields=False,
    )
    protected: dict[str, bytes] = {}
    for member, data in actual_payloads().items():
        rows: list[Any] = [json.loads(line) for line in data.splitlines()] if member.endswith(".jsonl") else [json.loads(data)]
        transformed = [transformer.transform(row, file_name=member) for row in rows]
        if member.endswith(".jsonl"):
            protected[member] = b"" if profile == "strict" else b"\n".join(json.dumps(row).encode() for row in transformed)
        else:
            if member == "scan-result/pricing-context.json" and profile == "strict":
                transformed[0] = reduce_strict_pricing_context(transformed[0])
            protected[member] = json.dumps(transformed[0]).encode()
    assert transformer.summary.unclassified == []
    assert transformer.summary.prohibited_paths == []
    StrictTransformationVerifier().verify(protected, load_privacy_profile(profile))
    summary = json.loads(protected["permissions-summary.json"])
    original = json.loads(actual_payloads()["permissions-summary.json"])
    for key in PERMISSION_COUNTS:
        assert summary["permission_degradation"][key] == original["permission_degradation"][key]
    assert "synthetic provider diagnostic" not in protected["permissions-summary.json"].decode()
    assert "123456789012" not in b"".join(protected.values()).decode()


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["counts", "detail", "record", "manifest"])
@pytest.mark.parametrize("unknown", [None, {}, [], 7])
def test_unknown_permission_fields_reject_without_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile: str, location: str, unknown: object
) -> None:
    """Future fields and finite counter keys must reject before publication."""
    import hashlib  # noqa: PLC0415
    import io  # noqa: PLC0415
    from zipfile import ZipFile  # noqa: PLC0415

    from tools.build_native_collector import _add_synthetic_region_scope  # noqa: PLC0415
    from unio_collector.collector.bundle.checksums import build_checksums  # noqa: PLC0415
    from unio_collector.collector_cli.app import main  # noqa: PLC0415

    source = tmp_path / "source.zip"
    assert main(["collect", "--fixture", str(FIXTURES / "cost.json"), "--output", str(source), "--quiet"]) == 0
    _add_synthetic_region_scope(source, FIXTURES / "region-scope.json")
    with ZipFile(source) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    member = "manifest.json" if location == "manifest" else "permissions/degradation-records.json" if location == "record" else "permissions-summary.json"
    payload = json.loads(members[member])
    target = (
        payload["permission_limitations"][0]
        if location == "manifest"
        else payload["records"][0]
        if location == "record"
        else payload["permission_degradation"]["outcomes"]
        if location == "counts"
        else payload["permission_degradation"]["degradation_details"][0]
    )
    target["unknown_synthetic_field"] = unknown
    members[member] = json.dumps(payload).encode()
    checksums = build_checksums(members)
    manifest = json.loads(members["manifest.json"])
    manifest["checksums"] = checksums
    members["manifest.json"] = json.dumps(manifest).encode()
    members["checksums.json"] = json.dumps({"algorithm": "sha256", "checksums": checksums}).encode()
    with ZipFile(source, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
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
        == 1
    )
    assert not output.exists()
    assert not vault.exists()
    assert not output.with_suffix(".zip.receipt.json").exists()
    assert not list(tmp_path.rglob("*.tmp"))
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
