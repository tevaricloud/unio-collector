"""Independent snapshot producer contract, profile and fail-closed coverage."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_snapshot_fixture import VARIANTS, snapshot_producer_case
from unio_collector.aws.snapshot.record import SnapshotRecord
from unio_collector.privacy.ec2.snapshot import SnapshotPrivacyContract
from unio_collector.scanners.inventory_evidence import InventoryEvidence

pytestmark = pytest.mark.offline


def test_snapshot_dto_fields() -> None:
    """Independent actual DTO fields cannot silently outgrow the closed contract."""
    for prefix, model in (("", InventoryEvidence), ("records[].", SnapshotRecord)):
        declared = {
            p[len(prefix) :]
            for p in SnapshotPrivacyContract.fields
            if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]
        }
        assert declared == {field.name for field in fields(model)}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("threshold", [None, -1, 0, 30, 365])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_snapshot_actual_wrapper(variant: str, threshold: int | None, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve wrapper metadata, numeric signals and producer failure semantics."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, statuses, warnings = snapshot_producer_case(variant, threshold)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert result["metadata"] == {"older_than_days": 90 if threshold is None else threshold}
    expected = {"denied": "permission_denied", "unsupported": "unsupported_region", "unavailable": "failed", "failure": "failed", "partial": "throttled"}.get(
        variant, "completed"
    )
    assert statuses == [expected]
    assert bool(warnings) == (expected != "completed")
    assert len(result["records"]) == int(variant in {"success", "optional", "future"})
    assert "synthetic-customer" not in json.dumps(result)
    for old, new in zip(row["payload"]["records"], result["records"], strict=True):
        assert new["snapshot_id"] != old["snapshot_id"]
        assert new["account_id"] != old["account_id"]
        assert new["volume_size_gib"] == old["volume_size_gib"]
        assert new["age_days"] == old["age_days"] == (0 if variant == "future" else 30)
        assert new["region"] == ("aws-region" if profile == "strict" else old["region"])
        assert new["start_time"] == (old["start_time"][:7] if profile == "strict" else old["start_time"])
        if variant == "optional":
            assert new["volume_id"] is None
            assert new["description"] is None
        else:
            assert new["volume_id"] != old["volume_id"]
            assert new["description"] != old["description"]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metadata", "tags", "path"])
def test_snapshot_nested_unknown(profile: str, location: str) -> None:
    """Reject unknown keys and path syntax before any profile-driven omission."""
    row, _, _ = snapshot_producer_case()
    payload = row["payload"]
    record = payload["records"][0]
    if location == "path":
        payload["records[].start_time"] = record["start_time"]
    else:
        target = {"root": payload, "record": record, "metadata": payload["metadata"], "tags": record["tags"]}[location]
        target["unknown_synthetic_field"] = {}
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_snapshot_registered_legacy_nullable_timestamp(profile: str) -> None:
    """Retain the registered historical identity and nullable DTO date contract."""
    row, _, _ = snapshot_producer_case("optional")
    row["evidence_module"] = row["evidence_module"].replace("inventory_evidence", "fixture_parity.synthetic_types")
    row["evidence_type"] = "SnapshotFixtureEvidence"
    row["payload"]["records"][0]["start_time"] = None
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert result["scanner_evidence"][0]["payload"]["records"][0]["start_time"] is None


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("key", "value"), [("start_time", "synthetic-invalid-date"), ("description", {}), ("volume_size_gib", -1), ("age_days", True), ("snapshot_id", None)]
)
def test_snapshot_malformed_fields(profile: str, key: str, value: object) -> None:
    """Wrongly typed known fields cannot bypass the explicit contract."""
    row, _, _ = snapshot_producer_case()
    row["payload"]["records"][0][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [True, "90", None, {}, []])
def test_snapshot_malformed_threshold(profile: str, value: object) -> None:
    """Reject malformed metadata without changing valid signed integer thresholds."""
    row, _, _ = snapshot_producer_case()
    row["payload"]["metadata"]["older_than_days"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("key", "value"),
    [("provider_id", "foreign"), ("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("evidence_schema_id", "unknown.schema")],
)
def test_snapshot_identity_conflicts(key: str, value: str) -> None:
    """Unrecognized identities cannot borrow the snapshot privacy contract."""
    row, _, _ = snapshot_producer_case()
    row[key] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
