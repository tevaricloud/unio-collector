"""Closed account-risk privacy verified against actual current producer contracts."""

from __future__ import annotations

import copy
import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_risk_fixture import account_risk_producer_payload
from unio_collector.aws.account.risk.record import AccountCostRiskRecord
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.privacy.account_risk import FIELDS, IAM_COUNTERS, TRAIL_FIELDS
from unio_collector.scanners.account_risk.cost.evidence import AccountCostRiskEvidence

pytestmark = pytest.mark.offline
VARIANTS = ("success", "empty", "unavailable", "denied", "partial", "capped", "status_unavailable", "name_only")


def test_account_risk_contract_matches_producer_and_provider_shapes() -> None:
    """Independent DTO/API field inventories cannot silently agree with a tiny fixture."""
    for prefix, dto in (("", AccountCostRiskEvidence), ("account_risk.", AccountCostRiskRecord), ("daily_costs[].", DailyCostRecord)):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(dto)}
    loader = Loader()
    assert set(TRAIL_FIELDS) == set(loader.load_service_model("cloudtrail", "service-2")["shapes"]["Trail"]["members"])
    shapes = loader.load_service_model("iam", "service-2")["shapes"]
    assert set(IAM_COUNTERS) == set(shapes[shapes["summaryMapType"]["key"]["shape"]]["enum"])
    risk = account_risk_producer_payload()["payload"]["account_risk"]
    assert set(risk["trails"][0]) == set(TRAIL_FIELDS)
    assert set(risk["iam_summary"]) == set(IAM_COUNTERS)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", VARIANTS)
def test_actual_account_risk_profiles(profile: str, variant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Protect complete and limited actual responses without changing observed signals."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    payload = account_risk_producer_payload(variant)
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert "synthetic-customer" not in json.dumps(protected)
    assert "123456789012" not in json.dumps(protected)
    record = protected["scanner_evidence"][0]["payload"]
    risk = record["account_risk"]
    original = payload["payload"]["account_risk"]
    assert risk["iam_summary"] == original["iam_summary"]
    assert risk["cloudtrail_available"] == original["cloudtrail_available"]
    assert risk["trail_statuses_complete"] == original["trail_statuses_complete"]
    assert risk["trail_status_omitted_count"] == original["trail_status_omitted_count"]
    assert bool(risk["collection_errors"]) == bool(original["collection_errors"])
    for trail, status in zip(risk["trails"], risk["trail_statuses"], strict=False):
        assert status["trail"] == trail.get("TrailARN", trail["Name"])
        assert trail["HomeRegion"] == ("aws-region" if profile == "strict" else "eu-west-2")
        assert status.get("latest_delivery_error") in (None, "")
    daily = record["daily_costs"]
    if profile == "strict":
        assert daily is None
    else:
        assert daily[1]["usage_type"] is None
        assert daily[0]["date"] == "2026-09-01"
        assert daily[0]["region"] == "eu-west-2"
        assert daily[0]["cost"] == "12.75"
        assert daily[0]["currency"] == "USD"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-unknown", 1])
@pytest.mark.parametrize("location", ["envelope", "payload", "risk", "trail", "status", "iam", "daily"])
def test_account_risk_unknown_descendants_reject(profile: str, value: object, location: str) -> None:
    """Preflight unknown names and empty/null containers before profile omission."""
    row = account_risk_producer_payload("partial")
    payload = row["payload"]
    risk = payload["account_risk"]
    target = {
        "envelope": row,
        "payload": payload,
        "risk": risk,
        "trail": risk["trails"][0],
        "status": risk["trail_statuses"][0],
        "iam": risk["iam_summary"],
        "daily": payload["daily_costs"][0],
    }[location]
    target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(p.endswith("unknown_synthetic_field") for p in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], True, -1, "synthetic-private", 1.5])
def test_iam_counters_do_not_admit_other_types(profile: str, value: object) -> None:
    """Finite counter names accept only nonnegative integers, never arbitrary data."""
    row = account_risk_producer_payload()
    row["payload"]["account_risk"]["iam_summary"]["Users"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(p.endswith("iam_summary.Users") for p in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_account_risk_optional_payload_and_scope_reset(profile: str) -> None:
    """Optional missing account observations remain valid, without admitting another scanner."""
    row = account_risk_producer_payload()
    other = copy.deepcopy(row)
    other.update(scanner_id="synthetic-other", evidence_type="Other", evidence_module="synthetic")
    row["payload"]["account_risk"] = None
    t = transformer(profile)
    actual = t.transform({"scanner_evidence": [row, other]}, file_name="scan-result/scanner-evidence.json")
    assert actual["scanner_evidence"][0]["payload"]["account_risk"] is None
    assert any(p.endswith("S3BucketName") for p in t.summary.unclassified)


@pytest.mark.parametrize(
    ("key", "value"), [("provider_id", "azure"), ("evidence_module", "synthetic"), ("evidence_type", "Other"), ("evidence_schema_id", "synthetic.unknown")]
)
def test_account_risk_metadata_conflicts_reject(key: str, value: object) -> None:
    """Scanner labels cannot grant privacy admission to foreign or malformed identities."""
    row = account_risk_producer_payload()
    row[key] = value
    with pytest.raises(ValueError, match="[Ss]chema|matching legacy AWS evidence identity"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("location", "value"),
    [
        ("cost", "synthetic-private"),
        ("cost", {}),
        ("cost", float("nan")),
        ("logging", "yes"),
        ("flag", None),
        ("diagnostic", {}),
    ],
)
def test_known_fields_reject_malformed_values_before_removal(profile: str, location: str, value: object) -> None:
    """Known names cannot hide wrong types inside strict-removed financial/diagnostic data."""
    row = account_risk_producer_payload("partial")
    risk = row["payload"]["account_risk"]
    target, key = {
        "cost": (row["payload"]["daily_costs"][0], "cost"),
        "logging": (risk["trail_statuses"][0], "is_logging"),
        "flag": (risk["trails"][0], "IsMultiRegionTrail"),
        "diagnostic": (risk["trail_statuses"][0], "latest_delivery_error"),
    }[location]
    target[key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(p.endswith(key) for p in t.summary.unclassified)
