"""Actual daily-cost producers must protect across every supported period form."""

from __future__ import annotations

import copy
from dataclasses import fields
from typing import get_args

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_daily_fixture import PERIODS, SCANNERS, daily_producer_payload
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.scan.period import PeriodKind, ScanPeriod
from unio_collector.privacy.daily_evidence import FIELDS, DailyEvidencePrivacyContract
from unio_collector.scanners.cost_explorer.daily_evidence import DailyCostEvidence

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner_id", SCANNERS)
@pytest.mark.parametrize("period_kind", [*PERIODS, "none"])
@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_daily_protection(*, scanner_id: str, period_kind: str, empty: bool, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Real collectors exercise optional periods, empty observations and populated costs."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    row = daily_producer_payload(scanner_id, period_kind, empty=empty)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    payload = result["scanner_evidence"][0]["payload"]
    if profile == "standard":
        assert payload == row["payload"]
    else:
        for record in payload["records"]:
            assert record.get("cost") in (None, "")
            assert record.get("currency") in (None, "")
            assert record["date"] == "2026-09"
        if period_kind != "none":
            assert payload["scan_period"]["kind"] == period_kind
            assert payload["scan_period"]["current_start_date"] == row["payload"]["scan_period"]["current_start_date"][:7]


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "period", "raw"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic"])
def test_daily_nested_unknowns(profile: str, location: str, value: object) -> None:
    """Unknown empty containers and values reject before strict omission."""
    row = copy.deepcopy(daily_producer_payload("data-transfer-cost-review"))
    payload = row["payload"]
    target = {"root": payload, "record": payload["records"][0], "period": payload["scan_period"], "raw": payload["scan_period"]["raw_input"]}[location]
    target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any("unknown_synthetic_field" in path for path in t.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "invented"),
        ("current_start_date", "2026-09"),
        ("current_end_date", "private text"),
        ("previous_start_date", None),
        ("raw_input.days", True),
        ("raw_input.months", 0),
        ("raw_input.years", -1),
        ("raw_input.date_from", "20260901"),
    ],
)
def test_daily_malformed_period_rejects(profile: str, field: str, value: object) -> None:
    """Finite period values and dates reject malformed data before generalisation."""
    row = daily_producer_payload("cost-spike-analysis")
    target = row["payload"]["scan_period"]
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


def test_daily_contract_matches_actual_dataclasses() -> None:
    """Independently compare producer fields and finite period vocabulary."""
    for prefix, dto in (("", DailyCostEvidence), ("records[].", DailyCostRecord), ("scan_period.", ScanPeriod)):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(dto)}
    assert set(PERIODS) == set(get_args(PeriodKind))
    for period_kind in get_args(PeriodKind):
        assert not DailyEvidencePrivacyContract().unknown_paths(
            daily_producer_payload("cost-spike-analysis", period_kind)["payload"], "scan-result/scanner-evidence.json"
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("provider_id", "foreign"), ("evidence_schema_id", "unknown.schema")],
)
def test_daily_identity_mismatch_rejects(field: str, value: str) -> None:
    """No matching by payload shape or cross-scanner reuse is permitted."""
    row = daily_producer_payload("cost-spike-analysis")
    row[field] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
