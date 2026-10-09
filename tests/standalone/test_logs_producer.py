"""Actual CloudWatch Logs producer coverage and closed privacy contracts."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_logs_fixture import ACTIVITY_SCANNERS, SCANNERS, VARIANTS, logs_producer_case
from unio_collector.aws.cloudwatch.log.constants import CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED, CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE
from unio_collector.aws.log.group.activity import LogGroupActivityRecord
from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.summary import MetricSummary
from unio_collector.privacy.log_activity import FIELDS, VOCABULARIES
from unio_collector.scanners.cloudwatch.log_activity.evidence import CloudWatchLogActivityEvidence

pytestmark = pytest.mark.offline
DEFAULT_IDLE_DAYS = 30


def test_logs_independent_contract() -> None:
    """Match actual DTO fields and producer status constants independently."""
    for prefix, model in (
        ("", CloudWatchLogActivityEvidence),
        ("records[].", LogGroupActivityRecord),
        ("records[].metrics[].", MetricSummary),
        ("records[].metrics[].datapoints[].", MetricDatapoint),
    ):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}
    assert VOCABULARIES["log_status"] == {CLOUDWATCH_LOG_METRIC_STATUS_COLLECTED, CLOUDWATCH_LOG_METRIC_STATUS_SKIPPED_BY_DETAIL_MODE}


@pytest.mark.parametrize("scanner", SCANNERS)
@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("mode", ["full", "regional", "global"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_logs_profiles(scanner: str, variant: str, mode: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cross real collection and serialization without constructing SDK clients."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, statuses, notes = logs_producer_case(scanner, variant, mode)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert statuses
    assert "/synthetic/customer" not in json.dumps(result)
    assert len(result["records"]) == len(row["payload"]["records"])
    for before, after in zip(row["payload"]["records"], result["records"], strict=True):
        assert before["log_group_name"] != after["log_group_name"]
        assert after["region"] == ("aws-region" if profile == "strict" else before["region"])
        assert after["stored_bytes"] == before["stored_bytes"]
        if scanner not in ACTIVITY_SCANNERS:
            continue
        assert result["idle_days"] == DEFAULT_IDLE_DAYS
        assert before["retention_in_days"] == after["retention_in_days"]
        assert before["metric_collection_status"] == after["metric_collection_status"]
        assert bool(before["metric_collection_reason"]) == bool(after["metric_collection_reason"])
        assert after["creation_time"] == (before["creation_time"][:7] if profile == "strict" and before["creation_time"] else before["creation_time"])
        for old, new in zip(before["metrics"], after["metrics"], strict=True):
            for field in (
                "namespace",
                "metric_name",
                "statistic",
                "observed_average",
                "observed_average_parts",
                "collection_status",
                "collection_context",
                "collection_reason",
            ):
                assert old[field] == new[field]
            assert new["start_time"] == (old["start_time"][:7] if profile == "strict" else old["start_time"])
            assert bool(new["limitation"]) == bool(old["limitation"])
    if scanner in ACTIVITY_SCANNERS and mode != "full" and len(result["records"]) > 1:
        assert notes
        assert any(v["metric_collection_status"] == "skipped_by_metric_detail_mode" for v in result["records"])


@pytest.mark.parametrize("scanner", ACTIVITY_SCANNERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metric", "datapoint", "tags", "path"])
@pytest.mark.parametrize("value", [{}, [], "synthetic-unknown"])
def test_logs_unknown_fields(scanner: str, profile: str, location: str, value: object) -> None:
    """Unknown empty/populated fields and literal paths reject before reduction."""
    row, _, _ = logs_producer_case(scanner)
    p = row["payload"]
    record = p["records"][0]
    metric = record["metrics"][0]
    if location == "path":
        p["records[].region"] = value
    else:
        target = {"root": p, "record": record, "metric": metric, "datapoint": metric["datapoints"][0], "tags": record["tags"]}[location]
        target["unknown_logs_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert bool(t.summary.unclassified) == (location != "tags" or not isinstance(value, str))


@pytest.mark.parametrize("scanner", ACTIVITY_SCANNERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("days", [-1, 0, 90])
def test_logs_signed_policy(scanner: str, profile: str, days: int) -> None:
    """Keep the actual parser's signed idle threshold semantics."""
    row, _, _ = logs_producer_case(scanner, idle_days=days)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert result["scanner_evidence"][0]["payload"]["idle_days"] == days


@pytest.mark.parametrize("scanner", ACTIVITY_SCANNERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_logs_legacy_and_identity(scanner: str, profile: str) -> None:
    """Accept registered historical metrics but reject conflicting schema identities."""
    row, _, _ = logs_producer_case(scanner)
    row.update(evidence_module="unio_collector.scanners.fixture_parity.synthetic_types", evidence_type="CloudWatchLogActivityFixtureEvidence")
    for record in row["payload"]["records"]:
        for metric in record["metrics"]:
            metric["collection_evidence_version"] = 0
            for key in ("collection_context", "collection_status", "collection_reason", "observed_average_parts"):
                metric[key] = None
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    for changes in (
        {"provider_id": "other"},
        {"evidence_type": "Other"},
        {"evidence_module": "other"},
        {"evidence_schema_id": "aws.cloudwatch.log-retention", "evidence_schema_version": 1},
    ):
        with pytest.raises(ValueError, match="identity|schema"):
            transformer(profile).transform({"scanner_evidence": [{**row, **changes}]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("namespace", "synthetic-secret"),
        ("metric_name", "unknown"),
        ("statistic", "unknown"),
        ("interpretation", "unknown"),
        ("collection_status", "unknown"),
        ("collection_status", "partial"),
        ("collection_reason", 999),
        ("collection_context", 3),
        ("collection_evidence_version", 2),
        ("observed_average", "NaN"),
        ("observed_average", "99"),
        ("observed_average_parts", [0, [99], 0]),
        ("observed_average_parts", [0, [], 0]),
        ("observed_average_parts", [0, [2], True]),
        ("observed_average_parts", [0, [2], 0, 0]),
        ("observed_average_parts", None),
    ],
)
def test_logs_metric_malformed(profile: str, key: str, value: object) -> None:
    """Reject unknown formats, nonfinite or contradictory aggregates and malformed tuples."""
    row, _, _ = logs_producer_case(ACTIVITY_SCANNERS[0])
    row["payload"]["records"][0]["metrics"][0][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("metric_collection_status", "unknown"),
        ("metric_collection_reason", []),
        ("stored_bytes", True),
        ("stored_bytes", -1),
        ("retention_in_days", "30"),
        ("creation_time", "not-a-date"),
        ("creation_time", {}),
        ("tags", {"Name": {}}),
    ],
)
def test_logs_record_types(profile: str, key: str, value: object) -> None:
    """Reject malformed known fields rather than treating them as safe metadata."""
    row, _, _ = logs_producer_case(ACTIVITY_SCANNERS[0])
    row["payload"]["records"][0][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_logs_boolean_threshold(profile: str) -> None:
    """A boolean is not a serialized integer idle-days policy."""
    row, _, _ = logs_producer_case(ACTIVITY_SCANNERS[0])
    row["payload"]["idle_days"] = True
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified
