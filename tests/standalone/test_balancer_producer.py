"""Actual load-balancer and current metric privacy contract regressions."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_balancer_fixture import VARIANTS, balancer_producer_case
from unio_collector.aws.load_balancer.record import LoadBalancerRecord
from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.summary import MetricSummary
from unio_collector.privacy.ec2.load_balancer import FIELDS, VOCABULARIES
from unio_collector.scanners.inventory_evidence import InventoryEvidence

pytestmark = pytest.mark.offline


def test_balancer_independent_contract() -> None:
    """Check complete DTO and offline SDK contracts independently of fixture generation."""
    for prefix, model in (
        ("", InventoryEvidence),
        ("records[].", LoadBalancerRecord),
        ("records[].metrics[].", MetricSummary),
        ("records[].metrics[].datapoints[].", MetricDatapoint),
    ):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}
    shapes = Loader().load_service_model("elbv2", "service-2")["shapes"]
    assert VOCABULARIES["lb_type"] == set(shapes["LoadBalancerTypeEnum"]["enum"]) | {"unknown"}
    assert VOCABULARIES["lb_state"] == set(shapes["LoadBalancerStateEnum"]["enum"]) | {"unknown"}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("mode", ["full", "summary"])
@pytest.mark.parametrize("tags", [True, False])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_balancer_actual_profiles(variant: str, mode: str, profile: str, monkeypatch: pytest.MonkeyPatch, *, tags: bool) -> None:
    """Exercise actual current producers and preserve incomplete metric observations."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, statuses = balancer_producer_case(variant, mode, tags=tags)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert statuses
    assert result["metadata"] == row["payload"]["metadata"]
    assert "synthetic-customer" not in json.dumps(result)
    assert len(result["records"]) == len(row["payload"]["records"])
    for before, after in zip(row["payload"]["records"], result["records"], strict=True):
        assert after["load_balancer_arn"] != before["load_balancer_arn"]
        assert after["region"] == ("aws-region" if profile == "strict" else before["region"])
        assert after["target_health_metadata_collected"] == before["target_health_metadata_collected"]
        assert after["tags_collected"] == before["tags_collected"]
        assert len(after["collection_errors"]) == len(before["collection_errors"])
        for old, new in zip(before["metrics"], after["metrics"], strict=True):
            assert new["collection_evidence_version"] == 1
            for key in (
                "collection_context",
                "collection_status",
                "collection_reason",
                "observed_min",
                "observed_max",
                "observed_average",
                "observed_average_parts",
            ):
                assert new[key] == old[key]
            assert bool(new["limitation"]) == bool(old["limitation"])
            if old["limitation"]:
                assert new["limitation"] != old["limitation"]
            assert new["start_time"] == (old["start_time"][:7] if profile == "strict" else old["start_time"])
            if variant in {"metrics_failed", "metrics_partial"}:
                assert new["observed_average"] is None
                assert new["observed_average_parts"] is None


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metadata", "metric", "datapoint", "tags", "path"])
def test_balancer_unknown_fields(profile: str, location: str) -> None:
    """Reject unknown descendants and literal path impersonation before transformation."""
    row, _ = balancer_producer_case()
    payload = row["payload"]
    record = payload["records"][0]
    metric = record["metrics"][0]
    if location == "path":
        payload["records[].metrics[].namespace"] = "AWS/ApplicationELB"
    else:
        target = {
            "root": payload,
            "record": record,
            "metadata": payload["metadata"],
            "metric": metric,
            "datapoint": metric["datapoints"][0],
            "tags": record["tags"],
        }[location]
        target["unknown_synthetic_field"] = {}
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("namespace", "synthetic-secret"),
        ("collection_status", "unknown"),
        ("collection_status", "partial"),
        ("collection_reason", 999),
        ("collection_context", 1),
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
def test_balancer_metric_malformed(profile: str, key: str, value: object) -> None:
    """Reject unknown formats, nonfinite or contradictory aggregates and malformed tuples."""
    row, _ = balancer_producer_case()
    row["payload"]["records"][0]["metrics"][0][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_balancer_registered_legacy(profile: str) -> None:
    """Retain the registered historical DTO identity and version-zero metrics."""
    row, _ = balancer_producer_case()
    row["evidence_module"] = row["evidence_module"].replace("inventory_evidence", "fixture_parity.synthetic_types")
    row["evidence_type"] = "LoadBalancerFixtureEvidence"
    for record in row["payload"]["records"]:
        for metric in record["metrics"]:
            metric["collection_evidence_version"] = 0
            for key in ("collection_context", "collection_status", "collection_reason", "observed_average_parts"):
                metric[key] = None
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified


@pytest.mark.parametrize(
    ("key", "value"),
    [("provider_id", "foreign"), ("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("evidence_schema_id", "unknown.schema")],
)
def test_balancer_identity_conflicts(key: str, value: str) -> None:
    """Foreign or conflicting identities cannot use the specific metric policy."""
    row, _ = balancer_producer_case()
    row[key] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
