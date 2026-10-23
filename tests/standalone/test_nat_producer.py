"""Actual NAT inventory privacy fields, admission and legacy metric compatibility."""

from __future__ import annotations

import copy
import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_nat_fixture import REJECTED_VARIANTS, VARIANTS, nat_producer_case
from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.summary import MetricSummary
from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
from unio_collector.privacy.ec2.nat_inventory import FIELDS, VOCABULARIES
from unio_collector.scanners.inventory_evidence import InventoryEvidence

pytestmark = pytest.mark.offline


def test_nat_independent_contract() -> None:
    """Bind every declared leaf to actual DTO fields and offline SDK vocabularies."""
    for prefix, model in (
        ("", InventoryEvidence),
        ("records[].", NatGatewayRecord),
        ("records[].metric_summaries[].", MetricSummary),
        ("records[].metric_summaries[].datapoints[].", MetricDatapoint),
    ):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(model)}
    shapes = Loader().load_service_model("ec2", "service-2")["shapes"]
    for field, kind, fallback in (("State", "nat_state", {"unknown"}), ("ConnectivityType", "connectivity", set())):
        assert set(shapes[shapes["NatGateway"]["members"][field]["shape"]]["enum"]) | fallback == VOCABULARIES[kind]


@pytest.mark.parametrize("variant", REJECTED_VARIANTS)
def test_nat_incomplete_admission(variant: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual cached inventory admission refuses partial/failed/malformed enumeration."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    with pytest.raises(ValueError, match="incomplete network enumeration"):
        nat_producer_case(variant)


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_nat_profiles(variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve factual fields and nulls while protecting identifiers and strict dates."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, coverage = nat_producer_case(variant)
    assert coverage
    assert all(item["state"] == "complete" and item["enumeration_normal_termination"] for item in coverage)
    t = transformer(profile)
    after = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert "synthetic-customer" not in json.dumps(after)
    assert "123456789012" not in json.dumps(after)
    assert len(after["records"]) == len(row["payload"]["records"])
    for original, protected in zip(row["payload"]["records"], after["records"], strict=True):
        assert protected["state"] == original["state"]
        assert protected["connectivity_type"] == original["connectivity_type"]
        assert protected["region"] == ("aws-region" if profile == "strict" else "eu-west-2")
        for field in ("nat_gateway_id", "subnet_id", "vpc_id", "account_id"):
            assert protected[field] is None if original[field] is None else protected[field] != original[field]
        assert (
            protected["create_time"] is None
            if original["create_time"] is None
            else protected["create_time"] == ("2026-09" if profile == "strict" else original["create_time"])
        )
        assert len(protected["metric_summaries"]) == len(original["metric_summaries"])
        for old, new in zip(original["metric_summaries"], protected["metric_summaries"], strict=True):
            for field in ("namespace", "metric_name", "statistic", "observed_average", "collection_status", "collection_context"):
                assert new[field] == old[field]
            assert bool(new["limitation"]) == bool(old["limitation"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metadata", "tags", "literal", "metric", "point"])
@pytest.mark.parametrize("value", [{}, [], "synthetic-unknown"])
def test_nat_unknowns(profile: str, location: str, value: object) -> None:
    """Unknown empty/populated containers reject before any strict omission."""
    row, _ = nat_producer_case("legacy_metrics")
    payload = row["payload"]
    record = payload["records"][0]
    if location == "literal":
        payload["records[].region"] = value
    else:
        target = {
            "root": payload,
            "record": record,
            "metadata": payload["metadata"],
            "tags": record["tags"],
            "metric": record["metric_summaries"][0],
            "point": record["metric_summaries"][0]["datapoints"][0],
        }[location]
        target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert bool(t.summary.unclassified) == (location != "tags" or not isinstance(value, str))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state", "future"),
        ("state", None),
        ("connectivity_type", "future"),
        ("connectivity_type", 1),
        ("create_time", "not-a-date"),
        ("nat_gateway_id", {}),
        ("tags", {"owner": []}),
        ("metric_summaries", {}),
        ("account_id", False),
    ],
)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_nat_malformed_fields(field: str, value: object, profile: str) -> None:
    """Known names never authorize malformed values or future finite metadata."""
    row, _ = nat_producer_case()
    row["payload"]["records"][0][field] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("namespace", "AWS/Other"),
        ("metric_name", "Unknown"),
        ("statistic", "Average"),
        ("collection_context", 3),
        ("collection_status", "future"),
        ("observed_average", "NaN"),
        ("observed_average_parts", [0, [1], "0"]),
        ("period", -1),
    ],
)
def test_nat_malformed_metrics(field: str, value: object) -> None:
    """Compatible observations still use exact context and factual DTO validation."""
    row, _ = nat_producer_case("legacy_metrics")
    row["payload"]["records"][0]["metric_summaries"][0][field] = value
    t = transformer("strict")
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("field", "value"),
    [("provider_id", "other"), ("evidence_type", "Future"), ("evidence_module", "unio_collector.private"), ("evidence_schema_id", "aws.future")],
)
def test_nat_identity_conflicts(field: str, value: str) -> None:
    """No nearby schema or provider identity inherits NAT admission."""
    row, _ = nat_producer_case()
    row = copy.deepcopy(row)
    row[field] = value
    with pytest.raises(ValueError, match="(?i)(identity|schema)"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
