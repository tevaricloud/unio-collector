"""Complete NAT cost producer fields and conditional privacy invariants."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_nat_cost import VARIANTS, nat_cost_producer_case
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.aws.metric.datapoint import MetricDatapoint
from unio_collector.aws.metric.summary import MetricSummary
from unio_collector.aws.network.nat_gateway_record import NatGatewayRecord
from unio_collector.privacy.network.nat_cost import FIELDS
from unio_collector.scanners.network.nat_gateway.evidence import NatGatewayCostEvidence

pytestmark = pytest.mark.offline
METRIC_NAMES = frozenset(
    {
        "BytesInFromSource",
        "BytesOutToDestination",
        "PeakBytesPerSecond",
        "PeakPacketsPerSecond",
        "ActiveConnectionCount",
        "ErrorPortAllocation",
        "PacketsDropCount",
    }
)


def test_nat_cost_contract_matches_actual_dtos() -> None:
    """Independent dataclass inventories detect omitted fields, including nested metrics."""
    for prefix, model in (
        ("", NatGatewayCostEvidence),
        ("nat_gateways[].", NatGatewayRecord),
        ("nat_gateways[].metric_summaries[].", MetricSummary),
        ("nat_gateways[].metric_summaries[].datapoints[].", MetricDatapoint),
        ("daily_costs[].", DailyCostRecord),
    ):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(model)}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_nat_cost_actual_profiles(variant: str, profile: str) -> None:
    """Actual metrics and costs remain factual; strict removes financial values and topology."""
    row = nat_cost_producer_case(variant)
    t = transformer(profile)
    after = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    for value in ("123456789012", "synthetic-customer", "nat-00000000000000000"):
        assert value not in json.dumps(after)
    before = row["payload"]
    if variant == "daily_optional":
        assert before["daily_costs"][0]["usage_type"] is None
    assert len(after["nat_gateways"]) == len(before["nat_gateways"])
    if profile == "strict":
        assert after["topology"] == []
        assert after["daily_costs"] is None
    for old, new in zip(before["daily_costs"] if profile == "standard" else [], after["daily_costs"] or [], strict=True):
        assert new["cost"] == (None if profile == "strict" else old["cost"])
        assert new["currency"] == (None if profile == "strict" else old["currency"])
        assert new["date"] == ("2026-05" if profile == "strict" else old["date"])
    for old, new in zip(before["nat_gateways"], after["nat_gateways"], strict=True):
        assert old["state"] == new["state"]
        assert old["connectivity_type"] == new["connectivity_type"]
        assert {metric["metric_name"] for metric in new["metric_summaries"]} == METRIC_NAMES
        assert len(new["metric_summaries"]) == len(METRIC_NAMES)
        for a, b in zip(old["metric_summaries"], new["metric_summaries"], strict=True):
            for key in ("observed_average", "observed_average_parts", "collection_context", "collection_status", "collection_reason"):
                assert a[key] == b[key]
            assert bool(a["limitation"]) == bool(b["limitation"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metric", "point", "cost", "facts", "tag", "literal", "state"])
def test_nat_cost_nested_unknown_rejection(profile: str, location: str) -> None:
    """Unknown containers, malformed tags and enum values reject before strict removal."""
    row = nat_cost_producer_case()
    p = row["payload"]
    record = p["nat_gateways"][0]
    target = {
        "root": p,
        "record": record,
        "metric": record["metric_summaries"][0],
        "point": record["metric_summaries"][0]["datapoints"][0],
        "cost": p["daily_costs"][0],
        "facts": p["topology"][0]["resources"][0]["facts"],
        "tag": record["tags"],
        "literal": p,
        "state": record,
    }[location]
    target["nat_gateways[].state" if location == "literal" else "state" if location == "state" else "unknown_nat_cost_container"] = (
        "future-state" if location == "state" else {}
    )
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("field", "value"), [("namespace", "AWS/Other"), ("collection_context", 3), ("period", -1), ("observed_average", "NaN"), ("collection_status", "future")]
)
def test_nat_cost_metric_delegate_rejects_malformed_values(profile: str, field: str, value: object) -> None:
    """Delegated validation keeps its exact context and malformed-value checks."""
    row = nat_cost_producer_case()
    row["payload"]["nat_gateways"][0]["metric_summaries"][0][field] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified
    assert all(".nat_gateways" in path for path in t.summary.unclassified)


@pytest.mark.parametrize(
    ("field", "value"),
    [("provider_id", "other"), ("evidence_type", "Future"), ("evidence_module", "unio_collector.private"), ("evidence_schema_id", "aws.future")],
)
def test_nat_cost_identity_conflicts(field: str, value: str) -> None:
    """Related identities do not inherit the wrapper's delegated admission."""
    row = nat_cost_producer_case()
    row[field] = value
    with pytest.raises(ValueError, match="(?i)(identity|schema)"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
