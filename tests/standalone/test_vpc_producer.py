"""Actual current VPC wrapper topology branches and privacy relationships."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_vpc_fixture import VARIANTS, vpc_producer_case

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_current_vpc_producer(variant: str, profile: str) -> None:
    """Actual six-kind collection, projection and serialization precede privacy."""
    row = vpc_producer_case(variant)
    assert row["payload"]["records"] == []
    assert {c["collection_name"] for c in row["payload"]["topology"][0]["coverage"]} == {
        "vpcs",
        "subnets",
        "route_tables",
        "vpc_endpoints",
        "nat_gateways",
        "network_interfaces",
    }
    t = transformer(profile)
    payload = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    for value in ("123456789012", "synthetic-customer", "vpc-00000000000000000", "nat-00000000000000000"):
        assert value not in json.dumps(payload)
    if profile == "strict":
        assert payload["topology"] == []
    else:
        assert [c["state"] for c in payload["topology"][0]["coverage"]] == [c["state"] for c in row["payload"]["topology"][0]["coverage"]]
