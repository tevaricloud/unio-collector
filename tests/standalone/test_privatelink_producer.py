"""Real PrivateLink producer privacy, finite facts and identifier consistency."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_privatelink_fixture import VARIANTS, privatelink_producer_case
from unio_collector.aws.network.private_link_record import PrivateLinkRegionRecord
from unio_collector.privacy.network.privatelink import FIELDS
from unio_collector.scanners.network.privatelink.evidence import PrivateLinkCostReviewEvidence

pytestmark = pytest.mark.offline


def test_privatelink_dto_fields() -> None:
    """Compare explicit schema fields to the actual producer's dataclasses."""
    for prefix, model in (("", PrivateLinkCostReviewEvidence), ("records[].", PrivateLinkRegionRecord)):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_privatelink_profiles(variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Protect whole customer names while retaining counts and collection limitations."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row = privatelink_producer_case(variant)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    text = json.dumps(result)
    for sensitive in ("123456789012", "synthetic-customer", "vpce-00000000000000000", "vpce-svc-00000000000000000"):
        assert sensitive not in text
    for old, new in zip(row["payload"]["records"], result["records"], strict=True):
        for key in (
            "interface_endpoint_count",
            "gateway_load_balancer_endpoint_count",
            "available_endpoint_count",
            "pending_endpoint_count",
            "tagged_endpoint_count",
            "endpoint_service_count",
        ):
            assert old[key] == new[key]
    if profile == "strict":
        assert result["topology"] == []
        assert "com.amazonaws.eu-west-2.ec2" not in text
        return
    before, after = row["payload"]["topology"][0], result["topology"][0]
    assert before["relation_state"] == after["relation_state"]
    assert [v["state"] for v in before["coverage"]] == [v["state"] for v in after["coverage"]]
    _assert_relationships(before, after, result["records"][0]["endpoint_service_names"])


def _assert_relationships(before: dict[str, Any], after: dict[str, Any], service_names: list[str]) -> None:
    """Check public constants, private fallback identities and tag policy independently."""
    for old, new in zip(before["resources"], after["resources"], strict=True):
        if old["facts"].get("ServiceName") == "com.amazonaws.eu-west-2.ec2":
            assert new["facts"]["ServiceName"] == old["facts"]["ServiceName"]
        if old["identity"] == old["facts"].get("ServiceName"):
            assert new["identity"] == new["facts"]["ServiceName"]
        for tag in new["facts"].get("Tags") or []:
            assert tag["Value"].startswith("TAG-")
            if any(item["Key"] == "Name" for item in old["facts"].get("Tags") or []):
                assert tag["Key"] == "Name"
        if new["kind"] == "vpc_endpoint_service_configurations" and new["facts"].get("ServiceName"):
            assert new["facts"]["ServiceName"] in service_names


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "facts", "tags", "state", "wrong_kind"])
def test_privatelink_unknown_preflight(profile: str, mutation: str) -> None:
    """Closed preflight also rejects unknowns hidden by strict topology removal."""
    row = privatelink_producer_case()
    payload = row["payload"]
    resource = next(v for v in payload["topology"][0]["resources"] if v["kind"] == "vpc_endpoints")
    if mutation == "wrong_kind":
        resource["kind"] = "addresses"
    else:
        target = (
            payload
            if mutation == "root"
            else payload["records"][0]
            if mutation == "record"
            else resource["facts"]["Tags"][0]
            if mutation == "tags"
            else resource["facts"]
        )
        target["State" if mutation == "state" else "unknown_privatelink_container"] = "future-state" if mutation == "state" else {}
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified
