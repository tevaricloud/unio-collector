"""Actual public IPv4 inventory and topology through closed profile treatment."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_ipv4_fixture import VARIANTS, ipv4_producer_case
from unio_collector.aws.ec2.public_ipv4_record import PublicIpv4RegionRecord
from unio_collector.aws.network.coverage import NetworkCollectionCoverage
from unio_collector.aws.network.resource import NetworkResourceFact
from unio_collector.aws.network.topology import NetworkTopologyEvidence
from unio_collector.privacy.network.public_ipv4 import FIELDS
from unio_collector.scanners.network.public_ipv4.evidence import PublicIpv4Evidence

pytestmark = pytest.mark.offline


def test_ipv4_independent_dto_inventory() -> None:
    """Every actual envelope/record/coverage field needs an explicit treatment."""
    for prefix, model in (
        ("", PublicIpv4Evidence),
        ("records[].", PublicIpv4RegionRecord),
        ("topology[].", NetworkTopologyEvidence),
        ("topology[].resources[].", NetworkResourceFact),
        ("topology[].coverage[].", NetworkCollectionCoverage),
    ):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_ipv4_profiles(variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run actual producer branches and preserve scope/counts with protected identities."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row = ipv4_producer_case(variant)
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    text = json.dumps(protected)
    for sensitive in ("synthetic-customer", "123456789012", "203.0.113.10", "eipalloc-00000000000000000", "eni-00000000000000000"):
        assert sensitive not in text
    for before, after in zip(row["payload"]["records"], protected["records"], strict=True):
        for key in (
            "elastic_ip_count",
            "attached_elastic_ip_count",
            "unattached_elastic_ip_count",
            "eni_public_ip_count",
            "auto_assigned_public_ip_count",
            "tagged_address_count",
        ):
            assert after[key] == before[key]
    if profile == "strict":
        assert protected["topology"] == []
        return
    original = row["payload"]["topology"][0]
    result = protected["topology"][0]
    assert result["relation_state"] == original["relation_state"]
    assert [v["state"] for v in result["coverage"]] == [v["state"] for v in original["coverage"]]
    assert [v["reason_codes"] for v in result["coverage"]] == [v["reason_codes"] for v in original["coverage"]]
    resources = result["resources"]
    allocations = {v["facts"].get("AllocationId") for v in resources if v["kind"] == "addresses"}
    for resource in resources:
        if resource["kind"] == "addresses" and resource["facts"].get("PublicIp"):
            assert resource["identity"] == (resource["facts"].get("AllocationId") or resource["facts"]["PublicIp"])
        if resource["kind"] == "network_interfaces":
            association = resource["facts"].get("Association") or {}
            if association.get("AllocationId") and variant != "missing_id":
                assert association["AllocationId"] in allocations


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "record", "facts", "wrong_kind", "state", "nested", "kind"])
def test_ipv4_unknown_preflight(profile: str, mutation: str) -> None:
    """Reject unknowns before strict omission, including wrong-kind valid field names."""
    row = ipv4_producer_case()
    payload = row["payload"]
    resource = next(v for v in payload["topology"][0]["resources"] if v["kind"] == "network_interfaces")
    if mutation == "kind":
        resource["kind"] = {}
    elif mutation == "wrong_kind":
        resource["facts"]["NatGatewayId"] = None
    elif mutation == "state":
        resource["facts"]["InterfaceType"] = "customer-private-kind"
    else:
        target = (
            payload
            if mutation == "root"
            else payload["records"][0]
            if mutation == "record"
            else resource["facts"]["Association"]
            if mutation == "nested"
            else resource["facts"]
        )
        target["unknown_network_container"] = {}
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_id", "azure"),
        ("evidence_type", "InventoryEvidence"),
        ("evidence_module", "unio_collector.scanners.inventory_evidence"),
        ("evidence_schema_id", "unknown.customer.schema"),
    ],
)
def test_ipv4_conflicting_identity(field: str, value: str) -> None:
    """A recognized scanner cannot borrow the contract under conflicting metadata."""
    row = ipv4_producer_case()
    row[field] = value
    expected = "schema metadata is incomplete or invalid" if field == "evidence_schema_id" else "matching registered AWS evidence identity"
    with pytest.raises(ValueError, match=expected):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
