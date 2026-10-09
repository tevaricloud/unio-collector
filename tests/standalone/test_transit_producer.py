"""Real transit producer coverage, finite map keys and cross-account token relations."""

from __future__ import annotations

import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_transit_fixture import STATES, TYPES, VARIANTS, transit_producer_case
from unio_collector.aws.network.transit_gateway_record import TransitGatewayRegionRecord
from unio_collector.privacy.network.transit import COUNTS, FIELDS, RESOURCE_TYPES
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.strict_verifier import StrictTransformationVerifier
from unio_collector.scanners.network.transit_gateway.evidence import TransitGatewayCostReviewEvidence

pytestmark = pytest.mark.offline


def test_transit_independent_contract() -> None:
    """Keep every DTO field and finite provider type/state independently accounted for."""
    for prefix, model in (("", TransitGatewayCostReviewEvidence), ("records[].", TransitGatewayRegionRecord)):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}
    shapes = Loader().load_service_model("ec2", "service-2")["shapes"]
    assert set(shapes["TransitGatewayAttachmentResourceType"]["enum"]) | {"unknown"} == RESOURCE_TYPES
    assert set(TYPES) - {None} == set(shapes["TransitGatewayAttachmentResourceType"]["enum"])
    assert set(STATES) == set(shapes["TransitGatewayAttachmentState"]["enum"])


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_transit_profiles(variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Preserve factual counts and ownership comparisons with actual serialized evidence."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row = transit_producer_case(variant)
    t = transformer(profile)
    result = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    for sensitive in ("123456789012", "210987654321", "synthetic-customer", "tgw-00000000000000000"):
        assert sensitive not in json.dumps(result)
    for old, new in zip(row["payload"]["records"], result["records"], strict=True):
        retained = {"transit_gateway_count", "tagged_transit_gateway_count", "untagged_transit_gateway_count"}
        assert {key: (None if profile == "strict" and key not in retained else old[key]) for key in COUNTS} == {key: new[key] for key in COUNTS}
        assert new["attachment_resource_type_counts"] == ({} if profile == "strict" else old["attachment_resource_type_counts"])
        if variant == "types":
            assert set(old["attachment_resource_type_counts"]) == RESOURCE_TYPES
    if profile == "strict":
        assert result["topology"] == []
        return
    before, after = row["payload"]["topology"][0], result["topology"][0]
    assert before["relation_state"] == after["relation_state"]
    assert [v["state"] for v in before["coverage"]] == [v["state"] for v in after["coverage"]]
    for old, new in zip(before["resources"], after["resources"], strict=True):
        if old["kind"] == "transit_gateway_attachments":
            assert (old["facts"].get("ResourceOwnerId") == before["account_id"]) == (new["facts"].get("ResourceOwnerId") == after["account_id"])
            assert new["facts"].get("State") == old["facts"].get("State")
            assert new["facts"].get("ResourceType") == old["facts"].get("ResourceType")


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["root", "counts", "count_type", "record", "facts", "state", "type", "tags", "wrong_kind"])
def test_transit_unknown_preflight(profile: str, mutation: str) -> None:
    """Unknown finite count keys and hidden nested objects reject before strict removal."""
    row = transit_producer_case()
    payload = row["payload"]
    resource = next(v for v in payload["topology"][0]["resources"] if v["kind"] == "transit_gateway_attachments")
    if mutation == "wrong_kind":
        resource["kind"] = "addresses"
    elif mutation in {"counts", "count_type"}:
        payload["records"][0]["attachment_resource_type_counts"]["unknown_transit_type" if mutation == "counts" else "vpc"] = (
            {} if mutation == "counts" else True
        )
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
        target["State" if mutation == "state" else "ResourceType" if mutation == "type" else "unknown_transit_container"] = (
            "future-value" if mutation in {"state", "type"} else {}
        )
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("count", [0, 7])
def test_strict_transit_scalar_verification(count: int) -> None:
    """Strict numeric topology reduction agrees with the independent verifier, including zero."""
    row = transit_producer_case()
    row["payload"]["records"][0]["attachment_count"] = count
    t = transformer("strict")
    document = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    assert document["scanner_evidence"][0]["payload"]["records"][0]["attachment_count"] is None
    verifier = StrictTransformationVerifier()
    verifier.verify({"scan-result/scanner-evidence.json": json.dumps(document).encode()}, load_privacy_profile("strict"))
    document["scanner_evidence"][0]["payload"]["records"][0]["attachment_count"] = count
    with pytest.raises(ValueError, match="attachment_count"):
        verifier.verify({"scan-result/scanner-evidence.json": json.dumps(document).encode()}, load_privacy_profile("strict"))


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_native_fixture_protects_tag_colliding_with_public_metadata(profile: str) -> None:
    """The actual shared producer includes the original false-positive tag value."""
    row = transit_producer_case("types")
    resources = row["payload"]["topology"][0]["resources"]
    attachments = [r for r in resources if r["kind"] == "transit_gateway_attachments"]
    assert attachments
    assert all({"Key": "Department", "Value": "network"} in r["facts"]["Tags"] for r in attachments)
    t = transformer(profile)
    document = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    payload = document["scanner_evidence"][0]["payload"]
    if profile == "strict":
        assert payload["topology"] == []
    else:
        for resource in payload["topology"][0]["resources"]:
            if resource["kind"] == "transit_gateway_attachments":
                assert all(tag["Value"] != "network" for tag in resource["facts"]["Tags"])
