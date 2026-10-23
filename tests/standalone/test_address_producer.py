"""Independent Elastic IP producer shape, profile and rejection contracts."""

from __future__ import annotations

import copy
import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_address_fixture import SCANNER, VARIANTS, address_producer_case
from unio_collector.aws.ec2.elastic_ip_record import ElasticIpRecord
from unio_collector.privacy.ec2.elastic_ip import DOMAINS, FIELDS
from unio_collector.scanners.inventory_evidence import InventoryEvidence

pytestmark = pytest.mark.offline


def test_address_independent_contract() -> None:
    """Compare privacy fields with actual DTOs and the installed offline SDK model."""
    for prefix, model in (("", InventoryEvidence), ("records[].", ElasticIpRecord)):
        declared = {p[len(prefix) :] for p in FIELDS if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {field.name for field in fields(model)}
    shapes = Loader().load_service_model("ec2", "service-2")["shapes"]
    assert set(shapes[shapes["Address"]["members"]["Domain"]["shape"]]["enum"]) == DOMAINS


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_address_profiles(variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise real wrapper branches without permitting SDK client construction."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    row, statuses = address_producer_case(variant)
    t = transformer(profile)
    after = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert statuses
    assert "synthetic-customer" not in json.dumps(after)
    assert "192.0.2.10" not in json.dumps(after)
    assert len(after["records"]) == len(row["payload"]["records"])
    if variant in {"associated", "empty", "denied", "unsupported", "unavailable", "failure"}:
        assert not after["records"]
    if variant == "partial":
        assert len(after["records"]) == 1
        assert len(set(statuses)) > 1
    for before, protected in zip(row["payload"]["records"], after["records"], strict=True):
        assert protected["domain"] == before["domain"]
        assert protected["region"] == ("aws-region" if profile == "strict" else "eu-west-2")
        assert protected["account_id"] != before["account_id"]
        for field, prefix in (("allocation_id", "RESOURCE-"), ("public_ip", "IPV4-")):
            assert protected[field] is None if before[field] is None else protected[field].startswith(prefix)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["root", "record", "metadata", "tags", "literal", "ip", "domain"])
@pytest.mark.parametrize("value", [{}, [], "synthetic-unknown"])
def test_address_unknowns(profile: str, location: str, value: object) -> None:
    """Empty and populated unknown containers reject before any profile omission."""
    row, _ = address_producer_case()
    payload = row["payload"]
    if location == "ip":
        payload["records"][0]["public_ip"] = value
    elif location == "domain":
        payload["records"][0]["domain"] = value
    elif location == "literal":
        payload["records[].region"] = value
    else:
        target = {"root": payload, "record": payload["records"][0], "metadata": payload["metadata"], "tags": payload["records"][0]["tags"]}[location]
        target["unknown_address_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    if location == "tags" and isinstance(value, str):
        assert not t.summary.unclassified
    else:
        assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_address_legacy_and_identity(profile: str) -> None:
    """Retain only registered historical identity and reject conflicting metadata."""
    row, _ = address_producer_case()
    legacy = copy.deepcopy(row)
    legacy.update(evidence_type="ElasticIpFixtureEvidence", evidence_module="unio_collector.scanners.fixture_parity.synthetic_types")
    t = transformer(profile)
    t.transform({"scanner_evidence": [legacy]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    for changes in ({"provider_id": "other"}, {"evidence_type": "Other"}, {"evidence_module": "other"}):
        wrong = {**row, **changes}
        with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
            transformer(profile).transform({"scanner_evidence": [wrong]}, file_name="scan-result/scanner-evidence.json")
    assert row["scanner_id"] == SCANNER
