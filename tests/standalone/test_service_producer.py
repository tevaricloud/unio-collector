"""Actual service producer branches, profile treatment and closed-schema rejection."""

from __future__ import annotations

import copy
import json
from dataclasses import fields

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_service_fixture import COLLECTORS, VARIANTS, service_producer_case
from unio_collector.privacy.service.fields import COMMON, VOCABULARIES
from unio_collector.scanners.service.coverage.evidence import ServiceCoverageEvidence
from unio_collector.scanners.service.coverage.record import ServiceCoverageRecord

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_service_producer(scanner: str, variant: str, profile: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise real collection, admission and serialization rather than empty fixture DTOs."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    row = service_producer_case(scanner, variant)
    assert row["serialization_status"] == "serialized"
    expected = {"route53": 3, "sns": 1, "step": 2, "lightsail": 7}[scanner.split("-", maxsplit=1)[0]]
    if variant in {"denied", "unavailable", "unsupported", "failure"}:
        expected = 0
        assert row["payload"]["warnings"]
    elif variant == "empty":
        expected = 0
    elif variant == "partial":
        expected = 0 if scanner.startswith("lightsail") else 1
    assert len(row["payload"]["records"]) == expected
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    payload = protected["scanner_evidence"][0]["payload"]
    encoded = json.dumps(payload)
    assert "123456789012" not in encoded
    assert "synthetic-customer" not in encoded
    if profile == "strict":
        assert payload["regions"] == ["aws-region"]
        assert "2026-01-02" not in encoded
    if scanner.startswith("step") and variant == "nullable":
        assert payload["records"][0]["attributes"]["creation_date"] == ""
    if scanner.startswith("sns") and variant == "malformed-detail":
        assert payload["records"][0]["attributes"]["subscription_count_status"] == "unavailable"
        assert payload["records"][0]["attributes"]["tags_collection_status"] == "unavailable"


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["payload", "record", "attributes", "metadata"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-unknown", 17])
def test_service_unknown_descendants(scanner: str, profile: str, location: str, value: object) -> None:
    """Unknown empty containers and nulls fail before strict transformation."""
    row = service_producer_case(scanner)
    payload = row["payload"]
    target = {"payload": payload, "record": payload["records"][0], "attributes": payload["records"][0]["attributes"], "metadata": payload["metadata"]}[location]
    target["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert any(path.endswith("unknown_synthetic_field") for path in t.summary.unclassified)


def test_actual_dto_fields_and_sdk_vocabulary() -> None:
    """Contract additions fail independently of the synthetic response fixture."""
    for prefix, dto in (("", ServiceCoverageEvidence), ("records[].", ServiceCoverageRecord)):
        actual = {
            path[len(prefix) :]
            for path in COMMON
            if path.startswith(prefix) and path[len(prefix) :] and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]
        }
        assert actual == {field.name for field in fields(dto)}
    for service, shape, kind in (
        ("route53", "HealthCheckType", "health_type"),
        ("route53", "RRType", "record_type"),
        ("stepfunctions", "StateMachineType", "machine_type"),
    ):
        assert set(Loader().load_service_model(service, "service-2")["shapes"][shape]["enum"]) == VOCABULARIES[kind]


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_cross_kind_attributes_and_identity_fail(profile: str) -> None:
    """A known field from another record kind never becomes a generic allowance."""
    row = service_producer_case("route53-cost-governance-review")
    wrong = copy.deepcopy(row)
    wrong["payload"]["records"][0]["attributes"]["traffic_policy_type"] = "A"
    t = transformer(profile)
    t.transform({"scanner_evidence": [wrong]}, file_name="scan-result/scanner-evidence.json")
    assert any(path.endswith("traffic_policy_type") for path in t.summary.unclassified)
    row["evidence_module"] = "untrusted.module"
    with pytest.raises(ValueError, match="matching registered AWS evidence identity"):
        transformer(profile).transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
