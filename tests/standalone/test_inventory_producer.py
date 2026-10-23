"""Actual Athena/API Gateway producer coverage with independent DTO assertions."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

import pytest
from botocore.loaders import Loader

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_athena_fixture import VARIANTS as ATHENA_VARIANTS
from tools.collector_athena_fixture import athena_producer_payload
from tools.collector_gateway_fixture import VARIANTS as GATEWAY_VARIANTS
from tools.collector_gateway_fixture import gateway_producer_payload
from unio_collector.aws.analytics.evidence.rows import NumericEvidenceRows
from unio_collector.aws.api_gateway.region_record import ApiGatewayRegionRecord
from unio_collector.aws.athena.region_record import AthenaRegionRecord
from unio_collector.privacy.athena import FIELDS as ATHENA_FIELDS
from unio_collector.privacy.gateway import FIELDS as GATEWAY_FIELDS
from unio_collector.scanners.analytics_ai.athena.evidence import AthenaQueryEfficiencyReviewEvidence
from unio_collector.scanners.platform.api_gateway.evidence import ApiGatewayCostReviewEvidence

pytestmark = pytest.mark.offline
EXPECTED_SEEN, EXPECTED_RETAINED, EXPECTED_OMITTED = 2250, 2048, 202
FACTORIES = {"athena": athena_producer_payload, "gateway": gateway_producer_payload}
CASES = [("athena", v) for v in ATHENA_VARIANTS] + [("gateway", v) for v in GATEWAY_VARIANTS]


def test_inventory_dto_and_provider_contracts() -> None:
    """Independent DTO/provider declarations detect omitted fields and enum changes."""
    for spec, prefix, dto in (
        (ATHENA_FIELDS, "", AthenaQueryEfficiencyReviewEvidence),
        (ATHENA_FIELDS, "records[].", AthenaRegionRecord),
        (ATHENA_FIELDS, "records[].query_numeric_evidence.", NumericEvidenceRows),
        (GATEWAY_FIELDS, "", ApiGatewayCostReviewEvidence),
        (GATEWAY_FIELDS, "records[].", ApiGatewayRegionRecord),
    ):
        declared = {p[len(prefix) :] for p in spec if p.startswith(prefix) and p != prefix and "." not in p[len(prefix) :] and "[" not in p[len(prefix) :]}
        assert declared == {f.name for f in fields(dto)}
    enum = Loader().load_service_model("apigateway", "service-2")["shapes"]["EndpointType"]["enum"]
    assert set(enum) == {"REGIONAL", "EDGE", "PRIVATE"}


@pytest.mark.parametrize(("producer", "variant"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("billing", [False, True])
def test_actual_inventory_profiles(producer: str, variant: str, profile: str, monkeypatch: pytest.MonkeyPatch, *, billing: bool) -> None:
    """Both profiles exercise real producers with null and populated cost context."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    monkeypatch.setattr("boto3.session.Session.resource", lambda *_a, **_k: pytest.fail("AWS forbidden"))
    original = FACTORIES[producer](variant, billing=billing)
    t = transformer(profile)
    protected = t.transform({"scanner_evidence": [original]}, file_name="scan-result/scanner-evidence.json")["scanner_evidence"][0]["payload"]
    assert not t.summary.unclassified
    assert "synthetic-customer" not in json.dumps(protected)
    before = original["payload"]["records"][0]
    after = protected["records"][0]
    assert bool(after["permission_errors"]) == bool(before["permission_errors"])
    assert after["account_id"] != before["account_id"]
    assert after["region"] == ("aws-region" if profile == "strict" else before["region"])
    for key, value in before.items():
        if type(value) in (int, bool):
            assert after[key] == (None if profile == "strict" and key == "regional_cost_record_count" else value)
        if key.startswith("sample_"):
            assert len(after[key]) == len(value)
    if profile == "standard":
        assert after["service_current_cost"] == ("17.25" if billing else None)
        assert after["regional_current_cost"] == before["regional_current_cost"]
    else:
        for key in (
            "service_current_cost",
            "service_previous_cost",
            "service_cost_currency",
            "regional_current_cost",
            "regional_cost_currency",
            "top_usage_type_costs",
        ):
            assert after.get(key) in (None, "", [])
    _assert_inventory_details(producer, variant, before, after, billing=billing)


def _assert_inventory_details(producer: str, variant: str, before: dict[str, Any], after: dict[str, Any], *, billing: bool) -> None:
    """Assert producer-specific completeness and numeric boundaries."""
    if producer == "athena":
        assert after["query_numeric_evidence"] == before["query_numeric_evidence"]
        numeric = before["query_numeric_evidence"]
        if variant == "omitted":
            assert numeric["seen_count"] == EXPECTED_SEEN
            assert len(numeric["rows"]) == EXPECTED_RETAINED
            assert numeric["omitted_count"] == EXPECTED_OMITTED
        if variant == "capped":
            assert after["query_execution_collection_limited"]
        if variant in {"denied", "unsupported", "failure", "partial"}:
            assert not numeric["read_complete"]
        if billing:
            assert before["top_usage_type_costs"]
    else:
        assert after["sample_endpoint_types"] == before["sample_endpoint_types"]
        if variant == "summary":
            assert not after["vpc_link_detail_collected"]


@pytest.mark.parametrize("producer", FACTORIES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic"])
@pytest.mark.parametrize("location", ["root", "record", "removed"])
def test_inventory_unknown_paths(producer: str, profile: str, value: object, location: str) -> None:
    """Unknown null/empty fields reject, including before diagnostic omission."""
    row = FACTORIES[producer]()
    payload = row["payload"]
    record = payload["records"][0]
    if location == "removed":
        record["permission_errors"] = [{"unknown_synthetic_field": value}]
    else:
        (payload if location == "root" else record)["unknown_synthetic_field"] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("field_count", 2),
        ("seen_count", 999),
        ("omitted_count", -1),
        ("read_complete", 1),
        ("rows", [[1, 2]]),
        ("rows", [[1, 2, float("inf")]]),
        ("rows", [[1, 2, True]]),
        ("rows", [[1, 2, {}]]),
        ("unknown_synthetic_field", None),
    ],
)
def test_athena_numeric_invariants(profile: str, key: str, value: object) -> None:
    """Malformed shape, finite values and completeness reject before transformation."""
    row = athena_producer_payload()
    row["payload"]["records"][0]["query_numeric_evidence"][key] = value
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("producer", FACTORIES)
def test_inventory_removed_financial_descendants(profile: str, producer: str) -> None:
    """Strict cost omission must never hide unknown nested objects."""
    row = FACTORIES[producer]()
    record = row["payload"]["records"][0]
    if producer == "athena":
        record["top_usage_type_costs"][0]["unknown_synthetic_field"] = {}
    else:
        record["service_current_cost"] = {"unknown_synthetic_field": None}
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


@pytest.mark.parametrize("producer", FACTORIES)
@pytest.mark.parametrize(
    ("key", "value"),
    [("provider_id", "foreign"), ("evidence_module", "foreign.module"), ("evidence_type", "ForeignEvidence"), ("evidence_schema_id", "unknown.schema")],
)
def test_inventory_identity_conflicts(producer: str, key: str, value: str) -> None:
    """A scanner cannot borrow another producer's privacy policy."""
    row = FACTORIES[producer]()
    row[key] = value
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_unknown_gateway_endpoint_rejects(profile: str) -> None:
    """Customer text cannot be admitted as finite endpoint metadata."""
    row = gateway_producer_payload()
    row["payload"]["records"][0]["sample_endpoint_types"] = ["synthetic-customer-secret"]
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified
