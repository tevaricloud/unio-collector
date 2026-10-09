"""Public service literals never exempt customer-controlled strings or containers."""

from __future__ import annotations

import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_service_fixture import service_producer_case
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline

CASES = [
    ("route53-cost-governance-review", "HTTPS"),
    ("sns-cost-governance-review", "true"),
    ("step-functions-cost-governance-review", "STANDARD"),
    ("lightsail-cost-governance-review", "stopped"),
]


@pytest.mark.parametrize(("scanner", "literal"), CASES)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", [None, "name", "tag", "unknown", "wrong-kind"])
def test_service_literal_positions(scanner: str, literal: str, profile: str, mutation: str | None) -> None:
    """Actual transformed records retain exact literals but reveal injected leaks."""
    t = transformer(profile)
    document = t.transform({"scanner_evidence": [service_producer_case(scanner, "collision")]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    row = document["scanner_evidence"][0]["payload"]["records"][0]
    if mutation == "name":
        row["resource_name"] = literal
    elif mutation == "tag":
        row["tags"]["synthetic-key"] = literal
    elif mutation == "unknown":
        row["unknown"] = {literal: None}
    elif mutation == "wrong-kind":
        row["resource_type"] = "synthetic-unknown-kind"
        row["attributes"]["health_check_type"] = literal
    result = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(document), known_original_values={literal})
    assert any(item.category == "known_original_value" for item in result.findings) is (mutation is not None)


@pytest.mark.parametrize("value", [0, 1, -1, True, "stopped", None])
def test_pricing_counter_key_requires_nonnegative_integer(value: object) -> None:
    """The fixed counter key is exempt only for its actual typed producer shape."""
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/pricing-context.json",
        content=json.dumps({"stopped_lookup_request_count": value}),
        known_original_values={"stopped"},
    )
    assert any(item.category == "known_original_value" for item in result.findings) is not (type(value) is int and value >= 0)


def test_pricing_nested_and_customer_values_are_not_exempt() -> None:
    """Only the top-level producer key is public; arbitrary descendants remain scanned."""
    for document in (
        {"unknown": {"stopped_lookup_request_count": 0}},
        {"stopped_lookup_request_count": 0, "value": "stopped"},
    ):
        result = ProtectedArchiveLeakScanner().scan_text(
            path="scan-result/pricing-context.json", content=json.dumps(document), known_original_values={"stopped"}
        )
        assert any(item.category == "known_original_value" for item in result.findings)
