"""Independent SDK/DTO contracts, literal roles and adversarial plaintext controls."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import fields
from typing import Any

import pytest

from tools.collector_ipv4_fixture import ipv4_producer_case
from tools.collector_recommendation.fixture import COLLECTORS, recommendation_producer_observation
from tools.collector_recommendation.response import OPS, sdk_model
from unio_collector.aws_native_recommendations.recommendation.record import AwsNativeRecommendationRecord
from unio_collector.aws_native_recommendations.recommendation.source_payload import AwsNativeRecommendationSourcePayload
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.recommendation.values import public_number
from unio_collector.privacy.selection import select_producer_contract
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder
from unio_collector.privacy.transform import PrivacyTransformer

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    "original",
    [
        "Idle",
        "None",
        "AccessDeniedException",
        "recommendation",
        "AWS resource",
        "recorded",
        "recommendation_id",
        "1200",
        "42.125",
        "SyntheticCustomerText",
        "RESOURCE-AAAAAAAAAAAAAAAB-suffix",
    ],
)
def test_recommendation_customer_and_operational_collisions(scanner: str, profile: str, original: str) -> None:
    """Only typed metadata roles can coincide; plaintext and untrusted identities reject."""
    row = recommendation_producer_observation(scanner)["evidence"]
    row["payload"]["records"][0]["resource_id"] = original
    if original == "1200":
        if scanner.startswith("compute-"):
            row["payload"]["records"][1]["current_configuration"]["volumeSize"] = 1200
        else:
            row["payload"]["summaries"][0]["recommendationCount"] = 1200
    if original == "42.125" and scanner.startswith("compute-"):
        row["payload"]["records"][0]["recommended_configuration"]["projectedUtilizationMetrics"][0]["value"] = 42.125
    protected, tokens = _transform(row, profile)
    scan = lambda content: ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(content), known_original_values={original}, generated_tokens=tokens
    )
    assert scan(protected).passed
    leaked = deepcopy(protected)
    leaked["scanner_evidence"][0]["payload"]["records"][0]["resource_id"] = original
    assert not scan(leaked).passed
    leaked["scanner_evidence"][0]["evidence_module"] = "untrusted"
    assert not scan(leaked).passed


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("negative", ["finance", "unknown", "malformed", "wrong_source", "wrong_module"])
def test_operational_masks_never_hide_customer_or_financial_data(scanner: str, profile: str, negative: str) -> None:
    """Declared numeric-role handling does not authorize other positions or identities."""
    row = recommendation_producer_observation(scanner)["evidence"]
    row["payload"]["records"][0]["resource_id"] = "1200"
    protected, tokens = _transform(row, profile)
    record = protected["scanner_evidence"][0]["payload"]["records"][0]
    if negative == "finance":
        record["estimated_monthly_savings"] = "1200"
    elif negative == "unknown":
        record["raw_summary"]["unknown_customer_count"] = 1200
    elif negative == "malformed":
        protected["scanner_evidence"][0]["payload"]["recommendation_count"] = "1200"
    elif negative == "wrong_source":
        protected["scanner_evidence"][0]["payload"]["source"] = "foreign"
        record["resource_id"] = "1200"
    else:
        protected["scanner_evidence"][0]["evidence_module"] = "foreign"
        record["resource_id"] = "1200"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={"1200"}, generated_tokens=tokens)
        .passed
    )


@pytest.mark.parametrize("field", ["evidence_module", "evidence_type", "provider_id", "serialization_format", "serialization_status", "evidence_schema_id"])
@pytest.mark.parametrize("scanner", COLLECTORS)
def test_recommendation_identity_conflicts_reject(scanner: str, field: str) -> None:
    """Unknown/conflicting metadata cannot enter a typed field or literal view."""
    row = recommendation_producer_observation(scanner)["evidence"]
    row[field] = "foreign"
    with pytest.raises(ValueError, match="identity|schema"):
        _transform(row, "standard")


@pytest.mark.parametrize("scanner", COLLECTORS)
def test_actual_recommendation_dto_and_sdk_inventory(scanner: str) -> None:
    """Compare complete real dataclasses and independent pinned SDK models."""
    observed = recommendation_producer_observation(scanner)
    payload = observed["evidence"]["payload"]
    assert set(payload) == {field.name for field in fields(AwsNativeRecommendationSourcePayload)} | {"evidence_version"}
    for record in payload["records"]:
        assert set(record) == {field.name for field in fields(AwsNativeRecommendationRecord)}
    contract = select_producer_contract(observed["evidence"])
    assert contract is not None
    assert contract.unknown_record_paths(observed["evidence"], "scan-result/scanner-evidence.json") == []
    service = COLLECTORS[scanner][1]
    model = sdk_model(service)
    names = model.operation_names
    assert isinstance(names, list)
    for call in observed["operations"]:
        assert OPS[call["operation"]][0] in names


@pytest.mark.parametrize("value", [True, None, "1", -1, float("nan"), float("inf"), {}, []])
def test_malformed_counts_are_not_operational_literals(value: object) -> None:
    """Bool, null, text and non-finite values never borrow integer-count treatment."""
    assert not public_number(value, ("count", "safe_metadata", False))


@pytest.mark.parametrize("value", [1200, 42.125])
def test_financial_numbers_are_never_operational_literals(value: object) -> None:
    """Financial and unknown positions remain fully visible to original-value scans."""
    assert not public_number(value, ("financial_scalar", "cost", False))
    assert not public_number(value, None)


def test_ipv4_byte_role_requires_valid_whole_topology() -> None:
    """The demonstrated cross-producer byte counter cannot mask malformed topology."""
    row = ipv4_producer_case()
    row["payload"]["topology"][0]["bytes_used"] = 1200
    protected, tokens = _transform(row, "standard")
    scan = lambda v: ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(v), known_original_values={"1200"}, generated_tokens=tokens
    )
    assert scan(protected).passed
    for key in ("unknown_customer_counter", "resources_observed"):
        bad = deepcopy(protected)
        bad["scanner_evidence"][0]["payload"]["topology"][0][key] = "1200"
        assert not scan(bad).passed


def _transform(row: dict[str, Any], profile: str) -> tuple[dict[str, Any], frozenset[str]]:
    scope = "bundle"
    builder = TokenVaultBuilder()
    service = TokenService(token_key=b"x" * 32, provider="aws", token_scope=scope, engagement_id="synthetic", vault_builder=builder)
    transformer = PrivacyTransformer(token_service=service, profile=load_privacy_profile(profile), allow_unknown_fields=False)
    protected = transformer.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert transformer.summary.unclassified == []
    assert transformer.summary.prohibited_paths == []
    return protected, frozenset(builder.entries_by_token)


@pytest.mark.parametrize("scanner", COLLECTORS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_arbitrary_recommendation_error_text_stays_protected(scanner: str, profile: str) -> None:
    """Only finite provider codes remain public; free-text errors still reject leaks."""
    row = recommendation_producer_observation(scanner, "partial")["evidence"]
    marker = "SyntheticCustomerErrorText"
    for detail in row["payload"]["metadata"]["operation_statuses"]:
        detail["error_code"] = marker
    protected, tokens = _transform(row, profile)
    scanner_service = ProtectedArchiveLeakScanner()
    assert scanner_service.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={marker}, generated_tokens=tokens
    ).passed
    protected["scanner_evidence"][0]["payload"]["metadata"]["operation_statuses"][0]["error_code"] = marker
    assert not scanner_service.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={marker}, generated_tokens=tokens
    ).passed


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize(
    ("field", "invalid"),
    [("source", "foreign"), ("service", "foreign"), ("resource_type", "foreign"), ("recommendation_type", "foreign"), ("recommendation_type", "hub")],
)
def test_record_identity_cannot_borrow_operational_number_role(profile: str, field: str, invalid: str) -> None:
    """A mismatched normalized source/resource tuple leaves all values visible."""
    row = recommendation_producer_observation("compute-optimizer-recommendation-review")["evidence"]
    row["payload"]["records"][0]["resource_id"] = "1200"
    protected, tokens = _transform(row, profile)
    record = protected["scanner_evidence"][0]["payload"]["records"][0]
    record["recommended_configuration"]["rank"] = 1200
    scanner_service = ProtectedArchiveLeakScanner()
    assert scanner_service.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={"1200"}, generated_tokens=tokens
    ).passed
    record[field] = invalid
    assert not scanner_service.scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={"1200"}, generated_tokens=tokens
    ).passed


@pytest.mark.parametrize("mutation", ["customer", "financial", "unknown", "wrong_identity", "unknown_category"])
def test_rds_categorical_cost_role_never_hides_values(mutation: str) -> None:
    """Categorical variation is not an amount or an arbitrary customer label."""
    row = recommendation_producer_observation("compute-optimizer-recommendation-review")["evidence"]
    row["payload"]["records"][0]["resource_id"] = "None"
    protected, tokens = _transform(row, "standard")
    rds = next(r for r in protected["scanner_evidence"][0]["payload"]["records"] if r["recommendation_type"] == "rds_database")
    original = "None"
    if mutation == "customer":
        rds["resource_id"] = original
    elif mutation == "financial":
        rds["estimated_monthly_savings"] = original
    elif mutation == "unknown":
        rds["raw_summary"]["unknown_customer_variation"] = original
    elif mutation == "wrong_identity":
        rds["service"] = "untrusted"
    else:
        original = "SyntheticCustomerVariation"
        rds["raw_summary"]["currentStorageEstimatedMonthlyVolumeIOPsCostVariation"] = original
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}, generated_tokens=tokens)
        .passed
    )
