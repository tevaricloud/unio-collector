"""Independent Free Tier DTO/model inventories and customer-leak rejection."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

import pytest
from botocore.session import Session
from botocore.validate import validate_parameters

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_freetier_fixture import SyntheticFreeTierSession, freetier_producer_observation
from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
from unio_collector.aws.free_tier.collection_result import FreeTierCollectionResult
from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord
from unio_collector.privacy.free_tier import FIELDS, REQUIRED, VOCABULARIES, FreeTierPrivacyContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("original", ["FREE", "PAID", "ACTIVE", "EXPIRED", "NOT_STARTED", "FreeTierCollectionResult", "synthetic-customer-freetier"])
def test_freetier_customer_literal_collision(profile: str, original: str) -> None:
    """Finite SDK states never exempt the same plaintext in arbitrary prose."""
    row = freetier_producer_observation()["evidence"]
    row["payload"]["usage_records"][0]["description"] = original
    protected = transformer(profile).transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}).passed
    protected["scanner_evidence"][0]["payload"]["usage_records"][0]["description"] = original
    assert not scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}).passed


@pytest.mark.parametrize("field", ["evidence_module", "evidence_type", "provider_id", "evidence_schema_id", "serialization_status", "serialization_format"])
def test_freetier_conflicting_identity(field: str) -> None:
    """Conflicting metadata cannot admit a decoder or a finite-literal exemption."""
    row = freetier_producer_observation()["evidence"]
    row[field] = "untrusted"
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={"FREE"})
        .passed
    )


@pytest.mark.parametrize("value", ["NaN", "Infinity", True, {}, [], 4.0, "customer"])
def test_freetier_malformed_financial_values_reject(value: object) -> None:
    """Finite decimal wire values retain their exact type, never an exemption."""
    row = freetier_producer_observation()["evidence"]
    row["payload"]["usage_records"][0]["actual_usage_amount"] = value
    assert FreeTierPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")
    assert not FreeTierPrivacyContract().is_literal("usage_records[].actual_usage_amount", "4.0")


def test_freetier_nullable_financial_value_is_declared() -> None:
    """Nulls are admitted only for the actual optional DTO fields."""
    row = freetier_producer_observation("nullable")["evidence"]
    assert not FreeTierPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")
    row["payload"]["account_id"] = None
    assert FreeTierPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")


def test_freetier_financial_plaintext_is_not_a_public_literal() -> None:
    """A preserved standard amount still rejects a colliding customer value."""
    row = freetier_producer_observation()["evidence"]
    row["payload"]["usage_records"][0]["description"] = "4.0"
    protected = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert protected["scanner_evidence"][0]["payload"]["usage_records"][0]["actual_usage_amount"] == "4.0"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={"4.0"})
        .passed
    )


def test_freetier_actual_dto_inventory() -> None:
    """Dataclass serialization excludes presentation-only computed properties."""
    root = {"account_id", "account_plan", "usage_records", "page_count", "permission_errors", "api_errors"}
    plan = {"account_id", "account_plan_type", "account_plan_status", "remaining_credit_amount", "remaining_credit_unit", "expiration_date"}
    usage = {"service", "operation", "usage_type", "region", "actual_usage_amount", "forecasted_usage_amount", "limit", "unit", "description", "free_tier_type"}
    assert {f.name for f in fields(FreeTierCollectionResult)} == root
    assert {f.name for f in fields(FreeTierAccountPlanRecord)} == plan
    assert {f.name for f in fields(FreeTierUsageRecord)} == usage
    assert {"": root, "account_plan": plan, "usage_records[]": usage} == REQUIRED
    row = freetier_producer_observation()["evidence"]
    assert set(row["payload"]) == root
    assert set(row["payload"]["account_plan"]) == plan
    assert set(row["payload"]["usage_records"][0]) == usage
    assert "usage_records[].utilization_percent" not in FIELDS
    assert not FreeTierPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")


def test_freetier_pinned_sdk_contract() -> None:
    """Real API responses and finite account states match the independent SDK model."""
    model: Any = Session().get_service_model("freetier")
    plan = model.operation_model("GetAccountPlanState").output_shape
    assert set(plan.members["accountPlanType"].enum) == VOCABULARIES["plan_type"]
    assert set(plan.members["accountPlanStatus"].enum) == VOCABULARIES["plan_status"]
    session = SyntheticFreeTierSession("success")
    validate_parameters(session.get_account_plan_state(), plan)
    for page in session.paginate(maxResults=1000):
        validate_parameters(page, model.operation_model("GetFreeTierUsage").output_shape)


@pytest.mark.parametrize(("field", "original"), [("unit", "GB-Mo"), ("usage_type", "TimedStorage-ByteHrs"), ("service", "Amazon Simple Storage Service")])
def test_freetier_public_financial_reference_still_rejects_plaintext(field: str, original: str) -> None:
    """Preservation is not a known-original masking exception."""
    row = freetier_producer_observation("requests" if field == "service" else "success")["evidence"]
    row["payload"]["usage_records"][0]["description"] = original
    protected = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert protected["scanner_evidence"][0]["payload"]["usage_records"][0][field] == original
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original})
        .passed
    )


def test_freetier_public_reference_does_not_admit_foreign_rows() -> None:
    """A changed service/operation or malformed quantity cannot borrow references."""
    for key, value in (("service", "synthetic-customer"), ("operation", "synthetic-customer"), ("actual_usage_amount", "NaN")):
        row = freetier_producer_observation()["evidence"]["payload"]["usage_records"][0]
        row[key] = value
        scoped = FreeTierPrivacyContract().for_container(row, FreeTierPrivacyContract.prefix + ".usage_records[]")
        assert scoped is not None
        decision = scoped.resolve_string(FreeTierPrivacyContract.prefix + ".usage_records[].usage_type", "TimedStorage-ByteHrs", "standard")
        assert decision is not None
        assert decision.treatment == "tokenise"


def test_freetier_public_reference_scope_is_not_shared() -> None:
    """No row or traversal can inherit another row's billing admission."""
    contract = FreeTierPrivacyContract()
    first = freetier_producer_observation()["evidence"]["payload"]["usage_records"][0]
    second = dict(first, service="synthetic-customer")
    admitted = contract.for_container(first, contract.prefix + ".usage_records[]")
    rejected = contract.for_container(second, contract.prefix + ".usage_records[]")
    path = contract.prefix + ".usage_records[].usage_type"
    assert admitted is not None
    assert rejected is not None
    for scope, expected in ((admitted, "preserve"), (rejected, "tokenise"), (contract, "tokenise")):
        decision = scope.resolve_string(path, "TimedStorage-ByteHrs", "standard")
        assert decision is not None
        assert decision.treatment == expected
