"""Quota schema correlation and adversarial customer/plaintext leak rejection."""

from __future__ import annotations

import json
from dataclasses import fields
from typing import Any

import pytest
from botocore.session import Session
from botocore.validate import validate_parameters

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_quota_fixture import SyntheticQuotaSession, quota_producer_observation
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.quota import CHECKS, FIELDS, QuotaPrivacyContract
from unio_collector.scanners.service_quota.observation import ServiceQuotaObservation
from unio_collector.scanners.service_quota.supported_checks import SUPPORTED_SERVICE_QUOTA_CHECKS

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("original", ["high", "10.0", "ec2-elastic-ips-per-region", "synthetic-customer-quota"])
def test_quota_customer_literal_collision(profile: str, original: str) -> None:
    """Controls and counts never exempt the same plaintext in a quota name."""
    row = quota_producer_observation()["evidence"]
    row["payload"]["quota_records"][0]["quota_name"] = original
    protected = transformer(profile).transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}).passed
    protected["scanner_evidence"][0]["payload"]["quota_records"][0]["quota_name"] = original
    assert not scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}).passed


@pytest.mark.parametrize("field", ["evidence_module", "evidence_type", "provider_id", "evidence_schema_id", "serialization_format"])
def test_quota_conflicting_identity(field: str) -> None:
    """Scanner IDs cannot admit foreign provider/schema/dictionary identities."""
    row = quota_producer_observation()["evidence"]
    row[field] = "untrusted"
    with pytest.raises(ValueError, match="identity|schema"):
        transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")


@pytest.mark.parametrize("value", [None, True, -1, "NaN", "Infinity", "-1", {}, "customer"])
def test_quota_invalid_quantity_keeps_customer_scan(value: object) -> None:
    """Only declared nullable finite nonnegative string quantities are accepted."""
    contract = QuotaPrivacyContract()
    assert bool(contract.unknown_paths(value, "", "quota_records[].quota_value")) == (value is not None)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_quota_foreign_record_keeps_plaintext_visible(profile: str) -> None:
    """Cross-check finite method strings do not borrow public metadata exceptions."""
    row = quota_producer_observation()["evidence"]
    row["payload"]["quota_records"][0]["resource_count_method"] = "ec2:DescribeVpcs count"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={"ec2:DescribeVpcs count"})
        .passed
    )
    t = transformer(profile)
    t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert t.summary.unclassified


def test_quota_fields_match_actual_dto_and_specs() -> None:
    """Expect complete emitted fields independently from producer dataclass/specs."""
    assert {f.name for f in fields(ServiceQuotaObservation)} == {
        p.removeprefix("quota_records[].") for p in FIELDS if p.startswith("quota_records[].") and "." not in p.removeprefix("quota_records[].")
    }
    assert set(CHECKS) == {s.check_id for s in SUPPORTED_SERVICE_QUOTA_CHECKS}
    for spec in SUPPORTED_SERVICE_QUOTA_CHECKS:
        assert CHECKS[spec.check_id][:3] == (spec.service, spec.resource_type, spec.usage_method)
    payload = quota_producer_observation()["evidence"]["payload"]
    assert set(payload) == {
        "collection_evidence_version",
        "account_id",
        "period",
        "selected_regions",
        "threshold",
        "status",
        "supported_check_count",
        "attempted_record_count",
        "expected_record_count",
        "unavailable_record_count",
        "quota_records",
        "warnings",
        "limitations",
    }
    assert not QuotaPrivacyContract().unknown_paths(payload, "source")


@pytest.mark.parametrize(
    ("service", "operation"),
    [
        ("ec2", "describe_addresses"),
        ("ec2", "describe_vpcs"),
        ("ec2", "describe_security_groups"),
        ("ec2", "describe_nat_gateways"),
        ("elbv2", "describe_load_balancers"),
        ("service-quotas", "get_service_quota"),
        ("service-quotas", "list_service_quotas"),
    ],
)
def test_quota_fixture_uses_pinned_sdk_response_keys(service: str, operation: str) -> None:
    """Independent provider model rejects invented wire fields and invalid containers."""
    model: Any = Session().get_service_model(service)
    api = {
        "describe_addresses": "DescribeAddresses",
        "describe_vpcs": "DescribeVpcs",
        "describe_security_groups": "DescribeSecurityGroups",
        "describe_nat_gateways": "DescribeNatGateways",
        "describe_load_balancers": "DescribeLoadBalancers",
        "get_service_quota": "GetServiceQuota",
        "list_service_quotas": "ListServiceQuotas",
    }[operation]
    parameters: dict[str, Any] = {"ServiceCode": "ec2", "QuotaCode": "L-0263D0A3"} if service == "service-quotas" else {}
    response = SyntheticQuotaSession(service, "success").response(operation, parameters)
    validate_parameters(response, model.operation_model(api).output_shape)
    if operation == "describe_nat_gateways":
        assert "AvailabilityZone" not in model.operation_model(api).output_shape.members["NatGateways"].member.members


def test_legacy_quota_privacy_selection_is_not_reinterpreted() -> None:
    """Versionless compatibility handling remains the existing legacy policy."""
    row = quota_producer_observation()["evidence"]
    row["payload"].pop("collection_evidence_version")
    assert QuotaPrivacyContract.for_record(row) is None


def test_preserved_standard_financial_value_is_not_a_public_literal() -> None:
    """Known-original money still rejects; quota literal masking cannot hide it."""
    row = quota_producer_observation()["evidence"]
    row["payload"]["quota_records"][0]["quota_name"] = "10"
    protected = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert protected["scanner_evidence"][0]["payload"]["period"]["total_cost"] == "10"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={"10"})
        .passed
    )
