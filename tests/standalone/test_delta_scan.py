"""Independent actual cost-delta contract, SDK and adversarial privacy checks."""

from __future__ import annotations

import json
from dataclasses import fields, replace
from typing import Any

import pytest
from botocore.session import Session
from botocore.validate import validate_parameters

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_delta_fixture import SyntheticCostSession, delta_producer_observation
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.privacy.cost_delta import REQUIRED, CostDeltaPrivacyContract
from unio_collector.privacy.leak.public.metadata import is_public_denied_reference
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.producer_fields import unknown_producer_paths
from unio_collector.privacy.resolver import PrivacyRegistryResolver
from unio_collector.scanners.cost_explorer.service_delta.evidence import CostExplorerServiceDeltaEvidence

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("original", ["CostExplorerServiceDeltaEvidence", "synthetic-customer-delta", "ACTIVE", "10.0"])
def test_delta_customer_and_financial_collisions(profile: str, original: str) -> None:
    """Arbitrary labels protect; financial plaintext is not a literal exemption."""
    row = delta_producer_observation()["evidence"]
    row["payload"]["result"]["service_costs"][0]["service_name"] = original
    protected = transformer(profile).transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    scanner = ProtectedArchiveLeakScanner()
    clean = scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original})
    assert clean.passed == (profile == "strict" or original != "10.0")
    if profile == "strict":
        protected["scanner_evidence"][0]["payload"]["result"]["service_costs"] = [{"service_name": original}]
    else:
        protected["scanner_evidence"][0]["payload"]["result"]["service_costs"][0]["service_name"] = original
    assert not scanner.scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original}).passed


@pytest.mark.parametrize("original", ["Amazon Simple Storage Service", "USD"])
def test_delta_preserved_public_financial_labels_still_scan(original: str) -> None:
    """A customer value matching a standard financial label still blocks."""
    row = delta_producer_observation()["evidence"]
    protected = transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not CostDeltaPrivacyContract().is_literal("result.service_costs[].currency", original)
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(protected), known_original_values={original})
        .passed
    )


@pytest.mark.parametrize("field", ["scanner_id", "evidence_module", "evidence_type", "provider_id", "serialization_status", "serialization_format"])
def test_delta_conflicting_metadata_rejects(field: str) -> None:
    """A foreign identity cannot admit the original DTO or its fixed-key view."""
    row = delta_producer_observation()["evidence"]
    row[field] = "untrusted"
    if field == "scanner_id":
        assert CostDeltaPrivacyContract.for_record(row) is None
    else:
        with pytest.raises(ValueError, match="identity"):
            transformer("standard").transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    row["payload"]["result"]["service_costs"][0]["service_name"] = "synthetic-customer-delta"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(
            path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={"synthetic-customer-delta"}
        )
        .passed
    )


@pytest.mark.parametrize("value", [None, True, 10.0, {}, [], "NaN", "Infinity", "customer"])
def test_delta_financial_types_reject(value: object) -> None:
    """Finite signed decimals are wire strings, never bools, nulls or containers."""
    row = delta_producer_observation()["evidence"]
    row["payload"]["absolute_threshold"] = value
    assert CostDeltaPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")


def test_delta_actual_dto_and_sdk_inventory() -> None:
    """Compare real dataclass fields and independent pinned botocore model shapes."""
    root = {f.name for f in fields(CostExplorerServiceDeltaEvidence)}
    result = {f.name for f in fields(CostExplorerResult)}
    observed = delta_producer_observation()
    assert root == set(observed["evidence"]["payload"])
    assert result == REQUIRED["result"]
    model: Any = Session().get_service_model("ce").operation_model("GetCostAndUsage")
    session = SyntheticCostSession("success")
    for request in observed["calls"]:
        validate_parameters(request, model.input_shape)
        validate_parameters(session.get_cost_and_usage(**request), model.output_shape)


def test_delta_version_zero_legacy_flags_are_optional() -> None:
    """Do not invent configuration defaults when earlier flags are absent."""
    row = delta_producer_observation()["evidence"]
    for key in ("analysis_inputs_version", "absolute_threshold_supplied", "percent_threshold_supplied"):
        row["payload"].pop(key)
    assert not CostDeltaPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")
    row["payload"]["analysis_inputs_version"] = 1
    assert CostDeltaPrivacyContract().unknown_record_paths(row, "scan-result/scanner-evidence.json")


@pytest.mark.parametrize(
    ("member", "prefix"),
    [
        ("analysis-readiness.json", "$.scanner_evidence_coverage"),
        ("collection-summary.json", "$.strict_analysis_readiness.scanner_evidence_coverage"),
        ("scan-result/report-bundle.json", "$.summary.scanner_evidence_coverage"),
    ],
)
@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ([], True),
        (["cost-explorer-service-delta"], True),
        (["synthetic customer label"], True),
        (None, False),
        ({}, False),
        ([False], False),
        ([{}], False),
        ([None], False),
    ],
)
def test_permission_denied_reference_shape(member: str, prefix: str, value: object, *, valid: bool) -> None:
    """Readiness producer references admit strings, never unknown nested structures."""
    result = unknown_producer_paths(value, member, prefix + ".permission_denied_scanner_ids")
    assert (not result) is valid


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("member", ["analysis-readiness.json", "collection-summary.json", "scan-result/report-bundle.json"])
@pytest.mark.parametrize("original", ["synthetic-customer-permission-reference", "permission_denied"])
def test_permission_reference_identifiers_protect_and_scan(profile: str, member: str, original: str) -> None:
    """Whole identifiers protect, including field-name collisions; reinjection rejects."""
    coverage = {"permission_denied_scanner_ids": [original]}
    value: dict[str, Any] = {"scanner_evidence_coverage": coverage}
    if member == "collection-summary.json":
        value = {"strict_analysis_readiness": value}
    elif member == "scan-result/report-bundle.json":
        value = {"summary": value}
    protected = transformer(profile).transform(value, file_name=member)
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=member, content=json.dumps(protected), known_original_values={original}).passed
    root = protected.get("strict_analysis_readiness", protected.get("summary", protected))
    identifiers = root["scanner_evidence_coverage"]["permission_denied_scanner_ids"]
    assert identifiers != [original]
    identifiers[0] = original
    assert not scanner.scan_text(path=member, content=json.dumps(protected), known_original_values={original}).passed


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_registered_denied_reference_preserves_protocol_identity(profile: str) -> None:
    """Static scanner identity remains correlated; arbitrary labels are not literals."""
    value = {"scanner_evidence_coverage": {"permission_denied_scanner_ids": ["cost-explorer-service-delta", "synthetic-customer-reference"]}}
    protected = transformer(profile).transform(value, file_name="analysis-readiness.json")
    refs = protected["scanner_evidence_coverage"]["permission_denied_scanner_ids"]
    assert refs[0] == "cost-explorer-service-delta"
    assert refs[1] != "synthetic-customer-reference"


@pytest.mark.parametrize("override", ["prohibited", "remove", "unsupported", "unknown_category", "fallback"])
def test_static_reference_never_overrides_a_stricter_policy(override: str) -> None:
    """Finite identity handling applies only to the exact supported default decision."""
    member = "analysis-readiness.json"
    path = "$.scanner_evidence_coverage.permission_denied_scanner_ids[]"
    decision = PrivacyRegistryResolver().resolve(domain="protected_bundle_input", member_path=member, json_path=path, key=None, profile_id="standard")
    assert is_public_denied_reference(member, path, "cost-explorer-service-delta", decision)
    if override in {"prohibited", "remove"}:
        decision = replace(decision, treatment=override)
    elif override == "unknown_category":
        decision = replace(decision, category=None)
    else:
        decision = replace(decision, decision_source=override)
    assert not is_public_denied_reference(member, path, "cost-explorer-service-delta", decision)
