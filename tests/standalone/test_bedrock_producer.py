"""Identity-bound Bedrock producer privacy through private and exported packages."""

from __future__ import annotations

import copy
import json
from dataclasses import fields
from typing import Any

import pytest

from tools.collector_bedrock_fixture import bedrock_producer_payload
from unio_collector.aws.bedrock.operation_limitation import BedrockOperationLimitation
from unio_collector.aws.bedrock.region_record import BedrockRegionRecord
from unio_collector.aws.usage.type_cost_summary import UsageTypeCostSummary
from unio_collector.privacy.bedrock import FIELDS
from unio_collector.privacy.crypto import derive_subkey, generate_root_key
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder
from unio_collector.privacy.transform import PrivacyTransformer

pytestmark = pytest.mark.offline


def transformer(profile: str) -> PrivacyTransformer:
    """Create a disposable synthetic-only transform context."""
    return PrivacyTransformer(
        token_service=TokenService(
            token_key=derive_subkey(generate_root_key(), "token-hmac"),
            provider="aws",
            token_scope="bundle",  # noqa: S106
            engagement_id="synthetic",
            vault_builder=TokenVaultBuilder(),
        ),
        profile=load_privacy_profile(profile),
        allow_unknown_fields=False,
    )


def test_closed_fields_match_actual_producer_dtos() -> None:
    """An added DTO member fails independently of simplified hand-written fixtures."""
    for prefix, dto in (
        ("records[].", BedrockRegionRecord),
        ("records[].operation_limitations[].", BedrockOperationLimitation),
        ("records[].top_usage_type_costs[].", UsageTypeCostSummary),
    ):
        declared = {path[len(prefix) :] for path in FIELDS if path.startswith(prefix) and "." not in path[len(prefix) :] and "[" not in path[len(prefix) :]}
        assert declared == {field.name for field in fields(dto)}


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("variant", ["success", "denied", "unsupported", "failure", "unavailable"])
@pytest.mark.parametrize("identity", ["versioned", "legacy", "schema_only"])
def test_actual_bedrock_producer_profiles(profile: str, variant: str, identity: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Actual collector, optional billing producer and serializer survive both profiles."""
    monkeypatch.setattr("boto3.session.Session.client", lambda *_args, **_kwargs: pytest.fail("AWS forbidden"))
    payload = bedrock_producer_payload(variant)
    if identity == "legacy":
        payload.pop("evidence_schema_id")
        payload.pop("evidence_schema_version")
    if identity == "schema_only":
        payload.pop("evidence_module")
        payload.pop("evidence_type")
    transform = transformer(profile)
    protected = transform.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
    assert not transform.summary.unclassified
    encoded = json.dumps(protected)
    for raw in ("123456789012", "synthetic-customer-model", "synthetic-throughput", "synthetic-profile", "synthetic-knowledge-base", "synthetic-agent"):
        assert raw not in encoded
    actual = protected["scanner_evidence"][0]["payload"]["records"][0]
    assert actual["foundation_model_count"] == payload["payload"]["records"][0]["foundation_model_count"]
    assert actual["account_id"].startswith("ACCOUNT-")
    if profile == "strict":
        assert actual["region"] == "aws-region"
        assert "17.25" not in encoded
        assert "9.50" not in encoded
        for field in ("service_current_cost", "service_previous_cost", "regional_current_cost", "service_cost_currency", "regional_cost_currency"):
            assert actual[field] == ""
        assert actual["top_usage_type_costs"] is None
    else:
        assert actual["service_current_cost"] == "17.25"
    if variant in {"denied", "failure", "unavailable"}:
        assert actual["permission_errors"]
        assert set(actual["permission_errors"]) == {""}
    if variant == "unsupported":
        assert actual["operation_limitations"][0]["error_classification"] == "unsupported_operation"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("location", ["payload", "record", "limitation", "cost"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-unknown", 1])
def test_unknown_bedrock_fields_fail_before_omission(profile: str, location: str, value: object) -> None:
    """Unknown empty/null descendants reject even inside strict-removed cost records."""
    payload = bedrock_producer_payload("unsupported")
    record = payload["payload"]["records"][0]
    target = {"payload": payload["payload"], "record": record, "limitation": record["operation_limitations"][0], "cost": record["top_usage_type_costs"][0]}[
        location
    ]
    target["unknown_synthetic_field"] = value
    transform = transformer(profile)
    if location == "payload":
        with pytest.raises(ValueError, match="schema v1 requires records and regions"):
            transform.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
        return
    transform.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
    assert any(path.endswith("unknown_synthetic_field") for path in transform.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], True, -1, "123456789012", 1.5])
def test_bedrock_count_types_are_closed(profile: str, value: object) -> None:
    """Counters do not admit strings, containers, booleans or negative values."""
    payload = bedrock_producer_payload()
    payload["payload"]["records"][0]["agent_count"] = value
    transform = transformer(profile)
    transform.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
    assert any(path.endswith("agent_count") for path in transform.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_bedrock_nullable_costs_and_scanner_context_isolation(profile: str) -> None:
    """Missing optional billing is valid; permissions never bleed into another row."""
    payload = bedrock_producer_payload(billing=False)
    other = copy.deepcopy(payload)
    other.update(scanner_id="synthetic-unregistered-scanner", evidence_type="Other", evidence_module="synthetic")
    other.pop("evidence_schema_id")
    other.pop("evidence_schema_version")
    transform = transformer(profile)
    result: Any = transform.transform({"scanner_evidence": [payload, other]}, file_name="scan-result/scanner-evidence.json")
    assert result["scanner_evidence"][0]["payload"]["records"][0]["service_current_cost"] is None
    assert any("sample_custom_model_names" in path for path in transform.summary.unclassified)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("value", [None, {}, [], "synthetic-unknown"])
def test_bedrock_outer_unknown_is_not_hidden_by_empty_containers(profile: str, value: object) -> None:
    """Versioned identity does not admit arbitrary additional envelope fields."""
    payload = bedrock_producer_payload()
    payload["unknown_envelope_field"] = value
    transform = transformer(profile)
    transform.transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
    assert "scan-result/scanner-evidence.json.scanner_evidence[].unknown_envelope_field" in transform.summary.unclassified


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("evidence_module", "synthetic.untrusted"),
        ("evidence_type", "SyntheticOther"),
        ("provider_id", "azure"),
        ("evidence_schema_version", True),
        ("evidence_schema_version", 2),
    ],
)
def test_bedrock_identity_conflicts_reject(key: str, value: object) -> None:
    """A recognized scanner name cannot authorize foreign or malformed metadata."""
    payload = bedrock_producer_payload()
    payload[key] = value
    with pytest.raises(ValueError, match="[Ss]chema"):
        transformer("standard").transform({"scanner_evidence": [payload]}, file_name="scan-result/scanner-evidence.json")
