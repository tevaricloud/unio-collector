"""Finite SDK configuration and profile-specific commitment financial currencies."""

from __future__ import annotations

import copy
import json

import pytest
from botocore.loaders import create_loader

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tools.collector_commitment.fixture import commitment_producer_observation
from unio_collector.privacy.commitment.vocabulary import CURRENCIES, PUBLIC_ROLES
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


def test_commitment_controls_match_pinned_sdk() -> None:
    """Known provider enums have independent owners, rather than fixture-derived vocabularies."""
    model = create_loader().load_service_model("savingsplans", "service-2")
    assert frozenset(model["shapes"]["CurrencyCode"]["enum"]) == CURRENCIES
    ec2 = create_loader().load_service_model("ec2", "service-2")
    assert PUBLIC_ROLES["tenancy"] == frozenset(ec2["shapes"]["Tenancy"]["enum"])
    assert PUBLIC_ROLES["platform"] == frozenset(ec2["shapes"]["RIProductDescription"]["enum"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_supported_commitment_configuration_and_currency(profile: str) -> None:
    """Preserve supported nonidentifier SDK controls; strict still removes every financial currency/value."""
    observed = commitment_producer_observation()["evidence"]
    operation = transformer(profile)
    result = operation.transform({"scanner_evidence": [observed]}, file_name=MEMBER)["scanner_evidence"][0]["payload"]["portfolio"]
    assert not operation.summary.unclassified
    item = result["inventory"][0]
    assert item["specification"]["instance_type"] == "m6i.large"
    assert item["specification"]["platform"] == "Linux/UNIX"
    assert item["payment"]["payment_option"] == "Partial Upfront"
    assert item["payment"]["currency"] == ("USD" if profile == "standard" else "")
    assert all(metric["currency"] == ("USD" if profile == "standard" else "") for metric in result["observed_metrics"])


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("field", ["instance_type", "platform", "payment_option", "currency"])
def test_unknown_commitment_provider_control_is_not_preserved(profile: str, field: str) -> None:
    """A future or customer-supplied provider string receives whole-value protection, not enum authority."""
    row = commitment_producer_observation()["evidence"]
    item = row["payload"]["portfolio"]["inventory"][0]
    section = "payment" if field in {"payment_option", "currency"} else "specification"
    item[section][field] = "synthetic-customer-provider-control"
    operation = transformer(profile)
    result = operation.transform({"scanner_evidence": [row]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    assert "synthetic-customer-provider-control" not in json.dumps(result)
    assert row["payload"]["portfolio"]["inventory"][0][section][field] == "synthetic-customer-provider-control"


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "boundary"])
def test_sdk_control_values_remain_customer_leak_negatives(profile: str, mutation: str) -> None:
    """Finite provider metadata never exempts the same text in identities or unknown/borrowed roles."""
    row = commitment_producer_observation()["evidence"]
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [row]}, file_name=MEMBER)
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"m6i.large"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    record = changed["scanner_evidence"][0]
    identity = record["payload"]["portfolio"]["inventory"][0]["identity"]
    if mutation == "customer":
        identity["source_id"] = "m6i.large"
    elif mutation == "unknown":
        identity["unknown_customer_field"] = "m6i.large"
    elif mutation == "foreign":
        record["provider_id"] = "foreign"
        identity["source_id"] = "m6i.large"
    else:
        identity["source_id"] += "m6i.large"
    checked = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"m6i.large"}, generated_tokens=generated)
    assert not checked.passed
    assert any(finding.category == "known_original_value" for finding in checked.findings)
