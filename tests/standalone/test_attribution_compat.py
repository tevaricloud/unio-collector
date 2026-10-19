"""Exact cross-producer operational counters and registered degradation-note ARNs."""

from __future__ import annotations

import copy
import json

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tools.collector_attribution.tagging import tagging_producer_observation
from tools.collector_managed.fixture import managed_producer_observation
from tools.collector_risk_fixture import account_risk_producer_payload
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


@pytest.mark.parametrize("family", ["ecs", "risk"])
@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "malformed", "foreign", "financial", "boundary"])
def test_operational_counter_roles_retain_leak_rejection(family: str, profile: str, mutation: str) -> None:
    """Only actual typed memory/quota controls pass; same-valued customer or financial fields reject."""
    row = managed_producer_observation("ecs-cost-governance-review")["evidence"] if family == "ecs" else account_risk_producer_payload()
    raw = (
        row["payload"]["records"][0]["task_definition_memory_mb_total"]
        if family == "ecs"
        else row["payload"]["account_risk"]["iam_summary"]["RolePolicySizeQuota"]
    )
    assert "1024" in str(raw)
    operation = transformer(profile)
    protected = operation.transform({"scanner_evidence": [row]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"1024"}, generated_tokens=generated).passed
    changed = copy.deepcopy(protected)
    payload = changed["scanner_evidence"][0]["payload"]
    counter = payload["records"][0] if family == "ecs" else payload["account_risk"]["iam_summary"]
    counter_key = "task_definition_memory_mb_total" if family == "ecs" else "RolePolicySizeQuota"
    customer = payload["records"][0] if family == "ecs" else payload["account_risk"]["trails"][0]
    customer_key = "sample_cluster_names" if family == "ecs" else "Name"
    if mutation == "customer":
        customer[customer_key] = ["1024"] if family == "ecs" else "1024"
    elif mutation == "unknown":
        counter["unknown_customer_counter"] = None
    elif mutation == "malformed":
        counter[counter_key] = "1024"
    elif mutation == "foreign":
        changed["scanner_evidence"][0]["provider_id"] = "foreign"
    elif mutation == "financial":
        if family == "ecs":
            counter["service_current_cost"] = "1024"
        else:
            payload["daily_costs"] = [{**row["payload"]["daily_costs"][0], "cost": "1024"}]
    else:
        token = customer[customer_key][0] if family == "ecs" else customer[customer_key]
        customer[customer_key] = [token + "1024"] if family == "ecs" else token + "1024"
    checked = scan.scan_text(path=MEMBER, content=json.dumps(changed), known_original_values={"1024"}, generated_tokens=generated)
    assert not checked.passed
    assert any(finding.category == "known_original_value" for finding in checked.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["customer", "unknown", "foreign", "provider", "unregistered", "boundary"])
def test_degradation_note_arn_context_is_not_a_plaintext_exemption(profile: str, mutation: str) -> None:
    """Carry actual generated tokens into note scans; borrowed or malformed ARNs still reject.

    Use the bundle writer's tuple-to-array boundary instead of pre-wire callback DTOs.
    """
    execution = json.loads(json.dumps(tagging_producer_observation("partial")["execution"]))
    operation = transformer(profile)
    protected = operation.transform({"scanner_results": [execution]}, file_name="scan-result/scanner-results.json")
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    scan = ProtectedArchiveLeakScanner()
    assert scan.scan_text(
        path="scan-result/scanner-results.json", content=json.dumps(protected), known_original_values={"eu-west-2"}, generated_tokens=generated
    ).passed
    changed = copy.deepcopy(protected)
    row = changed["scanner_results"][0]
    note = next(value for value in row["coverage_notes"] if value["note_type"] == "api_degradation")
    if mutation == "customer":
        note["resource_id"] = "eu-west-2"
    elif mutation == "unknown":
        note["unknown_customer_field"] = "eu-west-2"
    elif mutation in {"foreign", "provider"}:
        row["scanner_id" if mutation == "foreign" else "provider_id"] = "foreign"
        note["resource_id"] = "eu-west-2"
    elif mutation == "unregistered":
        note["resource_id"] = "arn:aws:elasticloadbalancing:eu-west-2:ACCOUNT-AAAAAAAAAAAAAAAA:RESOURCE-BBBBBBBBBBBBBBBB"
    else:
        note["resource_id"] += "eu-west-2"
    checked = scan.scan_text(
        path="scan-result/scanner-results.json", content=json.dumps(changed), known_original_values={"eu-west-2"}, generated_tokens=generated
    )
    assert not checked.passed
    assert any(finding.category == "known_original_value" for finding in checked.findings)
