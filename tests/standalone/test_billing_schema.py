"""Independent installed SDK/explicit privacy graph correlation and leak boundaries."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest

from tools.collector_billing.fixture import billing_producer_observation
from tools.collector_recommendation.response import sdk_model
from unio_collector.privacy.billing import alarm, anomaly, budgets
from unio_collector.privacy.billing.contract import BillingPrivacyContract
from unio_collector.privacy.billing.notes import BillingNoteContract, unknown_billing_notes
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.selection import select_producer_contract

pytestmark = pytest.mark.offline
CASES = {
    "budgets": (budgets.SHAPES, ("Budget", "Notification")),
    "ce": (anomaly.SHAPES, ("AnomalyMonitor", "AnomalySubscription")),
    "cloudwatch": (alarm.SHAPES, ("MetricAlarm",)),
}


@pytest.mark.parametrize("service", CASES)
def test_actual_sdk_graph(service: str) -> None:
    """Every retained SDK field/container/vocabulary matches independent pinned package data."""
    declared, roots = CASES[service]
    model = sdk_model(service)
    seen = set()

    def visit(name: str) -> None:
        if name in seen:
            return
        seen.add(name)
        shape = model.shape_for(name)
        spec = declared[name]
        assert spec["kind"] == shape.type_name
        assert spec["enum"] == shape.metadata.get("enum", [])
        assert spec["minimum"] == shape.metadata.get("min")
        assert spec["maximum"] == shape.metadata.get("max")
        if shape.type_name == "structure":
            assert set(spec["members"]) == set(shape.members)
            assert spec["required"] == shape.required_members
            assert spec["union"] == shape.is_tagged_union
            for field, child in shape.members.items():
                assert spec["members"][field][0] == child.name
                visit(child.name)
        elif shape.type_name in {"list", "map"}:
            child = shape.member if shape.type_name == "list" else shape.value
            assert spec["member"] == child.name
            visit(child.name)

    for root in roots:
        visit(root)
    assert set(declared) == seen


@pytest.mark.parametrize("key", ["Service", "Region", "LinkedAccount", "Tag", "CostCategory"])
def test_documented_filter_keys_only(key: str) -> None:
    """Only explicit SDK-documented legacy dimension keys bypass key tokenisation."""
    contract = BillingPrivacyContract()
    prefix = "$.scanner_evidence[].payload.budgets[].budget.CostFilters"
    assert contract.preserves_mapping_key(prefix, key)
    assert not contract.preserves_mapping_key(prefix + ".nested", key)
    assert not contract.preserves_mapping_key(prefix, "SyntheticCustomer")
    assert contract.mapping_key_category(prefix) == "resource_id"


@pytest.mark.parametrize("mutation", ["scanner", "module", "type", "provider", "schema"])
def test_untrusted_billing_identity(mutation: str) -> None:
    """Unknown identities cannot inherit SDK control scan exceptions."""
    row: dict[str, Any] = {
        "scanner_id": BillingPrivacyContract.scanner_id,
        "evidence_module": "unio_collector.aws.billing_guardrails.record",
        "evidence_type": "BillingGuardrailRecord",
        "provider_id": "aws",
    }
    field = {"scanner": "scanner_id", "module": "evidence_module", "type": "evidence_type", "provider": "provider_id", "schema": "evidence_schema_id"}[mutation]
    row[field] = "untrusted"
    if mutation == "scanner":
        assert select_producer_contract(row) is None
    else:
        with pytest.raises(ValueError, match="schema|Billing privacy"):
            select_producer_contract(row)


@pytest.mark.parametrize("value", ["COST", "Service", "AWS/Billing", "EstimatedCharges", "SyntheticCustomer"])
def test_standalone_customer_text_remains_visible(value: str) -> None:
    """No ordinary text or customer field can borrow a billing-control view."""
    scanner = ProtectedArchiveLeakScanner()
    result = scanner.scan_text(path="evidence/customer.json", content='{"customer": "' + value + '"}', known_original_values={value})
    assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("body", ["registered", "plaintext", "suffix", "foreign", "missing_context", "token_is_original"])
def test_billing_diagnostic_token_boundary(body: str) -> None:
    """Retain legacy labels only with exact operation-owned registered diagnostic tokens."""
    row = deepcopy(billing_producer_observation("denied")["evidence"])
    text_token = "RESOURCE-" + "A" * 16
    account_token = "ACCOUNT-" + "B" * 16
    row["payload"]["account_id"] = account_token
    text = text_token if body not in {"plaintext", "suffix"} else "SyntheticCustomer" if body == "plaintext" else text_token + "SyntheticCustomer"
    row["payload"]["permission_errors"] = ["budgets:describe_budgets:" + text]
    if body == "foreign":
        row["evidence_module"] = "untrusted.aws.billing_guardrails.record"
    originals = {text_token} if body == "token_is_original" else {"describe_budgets", "SyntheticCustomer"}
    registered = frozenset({text_token, account_token}) if body != "missing_context" else frozenset()
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values=originals, generated_tokens=registered
    )
    assert result.passed == (body == "registered")
    if body != "registered":
        assert any(f.category == "known_original_value" for f in result.findings)


@pytest.mark.parametrize("mutation", ["wrong_parent", "unknown", "null", "wrong_mode", "wrong_key", "missing", "scope_object"])
def test_billing_note_boundaries(mutation: str) -> None:
    """Reject malformed or foreign callback notes before their prose can be omitted."""
    observed = billing_producer_observation("summary")
    note = deepcopy(observed["execution"]["coverage_notes"][0])
    parent = "billing-alerts-and-budgets-review"
    if mutation == "wrong_parent":
        parent = "untrusted"
    elif mutation == "unknown":
        note["unknown_billing_note"] = None
    elif mutation == "null":
        note["impact"] = None
    elif mutation == "wrong_mode":
        note["configured_value"] = "budgets-only"
    elif mutation == "wrong_key":
        note["config_key"] = "untrusted.subscriber_detail_mode"
    elif mutation == "missing":
        note.pop("note_type")
    elif mutation == "scope_object":
        note["scope_area"] = {}
    assert unknown_billing_notes({"scanner_results": [{"scanner_id": parent, "coverage_notes": [note]}]}, "scan-result/scanner-results.json")
    if mutation != "wrong_parent":
        contract = BillingNoteContract.for_note(note)
        assert contract is not None
        assert contract.unknown_paths(note, "scan-result/scanner-results.json")


@pytest.mark.parametrize("container", ["CostFilters", "PlannedBudgetLimits"])
def test_billing_dynamic_keys_are_customer_data(container: str) -> None:
    """Never hide a leaked dynamic key behind the finite SDK value graph."""
    row = deepcopy(billing_producer_observation("success")["evidence"])
    customer = "SyntheticLeakedCustomerKey"
    row["payload"]["budgets"][0]["budget"][container][customer] = ["safe"] if container == "CostFilters" else {"Amount": "73.25", "Unit": "USD"}
    result = ProtectedArchiveLeakScanner().scan_text(
        path="scan-result/scanner-evidence.json", content=json.dumps({"scanner_evidence": [row]}), known_original_values={customer}
    )
    assert any(f.category == "known_original_value" for f in result.findings)
    contract = BillingPrivacyContract()
    assert "budgets[].budget.CostFilters.SyntheticLeakedCustomerKey" not in contract.fields
