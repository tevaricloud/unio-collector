"""Canonical environment labels must never globally exempt customer plaintext."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_sdk_wrappers import forbid_live_sdk as forbid_live_sdk  # noqa: PLC0414
from tests.standalone.test_transport_codes import MEMBERS, protected_document
from tests.standalone.test_transport_codes import transport_files as transport_files  # noqa: PLC0414
from tools.collector_serverless.fixture import LAMBDA, serverless_producer_observation
from tools.collector_serverless.lambda_client import SyntheticLambdaClient
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.environment.projection import SAFE_SERIALIZED_ENVIRONMENT_VALUES
from unio_collector.privacy.known_originals import collect_known_original_values
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
MEMBER = "scan-result/scanner-evidence.json"


@pytest.fixture
def environment_row(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, dict[str, Any], frozenset[str]]:
    """Use actual SDK tags, classifier output and operation-owned token identities."""
    original = SyntheticLambdaClient.list_tags

    def tags(client: SyntheticLambdaClient, **kwargs: object) -> dict[str, Any]:
        result = original(client, **kwargs)
        result["Tags"].update(Environment="production", Owner="production")
        return result

    monkeypatch.setattr(SyntheticLambdaClient, "list_tags", tags)
    observed = serverless_producer_observation(LAMBDA)
    operation = transformer("standard")
    protected = operation.transform({"scanner_evidence": [observed["evidence"]]}, file_name=MEMBER)
    assert not operation.summary.unclassified
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    return operation, protected, generated


@pytest.mark.parametrize("literal", sorted(SAFE_SERIALIZED_ENVIRONMENT_VALUES))
def test_environment_words_remain_known_customer_originals(literal: str) -> None:
    """Inventory retains every observed customer value at the requested unchanged length bound."""
    operation = transformer("standard")
    service = operation._value_tokens._token_service  # noqa: SLF001
    operation._value_tokens.tokenise("resource_name", literal)  # noqa: SLF001
    assert literal in collect_known_original_values(service, minimum_length=1)


def test_environment_customer_plaintext_rejects(environment_row: tuple[Any, dict[str, Any], frozenset[str]]) -> None:
    """An environment word in a customer field must reject through the real inventory collector."""
    operation, protected, generated = environment_row
    protected["scanner_evidence"][0]["payload"]["records"][0]["function_name"] = "production"
    known = collect_known_original_values(operation._value_tokens._token_service, minimum_length=4)  # noqa: SLF001
    result = ProtectedArchiveLeakScanner().scan_text(path=MEMBER, content=json.dumps(protected), known_original_values=known, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


def test_owned_environment_context_scans(environment_row: tuple[Any, dict[str, Any], frozenset[str]]) -> None:
    """Canonical context stays public only at its admitted parent/field positions."""
    _operation, protected, generated = environment_row
    result = ProtectedArchiveLeakScanner().scan_text(
        path=MEMBER, content=json.dumps(protected), known_original_values={"production"}, generated_tokens=generated
    )
    assert result.passed, result.findings


@pytest.mark.parametrize("mutation", ["customer", "unknown", "nullable", "version", "foreign", "provider", "module", "nested", "boundary"])
def test_environment_context_does_not_hide_plaintext(environment_row: tuple[Any, dict[str, Any], frozenset[str]], mutation: str) -> None:
    """Unknown/malformed contexts, untrusted identities and customer/token suffixes retain scans."""
    _operation, original, generated = environment_row
    protected = copy.deepcopy(original)
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"production"}, generated_tokens=generated).passed
    row = protected["scanner_evidence"][0]
    record = row["payload"]["records"][0]
    context = record["environment_context"]
    if mutation == "customer":
        record["function_name"] = "production"
    elif mutation == "unknown":
        context["unknown_customer"] = None
    elif mutation == "nullable":
        context["canonical_subtype"] = None
    elif mutation == "version":
        context["classifier_version"] = "untrusted-version"
    elif mutation == "foreign":
        row["scanner_id"] = "untrusted-wrapper"
    elif mutation == "provider":
        row["provider_id"] = "azure"
    elif mutation == "module":
        row["evidence_module"] = "untrusted.evidence"
    elif mutation == "nested":
        record["unknown_customer"] = {"tags": {}, "environment_context": dict(context)}
    else:
        context["classification"] = "RESOURCE-AAAAAAAAAAAAAAAAproduction"
    result = scanner.scan_text(path=MEMBER, content=json.dumps(protected), known_original_values={"production"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("member", MEMBERS)
@pytest.mark.parametrize("mutation", ["customer", "provider", "near_miss", "unknown", "wrong_member", "boundary"])
def test_unknown_controls_keep_customer_and_owner_checks(transport_files: dict[str, bytes], member: str, mutation: str) -> None:
    """Actual protocol controls stay identity-bound; plaintext, unknown paths and suffixes reject."""
    document, generated = protected_document(transport_files, member, "standard")
    scanner = ProtectedArchiveLeakScanner()
    baseline = scanner.scan_text(path=member, content=json.dumps(document), known_original_values={"unknown"}, generated_tokens=generated)
    assert baseline.passed, baseline.findings
    if mutation == "customer":
        document["customer_value"] = "unknown"
    elif mutation == "provider":
        if member.endswith(".jsonl"):
            document[UNIO_PROTOCOL.namespace]["operation_declared_in_registry"] = False
        else:
            document["provider_id"] = "untrusted-provider"
    elif mutation == "near_miss":
        if member.endswith(".jsonl"):
            document[UNIO_PROTOCOL.namespace]["service_availability_status"] = "unknown-customer"
        elif member == "permissions-summary.json":
            document["permission_degradation"]["degradation_details"][0]["confidence_effect"] = "unknown-customer"
        else:
            document["records"][0]["error_classification"] = "unknown-customer"
    elif mutation == "unknown":
        document["unknown_customer"] = None
    elif mutation == "wrong_member":
        member = "untrusted.json"
    else:
        document["customer_value"] = next(iter(generated)) + "unknown"
    result = scanner.scan_text(path=member, content=json.dumps(document), known_original_values={"unknown"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("mutation", ["action", "account", "unknown", "suffix", "success"])
def test_kms_unknown_classification_is_exact(transport_files: dict[str, bytes], mutation: str) -> None:
    """Only the actual denied KMS action with a registered account owns this compound control."""
    member = "permissions/degradation-records.json"
    document, generated = protected_document(transport_files, member, "standard")
    row = next(item for item in document["records"] if item.get("error_classification") == "access_denied_policy_source_unknown")
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=member, content=json.dumps(document), known_original_values={"unknown"}, generated_tokens=generated).passed
    if mutation == "action":
        row["api_action"] = "ec2:DescribeInstances"
    elif mutation == "account":
        row["account_id"] = "ACCOUNT-AAAAAAAAAAAAAAAA"
        generated = generated - {row["account_id"]}
    elif mutation == "unknown":
        row["unknown_customer"] = None
    elif mutation == "suffix":
        row["error_classification"] += "CustomerSuffix"
    else:
        row["api_call_succeeded"] = True
    result = scanner.scan_text(path=member, content=json.dumps(document), known_original_values={"unknown"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)
