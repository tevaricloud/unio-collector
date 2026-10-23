"""Actual transport code roles never hide customer fields or forged identities."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from tools.collector_permission_fixture import permission_producer_payloads
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.producer_fields import unknown_producer_paths
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder
from unio_collector.privacy.transform import PrivacyTransformer
from unio_collector.scanners.scanner.result import ScannerExecutionResult

pytestmark = pytest.mark.offline
MEMBERS = ("collection-log.jsonl", "permissions-summary.json", "permissions/degradation-records.json")
CODE = "AccessDeniedException"


@pytest.fixture(scope="module")
def transport_files() -> dict[str, bytes]:
    """Drive the real ledger and payload writer, not hand-written transport DTOs."""
    return permission_producer_payloads(json.loads((Path(__file__).parent / "fixtures/protection-producers.json").read_text()))


def protected_document(files: dict[str, bytes], member: str, profile: str) -> tuple[dict[str, Any], frozenset[str]]:
    """Protect actual producer records and retain only generated-token identities."""
    scope = "bundle"
    builder = TokenVaultBuilder()
    service = TokenService(token_key=bytes(range(32)), provider="aws", token_scope=scope, engagement_id="synthetic", vault_builder=builder)
    transformer = PrivacyTransformer(token_service=service, profile=load_privacy_profile(profile), allow_unknown_fields=False)
    source = files[member].decode()
    value = (
        next(json.loads(line) for line in source.splitlines() if json.loads(line).get("errorCode") == CODE) if member.endswith(".jsonl") else json.loads(source)
    )
    result = transformer.transform(value, file_name=member)
    assert not transformer.summary.unclassified
    return result, frozenset(builder.entries_by_token)


def target(document: dict[str, Any], member: str) -> dict[str, Any]:
    """Select the actual failing transport row without replacing its producer shape."""
    if member.endswith(".jsonl"):
        return document
    key = "permission_failures" if member == "permissions-summary.json" else "records"
    return next(row for row in document[key] if row.get("error_code") == CODE)


@pytest.mark.parametrize("member", MEMBERS)
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_transport_code_collision(transport_files: dict[str, bytes], member: str, profile: str) -> None:
    """Only a declared operational-code position can coincide with a customer ID."""
    document, tokens = protected_document(transport_files, member, profile)
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=member, content=json.dumps(document), known_original_values={CODE}, generated_tokens=tokens).passed
    row = target(document, member)
    customer_field = "eventID" if member.endswith(".jsonl") else "scanner_id" if member == "permissions-summary.json" else "resource_id"
    row[customer_field] = CODE
    assert not scanner.scan_text(path=member, content=json.dumps(document), known_original_values={CODE}, generated_tokens=tokens).passed


@pytest.mark.parametrize("member", MEMBERS)
@pytest.mark.parametrize("mutation", ["unknown", "wrong_identity", "wrong_action", "wrong_type", "missing", "unknown_code", "near_miss"])
def test_transport_metadata_never_borrows_roles(transport_files: dict[str, bytes], member: str, mutation: str) -> None:
    """Unknown/malformed/untrusted controls and arbitrary code text stay scanned."""
    document, tokens = protected_document(transport_files, member, "standard")
    row = target(document, member)
    code_field = "errorCode" if member.endswith(".jsonl") else "error_code"
    original = CODE
    if mutation == "unknown":
        row["unknown_customer_metadata"] = None
    elif mutation == "wrong_identity":
        if member.endswith(".jsonl"):
            row["eventVersion"] = "foreign"
        elif member == "permissions-summary.json":
            row["event_source"] = "untrusted"
        else:
            row["provider_id"] = "untrusted"
    elif mutation == "wrong_action":
        row["eventName" if member.endswith(".jsonl") else "event_name" if member == "permissions-summary.json" else "api_action"] = "DeleteResource"
    elif mutation == "wrong_type":
        if member.endswith(".jsonl"):
            row["readOnly"] = 1
        elif member == "permissions-summary.json":
            row["event_name"] = ["DescribeKey"]
        else:
            row["api_call_succeeded"] = 0
    elif mutation == "missing":
        row.pop(UNIO_PROTOCOL.namespace if member.endswith(".jsonl") else "scanner_id" if member == "permissions-summary.json" else "record_id")
    else:
        original = "SyntheticCustomerError" if mutation == "unknown_code" else CODE + "CustomerSuffix"
        row[code_field] = original
    assert (
        not ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={original}, generated_tokens=tokens).passed
    )


@pytest.mark.parametrize("member", MEMBERS[:2])
@pytest.mark.parametrize("registered", [False, True])
def test_transport_source_requires_actual_tokens(transport_files: dict[str, bytes], member: str, *, registered: bool) -> None:
    """A token-looking event source cannot stand in for an actual generated token."""
    document, tokens = protected_document(transport_files, member, "standard")
    row = target(document, member)
    if registered:
        assert ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={CODE}, generated_tokens=tokens).passed
    else:
        row["eventSource" if member.endswith(".jsonl") else "event_source"] = "DNS-AAAAAAAAAAAAAAAA"
        assert (
            not ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={CODE}, generated_tokens=tokens).passed
        )


def test_foreign_degradation_root_keeps_values_visible(transport_files: dict[str, bytes]) -> None:
    """A valid-looking child cannot override a foreign outer schema identity."""
    document, tokens = protected_document(transport_files, MEMBERS[-1], "standard")
    document = deepcopy(document)
    document["schema_version"] = "foreign"
    assert (
        not ProtectedArchiveLeakScanner()
        .scan_text(path=MEMBERS[-1], content=json.dumps(document), known_original_values={CODE}, generated_tokens=tokens)
        .passed
    )


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("field", ["errors", "warnings", "limitations"])
def test_actual_execution_diagnostics_protect_arbitrary_text(profile: str, field: str) -> None:
    """Protect the canonical result producer's prose instead of exempting codes."""
    row = ScannerExecutionResult(scanner_id="cost-explorer-service-delta", status="failed").convert_to_dict()
    text = "Synthetic customer phrase and AccessDeniedException"
    row[field] = [text]
    document = {"scanner_results": [row]}
    scanner = ProtectedArchiveLeakScanner()
    member = "scan-result/scanner-results.json"
    assert not scanner.scan_text(path=member, content=json.dumps(document), known_original_values={text, CODE}).passed
    builder = TokenVaultBuilder()
    scope = "bundle"
    service = TokenService(token_key=bytes(range(32)), provider="aws", token_scope=scope, engagement_id="synthetic", vault_builder=builder)
    transformer = PrivacyTransformer(token_service=service, profile=load_privacy_profile(profile), allow_unknown_fields=False)
    protected = transformer.transform(document, file_name=member)
    assert not transformer.summary.unclassified
    encoded = json.dumps(protected).encode()
    assert text.encode() not in encoded
    assert CODE.encode() not in encoded
    assert scanner.scan_text(
        path=member, content=encoded.decode(), known_original_values={text, CODE}, generated_tokens=frozenset(builder.entries_by_token)
    ).passed
    assert row[field] == [text]


@pytest.mark.parametrize("field", ["errors", "warnings", "limitations"])
@pytest.mark.parametrize("value", [None, 1, True, {}, {"unknown_nested": None}])
def test_result_diagnostic_descendants_remain_closed(field: str, value: object) -> None:
    """Malformed/null/unknown nested diagnostic values never become text tokens."""
    member = "scan-result/scanner-results.json"
    assert unknown_producer_paths({"scanner_results": [{field: [value]}]}, member)
