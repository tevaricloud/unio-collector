"""Exact protocol filenames do not globally exempt customer file suffixes."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tests.standalone.test_transport_codes import transport_files as transport_files  # noqa: PLC0414
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
CASES = (
    ("analysis-readiness.json", ("pricing_replay", "context_file")),
    ("analysis-readiness.json", ("scanner_evidence_payload_file",)),
    ("collection-summary.json", ("strict_analysis_readiness", "pricing_replay", "context_file")),
    ("collection-summary.json", ("strict_analysis_readiness", "scanner_evidence_payload_file")),
    ("signature.json", ("signed_payload",)),
)


@pytest.mark.parametrize(("member", "fields"), CASES)
@pytest.mark.parametrize("mutation", ["customer", "unknown", "suffix", "type", "member", "boundary"])
def test_fixed_reference_stays_position_bound(transport_files: dict[str, bytes], member: str, fields: tuple[str, ...], mutation: str) -> None:
    """Require actual supported fixed values; arbitrary content and token suffixes reject."""
    source = json.loads(transport_files[member])
    operation = transformer("standard")
    protected: dict[str, Any] = operation.transform(source, file_name=member)
    assert not operation.summary.unclassified
    scanner = ProtectedArchiveLeakScanner()
    generated = frozenset(operation._value_tokens._token_service.vault_builder.entries_by_token)  # noqa: SLF001
    assert scanner.scan_text(path=member, content=json.dumps(protected), known_original_values={".json"}, generated_tokens=generated).passed
    value = copy.deepcopy(protected)
    parent = value
    for field in fields[:-1]:
        parent = parent[field]
    if mutation == "customer":
        value["customer_value"] = ".json"
    elif mutation == "unknown":
        value["unknown_customer"] = None
    elif mutation == "suffix":
        parent[fields[-1]] += ".json"
    elif mutation == "type":
        parent[fields[-1]] = [parent[fields[-1]]]
    elif mutation == "member":
        member = "untrusted.json"
    else:
        value["customer_value"] = next(iter(generated), "RESOURCE-AAAAAAAAAAAAAAAA") + ".json"
    result = scanner.scan_text(path=member, content=json.dumps(value), known_original_values={".json"}, generated_tokens=generated)
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("mutation", ["unknown", "identity", "profile", "enabled", "limitation", "nested"])
def test_generated_strict_reference_view_keeps_guards(transport_files: dict[str, bytes], mutation: str) -> None:
    """Exact strict-generated redactions never loosen source admission or hide unknown content."""
    member = "collection-summary.json"
    value = transformer("strict").transform(json.loads(transport_files[member]), file_name=member)
    value.update(
        privacy_profile_id="strict",
        privacy_protection_enabled=True,
        protected_bundle_id="10000000-0000-4000-8000-000000000001",
        protected_llm_policy="llm_disabled_in_v1",
    )
    value["privacy_limitations"] = [
        {"type": "privacy_policy_cost_precision_reduced", "reason": "Strict privacy profile reduced cost precision; financial conclusions are limited."}
    ]
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path=member, content=json.dumps(value), known_original_values={".json"}).passed
    if mutation == "unknown":
        value["unknown_customer"] = None
    elif mutation == "identity":
        value["protected_bundle_id"] = "not-a-valid-generated-identity"
    elif mutation == "profile":
        value["privacy_profile_id"] = "untrusted-profile"
    elif mutation == "enabled":
        value["privacy_protection_enabled"] = 1
    elif mutation == "limitation":
        value["privacy_limitations"][0]["unknown_customer"] = None
    else:
        value["strict_analysis_readiness"]["pricing_replay"]["unknown_customer"] = None
    result = scanner.scan_text(path=member, content=json.dumps(value), known_original_values={".json"})
    assert any(finding.category == "known_original_value" for finding in result.findings)
