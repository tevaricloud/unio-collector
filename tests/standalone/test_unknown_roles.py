"""Reproduced Unknown customer collisions preserve exact operational ownership."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from tools.collector_bedrock_fixture import bedrock_producer_payload
from tools.collector_permission_fixture import permission_producer_payloads
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner
from unio_collector.privacy.profiles import load_privacy_profile
from unio_collector.privacy.tokens import TokenService, TokenVaultBuilder
from unio_collector.privacy.transform import PrivacyTransformer

pytestmark = pytest.mark.offline
LEDGER = "collection-log.jsonl"
DEGRADATION = "permissions/degradation-records.json"
EVIDENCE = "scan-result/scanner-evidence.json"


def _protected(member: str, profile: str) -> tuple[dict[str, Any], frozenset[str]]:
    builder = TokenVaultBuilder()
    scope = "bundle"
    service = TokenService(token_key=bytes(range(32)), provider="aws", token_scope=scope, engagement_id="synthetic", vault_builder=builder)
    operation = PrivacyTransformer(token_service=service, profile=load_privacy_profile(profile), allow_unknown_fields=False)
    if member == EVIDENCE:
        value = {"scanner_evidence": [bedrock_producer_payload("unsupported")]}
    else:
        files = permission_producer_payloads(json.loads((Path(__file__).parent / "fixtures/protection-producers.json").read_text()))
        if member == LEDGER:
            value = next(json.loads(line) for line in files[member].splitlines() if json.loads(line).get("errorCode") == "UnknownOperationException")
        else:
            value = json.loads(files[member])
    protected = operation.transform(value, file_name=member)
    assert operation.summary.unclassified == []
    return protected, frozenset(builder.entries_by_token)


def _scan(member: str, value: object, tokens: frozenset[str]) -> bool:
    return ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(value), known_original_values={"Unknown"}, generated_tokens=tokens).passed


@pytest.mark.parametrize("member", [LEDGER, DEGRADATION, EVIDENCE])
@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_unknown_operational_roles(member: str, profile: str) -> None:
    """Actual producers, not copied DTOs, supply all admitted operational positions."""
    value, tokens = _protected(member, profile)
    assert _scan(member, value, tokens)


@pytest.mark.parametrize("mutation", ["customer", "foreign", "unknown", "wrong_action", "malformed", "unregistered"])
@pytest.mark.parametrize("member", [LEDGER, DEGRADATION, EVIDENCE])
def test_unknown_roles_do_not_hide_plaintext(member: str, mutation: str) -> None:
    """Reject arbitrary/customer, forged, malformed and unregistered contexts."""
    document, tokens = _protected(member, "standard")
    value = deepcopy(document)
    {LEDGER: _ledger_mutation, DEGRADATION: _degradation_mutation, EVIDENCE: _evidence_mutation}[member](value, mutation)
    assert not _scan(member, value, tokens)


@pytest.mark.parametrize("schema", ["foreign", None])
def test_unknown_degradation_root_must_be_owned(schema: object) -> None:
    """An owned child cannot override its malformed outer envelope."""
    value, tokens = _protected(DEGRADATION, "standard")
    value["schema_version"] = schema
    assert not _scan(DEGRADATION, value, tokens)


def _ledger_mutation(value: dict[str, Any], mutation: str) -> None:
    """Change one actual local-ledger ownership or customer position."""
    row = value
    if mutation == "customer":
        row[UNIO_PROTOCOL.namespace]["error_reason"] = "Unknown"
    elif mutation == "foreign":
        row["readOnly"] = False
    elif mutation == "unknown":
        row[UNIO_PROTOCOL.namespace]["unknown_customer"] = None
    elif mutation == "wrong_action":
        row["eventName"] = "DeleteResource"
    elif mutation == "malformed":
        row["readOnly"] = 1
    else:
        row["eventSource"] = "DNS-AAAAAAAAAAAAAAAA"


def _degradation_mutation(value: dict[str, Any], mutation: str) -> None:
    """Change one owned degradation row without modifying its siblings."""
    row = next(row for row in value["records"] if row["error_code"] == "UnknownOperationException")
    if mutation == "customer":
        row["client_explanation"] = "Unknown"
    elif mutation == "foreign":
        row["provider_id"] = "foreign"
    elif mutation == "unknown":
        row["unknown_customer"] = None
    elif mutation == "wrong_action":
        row["api_action"] = "ec2:DeleteResource"
    elif mutation == "malformed":
        row["api_call_succeeded"] = 0
    else:
        row["account_id"] = "ACCOUNT-AAAAAAAAAAAAAAAA"


def _evidence_mutation(value: dict[str, Any], mutation: str) -> None:
    """Change the exact actual unsupported Bedrock limitation context."""
    row = value["scanner_evidence"][0]
    limitation = row["payload"]["records"][0]["operation_limitations"][0]
    if mutation == "customer":
        row["payload"]["records"][0]["sample_custom_model_names"] = ["Unknown"]
    elif mutation in {"foreign", "unregistered"}:
        row["provider_id"] = "foreign"
    elif mutation == "unknown":
        limitation["unknown_customer"] = None
    elif mutation == "wrong_action":
        limitation["api_action"] = "bedrock:DeleteResource"
    else:
        limitation["status"] = 0
