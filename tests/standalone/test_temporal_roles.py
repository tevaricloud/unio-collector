"""Temporal protocol roles never become date-shaped customer exemptions."""

from __future__ import annotations

import copy
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from tests.standalone.test_bedrock_producer import transformer
from tools.collector_logs_fixture import logs_producer_case
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.public.protocol import ProtocolScanContract
from unio_collector.privacy.leak.scan import ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline
ACCOUNT = "ACCOUNT-AAAAAAAAAAAAAAAA"
TOKENS = frozenset({ACCOUNT})
CLOCK = "2026-10-15T11:09:00.123456+00:00"


def _manifest() -> dict[str, Any]:
    return {"bundle_schema_version": "2026-03", "collection_mode": "read_only", "account_id": ACCOUNT, "generated_at": CLOCK}


@pytest.mark.parametrize("value", [CLOCK, "2026-10"])
def test_registered_manifest_temporal_role(value: str) -> None:
    """Month precision is meaningful only at the exact admitted temporal path."""
    document = _manifest()
    document["generated_at"] = value
    result = ProtectedArchiveLeakScanner().scan_text(path="manifest.json", content=json.dumps(document), known_original_values={value}, generated_tokens=TOKENS)
    assert result.passed, result.findings


@pytest.mark.parametrize(
    "mutation",
    [
        "customer",
        "unknown",
        "forged_account",
        "foreign_provider",
        "foreign_schema",
        "wrong_mode",
        "wrong_type",
        "malformed",
        "path_injection",
        "wrong_member",
        "date_version",
    ],
)
def test_untrusted_temporal_lookalikes_still_reject(mutation: str) -> None:
    """Neither ISO formatting nor a forged protocol identity can hide customer data."""
    document = _manifest()
    literal = "09:00"
    member = "manifest.json"
    mutations = {
        "customer": {"source": {"profile_name": literal}},
        "unknown": {"unknown_customer_time": literal},
        "forged_account": {"account_id": "ACCOUNT-BBBBBBBBBBBBBBBB"},
        "foreign_provider": {"provider_id": "untrusted"},
        "foreign_schema": {"bundle_schema_version": "untrusted"},
        "wrong_mode": {"collection_mode": "untrusted"},
        "wrong_type": {"generated_at": {"customer": literal}},
        "malformed": {"generated_at": "customer-" + literal},
        "path_injection": {"generated_at.customer": literal},
    }
    document.update(mutations.get(mutation, {}))
    if mutation == "wrong_member":
        member = "untrusted.json"
    elif mutation == "date_version":
        literal = "2026-03"
    result = ProtectedArchiveLeakScanner().scan_text(path=member, content=json.dumps(document), known_original_values={literal}, generated_tokens=TOKENS)
    assert any(finding.category == "known_original_value" for finding in result.findings)


@pytest.mark.parametrize("profile", ["standard", "strict"])
@pytest.mark.parametrize("mutation", ["none", "customer", "unknown", "owner", "provider", "conflict", "malformed"])
def test_closed_payload_temporal_roles(profile: str, mutation: str) -> None:
    """Use actual collector output and canonical transformation before adversarial mutations."""
    row, _, _ = logs_producer_case("cloudwatch-log-cost-and-relevance-review", "success")
    row["payload"]["records"][0]["creation_time"] = CLOCK
    t = transformer(profile)
    document = t.transform({"scanner_evidence": [row]}, file_name="scan-result/scanner-evidence.json")
    assert not t.summary.unclassified
    protected = document["scanner_evidence"][0]
    record = protected["payload"]["records"][0]
    literal = "09:00" if profile == "standard" else "2026-10"
    if mutation == "customer":
        record["log_group_name"] = literal
    elif mutation == "unknown":
        record["unknown_timestamp"] = literal
    elif mutation == "owner":
        protected["scanner_id"] = "untrusted"
    elif mutation == "provider":
        protected["provider_id"] = "untrusted"
    elif mutation == "conflict":
        protected["evidence_type"] = "untrusted"
    elif mutation == "malformed":
        record["creation_time"] = "customer-" + literal
    scan = ProtectedArchiveLeakScanner().scan_text(path="scan-result/scanner-evidence.json", content=json.dumps(document), known_original_values={literal})
    assert scan.passed if mutation == "none" else any(f.category == "known_original_value" for f in scan.findings)


def test_temporal_policy_has_no_shared_or_cross_call_state() -> None:
    """Trusted and untrusted roots retain independent immutable contexts concurrently."""
    trusted = _manifest()
    untrusted = copy.deepcopy(trusted)
    untrusted["account_id"] = "ACCOUNT-BBBBBBBBBBBBBBBB"
    contract = ProtocolScanContract(TOKENS)

    def mask(index: int) -> bool:
        original = trusted if index % 2 == 0 else untrusted
        before = copy.deepcopy(original)
        view = json.dumps(contract.mask("manifest.json", original))
        assert original == before
        return CLOCK in view

    with ThreadPoolExecutor(max_workers=4) as executor:
        assert list(executor.map(mask, range(40))) == [bool(i % 2) for i in range(40)]


@pytest.mark.parametrize("foreign_first", [False, True])
def test_degradation_rows_keep_independent_ownership(*, foreign_first: bool) -> None:
    """One legitimate AWS row cannot grant temporal ownership to its neighbour."""
    trusted = {"schema_version": "2026-07", "provider_id": "aws", "account_id": ACCOUNT, "timestamp": CLOCK}
    foreign = {**trusted, "provider_id": "untrusted"}
    rows = [foreign, trusted] if foreign_first else [trusted, foreign]
    document = {"schema_version": "2026-07", "records": rows}
    viewed = json.dumps(ProtocolScanContract(TOKENS).mask("permissions/degradation-records.json", document))
    assert viewed.count(CLOCK) == 1
    assert document["records"] == rows


@pytest.mark.parametrize("mutation", ["none", "foreign_namespace", "wrong_version", "wrong_flag", "unknown", "customer", "malformed"])
def test_local_ledger_timestamp_requires_its_closed_envelope(mutation: str) -> None:
    """A safety-blocked local operation remains a ledger record, not a successful AWS call."""
    namespace = UNIO_PROTOCOL.namespace
    document = {
        "eventVersion": UNIO_PROTOCOL.identifier("1"),
        "eventType": "AwsApiCall",
        "eventTime": CLOCK,
        namespace: {
            "local_only_audit_record": True,
            "authoritative_cloudtrail": False,
            "credential_material_returned": False,
            "operation_safety_status": "blocked",
        },
    }
    if mutation == "foreign_namespace":
        document["foreign"] = document.pop(namespace)
    elif mutation == "wrong_version":
        document["eventVersion"] = "untrusted"
    elif mutation == "wrong_flag":
        document[namespace]["credential_material_returned"] = True
    elif mutation == "unknown":
        document[namespace]["unknown"] = None
    elif mutation == "customer":
        document["errorMessage"] = CLOCK
    elif mutation == "malformed":
        document["eventTime"] = "customer-" + CLOCK
    view = json.dumps(ProtocolScanContract(TOKENS).mask("collection-log.jsonl", document))
    assert (CLOCK in view) is (mutation != "none")


@pytest.mark.parametrize("value", [None, [], {}, True, 202610, "2026-99", "customer-2026-10", "09:00"])
def test_malformed_timestamp_never_receives_temporal_view(value: object) -> None:
    """Wrong type, malformed month and time-only values remain fully visible."""
    document = _manifest()
    document["generated_at"] = value
    view = ProtocolScanContract(TOKENS).mask("manifest.json", document)

    assert isinstance(view, list)
    expected = [] if isinstance(value, dict) else value
    assert ["generated_at", expected] in view
