"""Actual local ledger controls remain identity-bound in collision scanning."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
from botocore.exceptions import ClientError

from tests.standalone.test_bedrock_producer import transformer
from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.leak.scan import PROTECTED_TOKEN_RE, ProtectedArchiveLeakScanner

pytestmark = pytest.mark.offline


@pytest.mark.parametrize("profile", ["standard", "strict"])
def test_actual_ledger_unavailability_collision_keeps_plaintext_and_guard_rejection(profile: str) -> None:
    """Use real record/classification output, then scan protected rows and tampering."""
    ledger = ApiCallLedger()
    ledger.set_identity({"Account": "123456789012", "UserId": "synthetic-user"})
    ledger.record(
        context=AwsAuditContext("root_advisory", "synthetic", ("securityhub:DescribeHub",)),
        service_name="securityhub",
        operation_name="DescribeHub",
        region_name="eu-west-2",
        request_parameters={},
        error=ClientError({"Error": {"Code": "InvalidAccessException", "Message": "not enabled"}}, "DescribeHub"),
    )
    source = ledger.records[0]
    assert source[UNIO_PROTOCOL.namespace]["service_availability_status"] == "not_enabled_or_unavailable"
    operation = transformer(profile)
    protected = operation.transform(source, file_name="collection-log.jsonl")
    assert not operation.summary.unclassified
    tokens = frozenset(match.group(0) for match in PROTECTED_TOKEN_RE.finditer(json.dumps(protected)))
    scanner = ProtectedArchiveLeakScanner()
    assert scanner.scan_text(path="collection-log.jsonl", content=json.dumps(protected), known_original_values={"available"}, generated_tokens=tokens).passed
    if profile == "strict":
        return
    for mutation in ("plaintext", "foreign", "unknown", "unsupported_status"):
        changed = deepcopy(protected)
        if mutation == "plaintext":
            changed[UNIO_PROTOCOL.namespace]["error_reason"] = "available"
        elif mutation == "foreign":
            changed["readOnly"] = False
        elif mutation == "unknown":
            changed[UNIO_PROTOCOL.namespace]["unknown_customer"] = "available"
        else:
            changed[UNIO_PROTOCOL.namespace]["service_availability_status"] = "available"
        assert not scanner.scan_text(
            path="collection-log.jsonl", content=json.dumps(changed), known_original_values={"available"}, generated_tokens=tokens
        ).passed
