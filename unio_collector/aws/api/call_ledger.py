from __future__ import annotations  # noqa: D100

import json
import threading
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from unio_collector import __version__
from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit.api_safety import (
    classify_aws_operation,
    classify_operation_read_only,
)
from unio_collector.aws.audit.events import (
    error_details,
    event_source,
    is_permission_error_code,
    sanitize_user_identity,
)
from unio_collector.aws.audit.redaction import (
    AuditLedgerRedactionPolicy,
    redact_request_parameters,
)

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.aws.audit.context import AwsAuditContext


class ApiCallLedger:  # noqa: D101
    def __init__(self, *, redact_context: bool = False) -> None:  # noqa: D107
        self.records: list[dict[str, Any]] = []
        self.user_identity: dict[str, Any] = {}
        self.recipient_account_id: str | None = None
        self._redaction_policy = AuditLedgerRedactionPolicy(enabled=redact_context)
        self._lock = threading.Lock()

    def set_identity(self, identity: dict[str, Any]) -> None:  # noqa: D102
        normalized_identity = sanitize_user_identity(identity)
        with self._lock:
            self.user_identity = normalized_identity
            account_id = normalized_identity.get("Account") or normalized_identity.get(
                "account_id",
            )
            if account_id:
                self.recipient_account_id = str(account_id)

    def record(  # noqa: D102
        self,
        *,
        context: AwsAuditContext,
        service_name: str,
        operation_name: str,
        region_name: str | None,
        request_parameters: dict[str, Any],
        response: dict[str, Any] | None = None,
        error: Exception | None = None,
        aws_cassette_replay: bool = False,
        completion_classification: str | None = None,
    ) -> None:
        attempt = context.attempt
        classification = completion_classification or (attempt.get_completion_classification() if attempt is not None else "unscoped")
        read_only = classify_operation_read_only(service_name, operation_name)
        operation_safety = classify_aws_operation(service_name, operation_name)
        audit_read_only = False if operation_safety.status == "credential_delegation" else read_only
        write_operation: bool | str
        if read_only is True:
            write_operation = False
        elif read_only is False:
            write_operation = True
        elif operation_safety.status == "credential_delegation":
            write_operation = False
        else:
            write_operation = "unknown"

        aws_region = region_name or "aws-global"
        error_code, error_message, request_id = error_details(error)
        error_classification = aws_errors.classify_aws_error(
            error,
            service_name=service_name,
            operation_name=operation_name,
        )
        if response is not None:
            request_id = request_id or response.get("ResponseMetadata", {}).get(
                "RequestId",
            )

        record = {
            "eventVersion": "unio-1",
            "userIdentity": self.user_identity or {"type": "Unknown"},
            "eventTime": datetime.now(UTC).isoformat(),
            "eventSource": event_source(service_name),
            "eventName": operation_name,
            "awsRegion": aws_region,
            "sourceIPAddress": "local",
            "userAgent": f"unio/{__version__}",
            "requestParameters": redact_request_parameters(request_parameters),
            "responseElements": {
                "_omitted": True,
                "awsRequestId": request_id,
            },
            "readOnly": audit_read_only,
            "eventType": "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": context.recipient_account_id or self.recipient_account_id,
            "eventID": str(uuid.uuid4()),
            "errorCode": error_code,
            "errorMessage": error_message,
            "unio": {
                "scanner_id": context.scanner_id,
                "collector": context.collector,
                "operation_declared_in_registry": True,
                "destructive": False,
                "write_operation": write_operation,
                "operation_safety_status": operation_safety.status,
                "credential_material_returned": (operation_safety.status == "credential_delegation"),
                "local_only_audit_record": True,
                "declared_api_call": f"{service_name}:{operation_name}",
                "authoritative_cloudtrail": False,
                "aws_cassette_replay": aws_cassette_replay,
                "expected_absence": error_classification.expected_absence,
                "permission_denied": error_classification.permission_denied,
                "service_unavailable": error_classification.service_unavailable,
                "error_category": error_classification.category,
                "error_reason": error_classification.reason,
                "service_availability_status": (error_classification.service_availability_status),
                "attempt_id": attempt.attempt_id if attempt is not None else None,
                "scanner_call_classification": classification,
                "completed_after_attempt_end": classification == "late",
                "attempt_outcome_reason": (attempt.get_outcome_reason() if attempt is not None else None),
            },
        }
        with self._lock:
            self.records.append(record)

    def write_jsonl(self, path: Path) -> None:  # noqa: D102
        with self._lock:
            records = list(self.records)
        path.write_text(
            "".join(
                json.dumps(
                    self._redaction_policy.apply(record),
                    sort_keys=True,
                )
                + "\n"
                for record in records
            ),
            encoding="utf-8",
        )

    def get_calls_for_scanner(
        self,
        scanner_id: str,
        *,
        attempt_id: str | None = None,
        include_late: bool = False,
    ) -> list[str]:
        """Return committed declared calls for one scanner attempt."""
        with self._lock:
            records = list(self.records)
        calls = {
            record["unio"]["declared_api_call"]
            for record in records
            if self._record_matches_attempt(
                record,
                scanner_id=scanner_id,
                attempt_id=attempt_id,
                include_late=include_late,
            )
        }
        return sorted(calls)

    def get_call_count_for_scanner(
        self,
        scanner_id: str,
        *,
        attempt_id: str | None = None,
        include_late: bool = False,
    ) -> int:
        """Return committed call count for one scanner attempt."""
        with self._lock:
            records = list(self.records)
        return sum(
            1
            for record in records
            if self._record_matches_attempt(
                record,
                scanner_id=scanner_id,
                attempt_id=attempt_id,
                include_late=include_late,
            )
        )

    def get_permission_failures(self) -> list[dict[str, Any]]:  # noqa: D102
        failures: list[dict[str, Any]] = []
        with self._lock:
            records = list(self.records)
        for record in records:
            error_code_value = record.get("errorCode")
            unio = record.get("unio", {})
            if not isinstance(unio, dict):
                unio = {}
            if unio.get("scanner_call_classification") == "late":
                continue
            if unio.get("expected_absence"):
                continue
            if not unio.get("permission_denied") and not is_permission_error_code(
                str(error_code_value or ""),
            ):
                continue
            failures.append(
                {
                    "scanner_id": record.get("unio", {}).get("scanner_id"),
                    "event_source": record.get("eventSource"),
                    "event_name": record.get("eventName"),
                    "region": record.get("awsRegion"),
                    "error_code": error_code_value,
                    "error_message": record.get("errorMessage"),
                },
            )
        return failures

    def _record_matches_attempt(
        self,
        record: dict[str, Any],
        *,
        scanner_id: str,
        attempt_id: str | None,
        include_late: bool,
    ) -> bool:
        unio = record.get("unio", {})
        if not isinstance(unio, dict):
            return False
        if unio.get("scanner_id") != scanner_id:
            return False
        if attempt_id is not None and unio.get("attempt_id") != attempt_id:
            return False
        return include_late or unio.get("scanner_call_classification") != "late"
