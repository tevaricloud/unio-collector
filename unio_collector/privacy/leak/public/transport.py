"""Exact actual ledger and AWS permission transport-code scan roles."""

from __future__ import annotations

import re

from unio_collector.aws.audit.api_safety import classify_aws_operation
from unio_collector.collector.protocol import UNIO_PROTOCOL
from unio_collector.privacy.producer_fields import unknown_producer_paths
from unio_collector.privacy.tokens import is_protected_token

PUBLIC_PERMISSION_CODE = "AccessDeniedException"
PUBLIC_UNSUPPORTED_CODE = "UnknownOperationException"


class TransportErrorScanContract:
    """Distinguish reproduced transport codes from customer identifiers."""

    @staticmethod
    def reject_root(member: str, value: dict[str, object], path: str) -> bool:
        """Keep a malformed or foreign degradation envelope wholly visible."""
        return (
            member == "permissions/degradation-records.json"
            and path == "$"
            and (value.get("schema_version") != "2026-07" or bool(unknown_producer_paths(value, member, path)))
        )

    @classmethod
    def view(cls, member: str, value: dict[str, object], path: str, generated_tokens: frozenset[str]) -> dict[str, object]:
        """Copy only a validated operational-code field in its actual producer role."""
        field = "errorCode" if member == "collection-log.jsonl" else "error_code"
        code = value.get(field)
        if not isinstance(code, str) or code not in {PUBLIC_PERMISSION_CODE, PUBLIC_UNSUPPORTED_CODE} or unknown_producer_paths(value, member, path):
            return value
        allowed = False
        if (member, path) == ("collection-log.jsonl", "$"):
            allowed = cls._ledger(value, generated_tokens)
        elif (member, path) == ("permissions-summary.json", "$.permission_failures[]"):
            allowed = cls._failure(value, generated_tokens)
        elif (member, path) == ("permissions/degradation-records.json", "$.records[]"):
            account = value.get("account_id")
            registered = isinstance(account, str) and account.startswith("ACCOUNT-") and account in generated_tokens and is_protected_token(account)
            allowed = cls._degradation(value) and (code != PUBLIC_UNSUPPORTED_CODE or registered)
        result = {**value, field: ""} if allowed else value
        account = value.get("account_id")
        if (
            allowed
            and (member, path) == ("permissions/degradation-records.json", "$.records[]")
            and value.get("api_action") == "kms:DescribeKey"
            and code == PUBLIC_PERMISSION_CODE
            and value.get("error_classification") == "access_denied_policy_source_unknown"
            and isinstance(account, str)
            and account.startswith("ACCOUNT-")
            and account in generated_tokens
            and is_protected_token(account)
        ):
            result = {**result, "error_classification": ""}
        return result

    @classmethod
    def _ledger(cls, value: dict[str, object], generated_tokens: frozenset[str]) -> bool:
        namespace = value.get(UNIO_PROTOCOL.namespace)
        if not isinstance(namespace, dict):
            return False
        return (
            value.get("eventVersion") == UNIO_PROTOCOL.identifier("1")
            and value.get("eventType") == "AwsApiCall"
            and value.get("readOnly") is True
            and namespace.get("local_only_audit_record") is True
            and namespace.get("authoritative_cloudtrail") is False
            and namespace.get("operation_declared_in_registry") is True
            and namespace.get("destructive") is False
            and namespace.get("write_operation") is False
            and namespace.get("credential_material_returned") is False
            and cls._event_action(value, generated_tokens)
        )

    @classmethod
    def _failure(cls, value: dict[str, object], generated_tokens: frozenset[str]) -> bool:
        return (
            set(value) - {"error_message"} == {"scanner_id", "event_source", "event_name", "region", "error_code"}
            and all(isinstance(value.get(k), str) and bool(value[k]) for k in ("scanner_id", "event_source", "event_name", "region"))
            and (value.get("error_message") is None or isinstance(value.get("error_message"), str))
            and cls._event_action(value, generated_tokens, snake_case=True)
        )

    @classmethod
    def _degradation(cls, value: dict[str, object]) -> bool:
        action = value.get("api_action")
        if not isinstance(action, str) or action.count(":") != 1:
            return False
        required = (
            "schema_version",
            "record_id",
            "provider_id",
            "account_id",
            "region",
            "scanner_id",
            "api_action",
            "evidence_category",
            "outcome",
            "evidence_interpretation",
        )
        return (
            all(isinstance(value.get(k), str) and bool(value[k]) for k in required)
            and value.get("schema_version") == "2026-07"
            and value.get("provider_id") == "aws"
            and value.get("outcome") in ({"unsupported_operation"} if value.get("error_code") == PUBLIC_UNSUPPORTED_CODE else {"denied", "service_unavailable"})
            and value.get("api_call_succeeded") is False
            and all(value.get(k) is None or type(value[k]) is bool for k in ("collection_continued", "scanner_continued", "related_findings_may_be_incomplete"))
            and cls._action(*action.split(":"))
        )

    @classmethod
    def _event_action(cls, value: dict[str, object], generated_tokens: frozenset[str], *, snake_case: bool = False) -> bool:
        source = value.get("event_source" if snake_case else "eventSource")
        operation = value.get("event_name" if snake_case else "eventName")
        if not isinstance(source, str) or not isinstance(operation, str):
            return False
        if source.endswith(".amazonaws.com"):
            return cls._action(source.removesuffix(".amazonaws.com"), operation)
        return source.startswith("DNS-") and is_protected_token(source) and source in generated_tokens and cls._action("aws", operation)

    @staticmethod
    def _action(service: str, operation: str) -> bool:
        return (
            bool(re.fullmatch(r"[a-z][a-z0-9-]*", service) and re.fullmatch(r"[A-Z][A-Za-z0-9]*", operation))
            and classify_aws_operation(service, operation).is_read_only
        )
