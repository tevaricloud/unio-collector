"""Read provider pages with explicit completeness and whole-record bounds."""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any, ClassVar

from unio_collector.aws.core.error.helpers import THROTTLE_ERROR_CODES, get_aws_error_code
from unio_collector.scanners.aws_native.collection.actions import AWS_NATIVE_ACTIONS
from unio_collector.scanners.aws_native.collection.result import AwsNativeOperationResult

MAX_NATIVE_RECORD_BYTES = 65_536
MAX_NATIVE_OPERATION_PAGES = 100
MAX_NATIVE_OPERATION_RECORDS = 100


class AwsNativeOperationReader:
    """Bound existing read-only calls without turning missing pages into absence."""

    permission_codes: ClassVar[frozenset[str]] = frozenset(
        {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedException",
            "UnrecognizedClientException",
        }
    )
    not_enabled_codes: ClassVar[frozenset[str]] = frozenset(
        {
            "OptInRequiredException",
            "OptInRequired",
            "AccountNotOptedInException",
            "SubscriptionRequiredException",
        }
    )

    def read(
        self,
        client: Any,  # noqa: ANN401
        *,
        operation_name: str,
        result_keys: tuple[str, ...],
        request_parameters: dict[str, Any] | None = None,
        limit: int = MAX_NATIVE_OPERATION_RECORDS,
    ) -> AwsNativeOperationResult:
        """Retain complete rows in provider order and label every early stop."""
        self._validate_request(operation_name, limit)
        if limit == 0:
            return AwsNativeOperationResult((), "capped", "RecordLimit")
        items: list[dict[str, Any]] = []
        observed = 0
        page_count = 0
        parameters = request_parameters or {}
        try:
            pages = (
                client.get_paginator(operation_name).paginate(**parameters)
                if client.can_paginate(operation_name)
                else (getattr(client, operation_name)(**parameters),)
            )
            for page in pages:
                page_count += 1
                rows = self._rows(page, result_keys)
                observed += len(rows)
                for row in rows:
                    if len(items) >= limit:
                        return AwsNativeOperationResult(tuple(items), "capped", "RecordLimit", observed, observed - len(items))
                    if self._record_size(row) > MAX_NATIVE_RECORD_BYTES:
                        return AwsNativeOperationResult(tuple(items), "capped", "RecordByteLimit", observed, observed - len(items))
                    items.append(row)
                if page_count >= MAX_NATIVE_OPERATION_PAGES:
                    return AwsNativeOperationResult(tuple(items), "capped", "PageLimit", observed, observed - len(items))
            if not page_count:
                return AwsNativeOperationResult((), "unavailable", "MissingPage")
        except Exception as exc:  # noqa: BLE001
            code = self.error_code(exc)
            status = "partial" if items else self.classify_error_code(code)
            return AwsNativeOperationResult(
                tuple(items),
                status,
                code,
                observed,
                observed - len(items),
                stop_collection=isinstance(exc, (TypeError, ValueError, OverflowError, RecursionError)),
            )
        return AwsNativeOperationResult(tuple(items), "complete", observed_count=observed)

    @staticmethod
    def _validate_request(operation: str, limit: int) -> None:
        if operation not in AWS_NATIVE_ACTIONS or type(limit) is not int or not 0 <= limit <= MAX_NATIVE_OPERATION_RECORDS:
            message = "AWS-native operation or evidence limit is unsupported."
            raise ValueError(message)

    @classmethod
    def _record_size(cls, row: object) -> int:
        if not isinstance(row, dict):
            message = "AWS-native provider result contains a malformed record."
            raise ValueError(message)
        return len(json.dumps(row, default=cls._json_value, allow_nan=False).encode("utf-8"))

    @staticmethod
    def _rows(page: object, result_keys: tuple[str, ...]) -> list[Any]:
        if isinstance(page, dict):
            present = [key for key in result_keys if key in page]
            if len(present) == 1 and isinstance(page[present[0]], list):
                return page[present[0]]
        message = "AWS-native provider response has missing or ambiguous result rows."
        raise ValueError(message)

    @staticmethod
    def _json_value(value: object) -> str:
        if isinstance(value, datetime | date):
            return value.isoformat()
        if isinstance(value, Decimal) and value.is_finite():
            return str(value)
        message = "AWS-native provider record contains unsupported values."
        raise ValueError(message)

    @classmethod
    def classify_error_code(cls, code: str) -> str:
        """Classify explicit provider error codes without matching prose."""
        if code in cls.permission_codes:
            return "permission_limited"
        if code in cls.not_enabled_codes:
            return "not_enabled"
        return "unavailable"

    @classmethod
    def error_code(cls, exc: Exception) -> str:
        """Return bounded diagnostic metadata without provider error text."""
        code = get_aws_error_code(exc) or type(exc).__name__
        known = (
            cls.permission_codes
            | cls.not_enabled_codes
            | THROTTLE_ERROR_CODES
            | {
                "ResourceNotFoundException",
                "InvalidParameterValueException",
                "ValidationException",
                "ServiceUnavailableException",
                "InternalErrorException",
                "InternalServerException",
                "DataUnavailableException",
                "InvalidAction",
                "UnauthorizedOperation",
            }
        )
        if code not in known:
            code = type(exc).__name__
        return code if re.fullmatch(r"[A-Za-z0-9]{1,80}", code) else "ProviderError"
