from __future__ import annotations  # noqa: D100

import time
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit.api_safety import classify_aws_operation
from unio_collector.aws.audit.errors import UndeclaredAwsOperationError
from unio_collector.aws.audit.operation_names import get_api_operation_name
from unio_collector.aws.audit.response_counts import count_response_results
from unio_collector.aws.audit.unsafe_error import UnsafeAwsOperationError
from unio_collector.aws.audited.paginator import AuditedAwsPaginator

if TYPE_CHECKING:
    from unio_collector.aws.api.call_ledger import ApiCallLedger
    from unio_collector.aws.audit.context import AwsAuditContext
    from unio_collector.aws.cassette import AwsCassetteRecorder, AwsCassetteReplayer
    from unio_collector.aws.rate.limiter import AwsRateLimiter
    from unio_collector.aws.telemetry import AwsApiTelemetryRecorder
    from unio_collector.core.attempt import AttemptDeadlineContract


class AuditedAwsClient:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        *,
        raw_client: Any,  # noqa: ANN401
        service_name: str,
        region_name: str | None,
        ledger: ApiCallLedger,
        audit_context: AwsAuditContext,
        rate_limiter: AwsRateLimiter | None = None,
        telemetry: AwsApiTelemetryRecorder | None = None,
        cassette_recorder: AwsCassetteRecorder | None = None,
        cassette_replayer: AwsCassetteReplayer | None = None,
        attempt: AttemptDeadlineContract | None = None,
    ) -> None:
        self._raw_client = raw_client
        self._service_name = service_name
        self._region_name = region_name
        self._ledger = ledger
        self._audit_context = audit_context
        self._rate_limiter = rate_limiter
        self._telemetry = telemetry
        self._cassette_recorder = cassette_recorder
        self._cassette_replayer = cassette_replayer
        self._attempt = attempt or audit_context.attempt

    def can_paginate(self, operation_name: str) -> bool:  # noqa: D102
        can_paginate = getattr(self._raw_client, "can_paginate", None)
        if not callable(can_paginate):
            return False
        return bool(can_paginate(operation_name))

    def get_paginator(self, operation_name: str) -> Any:  # noqa: ANN401, D102
        return AuditedAwsPaginator(
            raw_paginator=self._raw_client.get_paginator(operation_name),
            service_name=self._service_name,
            region_name=self._region_name,
            operation_name=get_api_operation_name(self._raw_client, operation_name),
            ledger=self._ledger,
            audit_context=self._audit_context,
            rate_limiter=self._rate_limiter,
            telemetry=self._telemetry,
            account_id_provider=self._get_account_id,
            cassette_recorder=self._cassette_recorder,
            cassette_replayer=self._cassette_replayer,
            attempt=self._attempt,
        )

    def __getattr__(self, name: str) -> Any:  # noqa: ANN401
        """Wrap supported AWS client operations with audit controls."""
        raw_attr = getattr(self._raw_client, name)
        if not callable(raw_attr) or name.startswith("_"):
            return raw_attr

        operation_name = get_api_operation_name(self._raw_client, name)

        def audited_call(**kwargs: Any) -> Any:  # noqa: ANN401
            self._require_authority()
            declared_call = f"{self._service_name}:{operation_name}"
            if declared_call not in self._audit_context.allowed_api_calls:
                msg = f"Scanner {self._audit_context.scanner_id} attempted undeclared AWS operation {declared_call}"
                raise UndeclaredAwsOperationError(
                    msg,
                )
            self._validate_operation_safety(operation_name)
            rate_limit_wait_ms = self._acquire_rate_limit(operation_name)
            self._require_authority()
            started = time.perf_counter()
            try:
                if self._cassette_replayer is not None:
                    response = self._cassette_replayer.replay(
                        service=self._service_name,
                        operation=operation_name,
                        region=self._region_name,
                        request=kwargs,
                    )
                else:
                    response = raw_attr(**kwargs)
            except Exception as exc:
                latency_ms = (time.perf_counter() - started) * 1000
                completion_classification = self._get_completion_classification()
                throttled = aws_errors.is_throttling_error(exc)
                if throttled:
                    self._penalize_rate_limit(operation_name)
                if self._cassette_recorder is not None:
                    self._cassette_recorder.record_error(
                        service=self._service_name,
                        operation=operation_name,
                        region=self._region_name,
                        request=kwargs,
                        error=exc,
                        attempt=self._attempt,
                        completion_classification=completion_classification,
                    )
                self._ledger.record(
                    context=self._audit_context,
                    service_name=self._service_name,
                    operation_name=operation_name,
                    region_name=self._region_name,
                    request_parameters=kwargs,
                    error=exc,
                    aws_cassette_replay=self._cassette_replayer is not None,
                    completion_classification=completion_classification,
                )
                self._record_telemetry(
                    operation_name=operation_name,
                    status=("late_failure" if completion_classification == "late" else "failure"),
                    latency_ms=latency_ms,
                    rate_limit_wait_ms=rate_limit_wait_ms,
                    error=exc,
                    throttled=throttled,
                    replayed=self._cassette_replayer is not None,
                )
                if completion_classification == "late":
                    self._require_authority()
                raise
            latency_ms = (time.perf_counter() - started) * 1000
            completion_classification = self._get_completion_classification()
            if self._cassette_recorder is not None and isinstance(response, dict):
                self._cassette_recorder.record_response(
                    service=self._service_name,
                    operation=operation_name,
                    region=self._region_name,
                    request=kwargs,
                    response=response,
                    attempt=self._attempt,
                    completion_classification=completion_classification,
                )
            self._ledger.record(
                context=self._audit_context,
                service_name=self._service_name,
                operation_name=operation_name,
                region_name=self._region_name,
                request_parameters=kwargs,
                response=response if isinstance(response, dict) else None,
                aws_cassette_replay=self._cassette_replayer is not None,
                completion_classification=completion_classification,
            )
            self._record_telemetry(
                operation_name=operation_name,
                status=("late_success" if completion_classification == "late" else "success"),
                latency_ms=latency_ms,
                rate_limit_wait_ms=rate_limit_wait_ms,
                response=response,
                replayed=self._cassette_replayer is not None,
            )
            self._require_authority()
            return response

        return audited_call

    def _validate_operation_safety(self, operation_name: str) -> None:
        classification = classify_aws_operation(self._service_name, operation_name)
        if classification.is_runtime_safe:
            return
        msg = (
            f"Scanner {self._audit_context.scanner_id} attempted unsafe AWS "
            f"operation {classification.declared_call}: "
            f"{classification.status}. {classification.reason}"
        )
        raise UnsafeAwsOperationError(msg)

    def _acquire_rate_limit(self, operation_name: str) -> float:
        if self._rate_limiter is None:
            return 0.0
        if self._attempt is None:
            wait_seconds = self._rate_limiter.acquire(
                account_id=self._get_account_id(),
                region=self._region_name,
                service=self._service_name,
                operation=operation_name,
            )
        else:
            wait_seconds = self._rate_limiter.acquire(
                account_id=self._get_account_id(),
                region=self._region_name,
                service=self._service_name,
                operation=operation_name,
                attempt=self._attempt,
            )
        return wait_seconds * 1000

    def _penalize_rate_limit(self, operation_name: str) -> None:
        if self._rate_limiter is None:
            return
        self._rate_limiter.penalize(
            account_id=self._get_account_id(),
            region=self._region_name,
            service=self._service_name,
            operation=operation_name,
        )

    def _record_telemetry(
        self,
        *,
        operation_name: str,
        status: str,
        latency_ms: float,
        response: Any | None = None,  # noqa: ANN401
        error: Exception | None = None,
        throttled: bool = False,
        rate_limit_wait_ms: float = 0.0,
        replayed: bool = False,
    ) -> None:
        if self._telemetry is None:
            return
        error_classification = aws_errors.classify_aws_error(
            error,
            service_name=self._service_name,
            operation_name=operation_name,
        )
        counts = count_response_results(
            service_name=self._service_name,
            operation_name=operation_name,
            response=response,
        )
        self._telemetry.record_call(
            scanner_id=self._audit_context.scanner_id,
            account_id=self._get_account_id(),
            region=self._region_name,
            service=self._service_name,
            operation=operation_name,
            status=status,
            latency_ms=latency_ms,
            throttled=throttled,
            permission_denied=error_classification.permission_denied,
            service_unavailable=error_classification.service_unavailable,
            expected_absence=error_classification.expected_absence,
            error_code=error_classification.code,
            error_category=error_classification.category,
            expected_absence_reason=error_classification.reason,
            service_availability_status=(error_classification.service_availability_status),
            result_count=counts.result_count,
            resource_count=counts.resource_count,
            metric_datapoint_count=counts.metric_datapoint_count,
            rate_limit_wait_ms=rate_limit_wait_ms,
            replayed=replayed,
            attempt_id=(self._attempt.attempt_id if self._attempt is not None else None),
        )

    def _get_account_id(self) -> str | None:
        return self._audit_context.recipient_account_id or self._ledger.recipient_account_id

    def _require_authority(self) -> None:
        if self._attempt is not None:
            self._attempt.raise_if_cancelled()

    def _get_completion_classification(self) -> str:
        if self._attempt is None:
            return "unscoped"
        return self._attempt.get_completion_classification()
