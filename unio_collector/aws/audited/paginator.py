from __future__ import annotations  # noqa: D100

import time
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.audit.api_safety import classify_aws_operation
from unio_collector.aws.audit.errors import UndeclaredAwsOperationError
from unio_collector.aws.audit.events import response_indicates_more_pages
from unio_collector.aws.audit.response_counts import count_response_results
from unio_collector.aws.audit.unsafe_error import UnsafeAwsOperationError
from unio_collector.aws.cassette import (
    AwsCassetteRecorder,
    AwsCassetteReplayer,
    MissingAwsCassetteEntryError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.api.call_ledger import ApiCallLedger
    from unio_collector.aws.audit.context import AwsAuditContext
    from unio_collector.aws.rate.limiter import AwsRateLimiter
    from unio_collector.aws.telemetry import AwsApiTelemetryRecorder
    from unio_collector.core.attempt import AttemptDeadlineContract


class AuditedAwsPaginator:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        *,
        raw_paginator: Any,  # noqa: ANN401
        service_name: str,
        region_name: str | None,
        operation_name: str,
        ledger: ApiCallLedger,
        audit_context: AwsAuditContext,
        rate_limiter: AwsRateLimiter | None,
        telemetry: AwsApiTelemetryRecorder | None,
        account_id_provider: Callable[[], Any],
        cassette_recorder: AwsCassetteRecorder | None = None,
        cassette_replayer: AwsCassetteReplayer | None = None,
        attempt: AttemptDeadlineContract | None = None,
    ) -> None:
        self._raw_paginator = raw_paginator
        self._service_name = service_name
        self._region_name = region_name
        self._operation_name = operation_name
        self._ledger = ledger
        self._audit_context = audit_context
        self._rate_limiter = rate_limiter
        self._telemetry = telemetry
        self._account_id_provider = account_id_provider
        self._cassette_recorder = cassette_recorder
        self._cassette_replayer = cassette_replayer
        self._attempt = attempt or audit_context.attempt

    def paginate(self, **kwargs: Any) -> Any:  # noqa: ANN401, C901, D102
        self._require_authority()
        declared_call = f"{self._service_name}:{self._operation_name}"
        if declared_call not in self._audit_context.allowed_api_calls:
            msg = f"Scanner {self._audit_context.scanner_id} attempted undeclared AWS operation {declared_call}"
            raise UndeclaredAwsOperationError(
                msg,
            )
        self._validate_operation_safety()
        iterator = iter(()) if self._cassette_replayer is not None else iter(self._raw_paginator.paginate(**kwargs))
        while True:
            self._require_authority()
            rate_limit_wait_ms = self._acquire_rate_limit()
            self._require_authority()
            started = time.perf_counter()
            try:
                if self._cassette_replayer is not None:
                    page = self._cassette_replayer.replay(
                        service=self._service_name,
                        operation=self._operation_name,
                        region=self._region_name,
                        request=kwargs,
                    )
                else:
                    page = next(iterator)
            except StopIteration:
                return
            except MissingAwsCassetteEntryError:
                raise
            except Exception as exc:
                latency_ms = (time.perf_counter() - started) * 1000
                completion_classification = self._get_completion_classification()
                throttled = aws_errors.is_throttling_error(exc)
                if throttled:
                    self._penalize_rate_limit()
                if self._cassette_recorder is not None:
                    self._cassette_recorder.record_error(
                        service=self._service_name,
                        operation=self._operation_name,
                        region=self._region_name,
                        request=kwargs,
                        error=exc,
                        attempt=self._attempt,
                        completion_classification=completion_classification,
                    )
                self._ledger.record(
                    context=self._audit_context,
                    service_name=self._service_name,
                    operation_name=self._operation_name,
                    region_name=self._region_name,
                    request_parameters=kwargs,
                    error=exc,
                    aws_cassette_replay=self._cassette_replayer is not None,
                    completion_classification=completion_classification,
                )
                self._record_telemetry(
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
            response = page if isinstance(page, dict) else None
            replay_has_more_pages = self._cassette_replayer is not None and response_indicates_more_pages(response)
            if self._cassette_recorder is not None and response is not None:
                self._cassette_recorder.record_response(
                    service=self._service_name,
                    operation=self._operation_name,
                    region=self._region_name,
                    request=kwargs,
                    response=response,
                    attempt=self._attempt,
                    completion_classification=completion_classification,
                )
            self._ledger.record(
                context=self._audit_context,
                service_name=self._service_name,
                operation_name=self._operation_name,
                region_name=self._region_name,
                request_parameters=kwargs,
                response=response,
                aws_cassette_replay=self._cassette_replayer is not None,
                completion_classification=completion_classification,
            )
            self._record_telemetry(
                status=("late_success" if completion_classification == "late" else "success"),
                latency_ms=latency_ms,
                rate_limit_wait_ms=rate_limit_wait_ms,
                response=response,
                replayed=self._cassette_replayer is not None,
            )
            self._require_authority()
            yield page
            if self._cassette_replayer is not None and not replay_has_more_pages:
                return

    def _acquire_rate_limit(self) -> float:
        if self._rate_limiter is None:
            return 0.0
        if self._attempt is None:
            wait_seconds = self._rate_limiter.acquire(
                account_id=self._get_account_id(),
                region=self._region_name,
                service=self._service_name,
                operation=self._operation_name,
            )
        else:
            wait_seconds = self._rate_limiter.acquire(
                account_id=self._get_account_id(),
                region=self._region_name,
                service=self._service_name,
                operation=self._operation_name,
                attempt=self._attempt,
            )
        return wait_seconds * 1000

    def _validate_operation_safety(self) -> None:
        classification = classify_aws_operation(
            self._service_name,
            self._operation_name,
        )
        if classification.is_read_only:
            return
        msg = (
            f"Scanner {self._audit_context.scanner_id} attempted unsafe AWS "
            f"operation {classification.declared_call}: "
            f"{classification.status}. {classification.reason}"
        )
        raise UnsafeAwsOperationError(msg)

    def _penalize_rate_limit(self) -> None:
        if self._rate_limiter is None:
            return
        self._rate_limiter.penalize(
            account_id=self._get_account_id(),
            region=self._region_name,
            service=self._service_name,
            operation=self._operation_name,
        )

    def _record_telemetry(
        self,
        *,
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
            operation_name=self._operation_name,
        )
        counts = count_response_results(
            service_name=self._service_name,
            operation_name=self._operation_name,
            response=response,
        )
        self._telemetry.record_call(
            scanner_id=self._audit_context.scanner_id,
            account_id=self._get_account_id(),
            region=self._region_name,
            service=self._service_name,
            operation=self._operation_name,
            status=status,
            latency_ms=latency_ms,
            expected_absence=error_classification.expected_absence,
            service_unavailable=error_classification.service_unavailable,
            throttled=throttled,
            permission_denied=error_classification.permission_denied,
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
        value = self._account_id_provider()
        return str(value) if value else None

    def _require_authority(self) -> None:
        if self._attempt is not None:
            self._attempt.raise_if_cancelled()

    def _get_completion_classification(self) -> str:
        if self._attempt is None:
            return "unscoped"
        return self._attempt.get_completion_classification()
