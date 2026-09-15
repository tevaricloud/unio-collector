from __future__ import annotations  # noqa: D100

import threading
from typing import TYPE_CHECKING

from unio_collector.aws.client.config import AwsRuntimeConfig, RateLimitRule
from unio_collector.aws.core.rate.limit_key import AwsRateLimitKey
from unio_collector.aws.token_bucket import TokenBucket

if TYPE_CHECKING:
    from unio_collector.core.attempt import AttemptDeadlineContract


class AwsRateLimiter:  # noqa: D101
    def __init__(self, config: AwsRuntimeConfig) -> None:  # noqa: D107
        self.config = config
        self._buckets: dict[AwsRateLimitKey, TokenBucket] = {}
        self._lock = threading.Lock()

    def acquire(  # noqa: D102
        self,
        *,
        account_id: str | None,
        region: str | None,
        service: str,
        operation: str,
        attempt: AttemptDeadlineContract | None = None,
    ) -> float:
        return self._get_bucket(
            account_id=account_id,
            region=region,
            service=service,
            operation=operation,
        ).acquire(attempt)

    def penalize(  # noqa: D102
        self,
        *,
        account_id: str | None,
        region: str | None,
        service: str,
        operation: str,
    ) -> None:
        self._get_bucket(
            account_id=account_id,
            region=region,
            service=service,
            operation=operation,
        ).penalize()

    def _get_bucket(
        self,
        *,
        account_id: str | None,
        region: str | None,
        service: str,
        operation: str,
    ) -> TokenBucket:
        key = self._build_key(
            account_id=account_id,
            region=region,
            service=service,
            operation=operation,
        )
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(
                    self._get_rule(service=service, operation=operation),
                )
                self._buckets[key] = bucket
            return bucket

    def _build_key(
        self,
        *,
        account_id: str | None,
        region: str | None,
        service: str,
        operation: str,
    ) -> AwsRateLimitKey:
        normalized_service = service.lower()
        operation_key = f"{normalized_service}:{operation}"
        if operation_key in self.config.operation_rate_limits:
            return AwsRateLimitKey(
                account_id=account_id or "unknown-account",
                region=region or "aws-global",
                service=normalized_service,
                operation=operation,
            )
        return AwsRateLimitKey(
            account_id=account_id or "unknown-account",
            region=region or "aws-global",
            service=normalized_service,
        )

    def _get_rule(self, *, service: str, operation: str) -> RateLimitRule:
        normalized_service = service.lower()
        operation_key = f"{normalized_service}:{operation}"
        operation_rule = self.config.operation_rate_limits.get(operation_key)
        if operation_rule is not None:
            return operation_rule
        return self.config.rate_limits.get(
            normalized_service,
            RateLimitRule(requests_per_second=3.0, burst=3),
        )
