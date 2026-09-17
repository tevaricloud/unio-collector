from __future__ import annotations  # noqa: D100

import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.aws.client.config import RateLimitRule
    from unio_collector.core.attempt import AttemptDeadlineContract

_MAX_CANCELLATION_WAIT_SECONDS = 0.1


class TokenBucket:  # noqa: D101
    def __init__(self, rule: RateLimitRule) -> None:  # noqa: D107
        self.rule = rule
        self._tokens = float(rule.burst)
        self._last_refill = time.monotonic()
        self._blocked_until = 0.0
        self._lock = threading.Lock()

    def acquire(
        self,
        attempt: AttemptDeadlineContract | None = None,
    ) -> float:
        """Acquire a token while observing an optional attempt deadline."""
        total_wait_seconds = 0.0
        while True:
            if attempt is not None:
                attempt.raise_if_cancelled()
            sleep_seconds = self._try_acquire()
            if sleep_seconds <= 0:
                return total_wait_seconds
            if attempt is None:
                total_wait_seconds += sleep_seconds
                time.sleep(sleep_seconds)
                continue
            remaining = attempt.time_remaining_seconds()
            wait_seconds = min(
                sleep_seconds,
                _MAX_CANCELLATION_WAIT_SECONDS,
                remaining if remaining is not None else sleep_seconds,
            )
            started = time.monotonic()
            attempt.wait_for_cancellation(max(0.0, wait_seconds))
            total_wait_seconds += time.monotonic() - started
            attempt.raise_if_cancelled()

    def penalize(self) -> None:  # noqa: D102
        if self.rule.penalty_seconds <= 0:
            return
        with self._lock:
            self._blocked_until = max(
                self._blocked_until,
                time.monotonic() + self.rule.penalty_seconds,
            )

    def _try_acquire(self) -> float:
        with self._lock:
            now = time.monotonic()
            if now < self._blocked_until:
                return self._blocked_until - now
            self._refill(now)
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0
            missing = 1.0 - self._tokens
            return missing / self.rule.requests_per_second

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._last_refill)
        if elapsed <= 0:
            return
        self._tokens = min(
            float(self.rule.burst),
            self._tokens + elapsed * self.rule.requests_per_second,
        )
        self._last_refill = now
