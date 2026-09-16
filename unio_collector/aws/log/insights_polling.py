from __future__ import annotations  # noqa: D100

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class LogsInsightsPollingConfig:  # noqa: D101
    timeout_seconds: float
    poll_seconds: float

    def get_deadline(self) -> float:  # noqa: D102
        return time.monotonic() + max(1.0, self.timeout_seconds)

    def get_sleep_seconds(self, deadline: float) -> float:  # noqa: D102
        remaining = deadline - time.monotonic()
        return max(0.0, min(max(0.1, self.poll_seconds), remaining))
