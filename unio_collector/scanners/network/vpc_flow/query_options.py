from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class VpcFlowQueryOptions:  # noqa: D101
    max_log_groups: int = 3
    query_limit: int = 50
    max_query_polls: int = 12
    poll_seconds: float = 1.0
    query_timeout_seconds: float = 120.0
