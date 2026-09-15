"""Athena read limits and opaque caller-supplied interpretation inputs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AthenaQueryCollectionScope:
    """Keep operational request bounds separate from private threshold defaults."""

    max_query_execution_workgroups: int = 10
    max_query_executions_per_workgroup: int = 25
    long_running_query_ms: int | None = None
    high_bytes_scanned: int | None = None
    policy_input_source: int = 0
