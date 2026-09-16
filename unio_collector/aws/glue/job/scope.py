"""Glue read limits and opaque caller-supplied interpretation inputs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class GlueJobCollectionScope:
    """Keep operational request bounds separate from private threshold defaults."""

    max_job_run_jobs: int = 25
    max_job_runs_per_job: int = 10
    long_running_job_seconds: int | None = None
    high_dpu_seconds: float | None = None
    policy_input_source: int = 0
