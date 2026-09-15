from __future__ import annotations  # noqa: D100

from dataclasses import dataclass


@dataclass(frozen=True)
class LambdaS3PolicyCandidateResult:  # noqa: D101
    bucket_names: set[str] | None
    function_count: int = 0
    policy_candidate_bucket_count: int = 0
    policy_read_error_count: int = 0
    skipped_reason: str | None = None
    baseline_bucket_check_count: int = 0
    minimum_bucket_check_count: int = 0

    @property
    def should_use_policy_candidates(self) -> bool:  # noqa: D102
        return self.bucket_names is not None and self.policy_read_error_count == 0
