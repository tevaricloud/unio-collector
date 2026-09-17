from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field


@dataclass(frozen=True)
class XRayRegionRecord:  # noqa: D101
    account_id: str
    region: str
    group_count: int = 0
    sampling_rule_count: int = 0
    custom_sampling_rule_count: int = 0
    sampling_statistics_count: int = 0
    sampled_trace_count: int = 0
    request_count: int = 0
    borrow_count: int = 0
    encryption_type: str | None = None
    sample_group_names: list[str] = field(default_factory=list)
    sample_sampling_rule_names: list[str] = field(default_factory=list)
    permission_errors: list[str] = field(default_factory=list)
