"""Frozen scope and outcome of one bounded query."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowQuerySummary:
    """Completeness applies only to the declared ACCEPT pair query scope."""

    region: str
    flow_log_id: str
    log_group_name: str
    start: str
    end: str
    result_limit: int
    records_returned: int
    state: str
    reasons: tuple[str, ...] = ()
    selection: str = "bytes-desc-address-action-asc-v1"
    grouping: tuple[str, ...] = ("srcaddr", "dstaddr", "action")
    action_filter: str = "ACCEPT"
