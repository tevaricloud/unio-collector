"""Structured completeness of one regional network enumeration."""

from dataclasses import dataclass


@dataclass(frozen=True)
class NetworkCollectionCoverage:
    """Keep successful emptiness separate from unavailable or omitted facts."""

    account_id: str
    collection_name: str
    region: str
    operation: str
    state: str
    pages_observed: int = 0
    resources_observed: int = 0
    resources_retained: int = 0
    resources_omitted: int = 0
    enumeration_normal_termination: bool = False
    reason_codes: tuple[str, ...] = ()
    failure_category: str | None = None
    failure_reference: str | None = None
