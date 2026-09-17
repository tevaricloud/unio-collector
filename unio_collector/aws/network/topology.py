"""Versioned neutral regional network evidence."""

from dataclasses import dataclass

from unio_collector.aws.network.coverage import NetworkCollectionCoverage
from unio_collector.aws.network.resource import NetworkResourceFact


@dataclass(frozen=True)
class NetworkTopologyEvidence:
    """Retained whole facts and explicit accounting of omitted evidence."""

    account_id: str
    region: str
    resources: tuple[NetworkResourceFact, ...] = ()
    coverage: tuple[NetworkCollectionCoverage, ...] = ()
    relation_state: str = "complete"
    reason_codes: tuple[str, ...] = ()
    byte_limit: int = 0
    bytes_used: int = 0
    resources_observed: int = 0
    resources_retained: int = 0
    resources_omitted: int = 0
    relations_observed: int = 0
    relations_retained: int = 0
    relations_omitted: int = 0
    selection_version: str = "network-whole-record-v1"
    bound_hit: bool = False
