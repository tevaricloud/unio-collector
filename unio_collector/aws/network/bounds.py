"""Deterministic serialization budgets, independent of AWS enumeration scope."""

import json
from dataclasses import asdict, replace

from unio_collector.aws.network.resource import NetworkResourceFact
from unio_collector.aws.network.topology import NetworkTopologyEvidence

ENDPOINT_TOPOLOGY_BYTES = 4 * 1024 * 1024
TRANSIT_TOPOLOGY_BYTES = 512 * 1024
PRIVATELINK_TOPOLOGY_BYTES = 512 * 1024


class NetworkEvidenceBounds:
    """Select whole facts in canonical order and retain omission accounting."""

    def __init__(self, byte_limit: int = ENDPOINT_TOPOLOGY_BYTES) -> None:
        """Set a whole-record serialization budget."""
        if byte_limit < len(b"[]"):
            msg = "Network evidence byte limit must fit the empty resource array"
            raise ValueError(msg)
        self.byte_limit = byte_limit

    def apply(self, evidence: NetworkTopologyEvidence) -> NetworkTopologyEvidence:
        """Bound the canonical resource array; metadata has fixed per-operation size."""
        retained: list[NetworkResourceFact] = []
        used = 2
        for resource in sorted(evidence.resources, key=lambda item: (item.kind, item.identity, item.observation_ordinal)):
            size = len(json.dumps(asdict(resource), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
            size += bool(retained)
            if used + size <= self.byte_limit:
                retained.append(resource)
                used += size
        observed_relations = sum(relation_count(item) for item in evidence.resources) + evidence.relations_omitted
        retained_relations = sum(relation_count(item) for item in retained)
        omitted = len(evidence.resources) - len(retained) + evidence.resources_omitted
        coverage = []
        for item in evidence.coverage:
            kind_retained = sum(1 + len(resource.repeated_observation_ordinals) for resource in retained if resource.kind == item.collection_name)
            kind_observed = sum(1 + len(resource.repeated_observation_ordinals) for resource in evidence.resources if resource.kind == item.collection_name)
            kind_omitted = kind_observed - kind_retained
            coverage.append(
                replace(
                    item,
                    resources_retained=kind_retained,
                    resources_omitted=item.resources_omitted + kind_omitted,
                    state="capped" if kind_omitted and item.state == "complete" else item.state,
                    reason_codes=tuple(dict.fromkeys((*item.reason_codes, "evidence_omitted_by_bound"))) if kind_omitted else item.reason_codes,
                )
            )
        return replace(
            evidence,
            resources=tuple(retained),
            coverage=tuple(coverage),
            byte_limit=self.byte_limit,
            bytes_used=used,
            resources_observed=len(evidence.resources) + evidence.resources_omitted,
            resources_retained=len(retained),
            resources_omitted=omitted,
            relations_observed=observed_relations,
            relations_retained=retained_relations,
            relations_omitted=observed_relations - retained_relations,
            bound_hit=bool(omitted),
        )


def relation_count(resource: NetworkResourceFact) -> int:
    """Count stored references, routes, and associations without reachability inference."""
    facts = resource.facts
    return sum(len(facts.get(key) or []) for key in ("Routes", "Associations", "RouteTableIds", "SubnetIds")) + sum(
        bool(facts.get(key)) for key in ("VpcId", "SubnetId", "TransitGatewayId", "ResourceId")
    )
