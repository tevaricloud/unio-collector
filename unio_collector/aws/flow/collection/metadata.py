"""Neutral flow query and topology completeness accounting."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from unio_collector.aws.flow.limitations import NOT_RETAINED_FIELDS
from unio_collector.aws.flow.observation import FLOW_EVIDENCE_VERSION

if TYPE_CHECKING:
    from unio_collector.aws.flow.query_summary import FlowQuerySummary


@dataclass
class VpcFlowLogCollectionMetadata:
    """Track declared collection scope separately from topology resolution."""

    flow_logs_discovered: int = 0
    queried_log_groups: list[str] = field(default_factory=list)
    query_errors: list[str] = field(default_factory=list)
    enrichment_errors: list[str] = field(default_factory=list)
    route_table_enrichment_errors: list[str] = field(default_factory=list)
    queries: list[FlowQuerySummary] = field(default_factory=list)
    reasons: set[str] = field(default_factory=set)
    topology: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record_flow_log_count(self, count: int) -> None:
        """Count eligible discovered definitions, including those omitted by cap."""
        self.flow_logs_discovered += count

    def record_queried_log_group(self, region: str, log_group_name: str) -> None:
        """Record attempted queries, including failed ones."""
        self.queried_log_groups.append(f"{region}:{log_group_name}")

    def record_query_error(self, region: str, log_group_name: str, exc: Exception) -> None:
        """Keep historical diagnostic keys alongside structured query outcomes."""
        self.query_errors.append(f"{region}:{log_group_name}:{exc}")
        self.reasons.add("query_failure")

    def convert_to_dict(self) -> dict[str, Any]:
        """Serialize collection status without finding-oriented prose."""
        successful = [query for query in self.queries if query.state != "unavailable"]
        reasons = sorted(self.reasons | {reason for query in self.queries for reason in query.reasons})
        if self.query_errors or "unsupported_format" in reasons or "unsupported_destination" in reasons:
            state = "partial" if successful else "unavailable"
        elif "definition_cap_reached" in reasons or "query_result_limit_reached" in reasons:
            state = "capped"
        else:
            state = "complete" if successful else "skipped"
        return {
            "flow_evidence_version": FLOW_EVIDENCE_VERSION,
            "flow_logs_discovered": self.flow_logs_discovered,
            "queried_log_groups": self.queried_log_groups,
            "query_errors": self.query_errors,
            "enrichment_errors": self.enrichment_errors,
            "route_table_enrichment_errors": self.route_table_enrichment_errors,
            "collection_state": state,
            "reason_codes": reasons,
            "queries": [asdict(query) for query in self.queries],
            "topology": self.topology,
            "not_retained_fields": list(NOT_RETAINED_FIELDS),
            "field_retention_reason": "fields_not_retained_by_pair_aggregation",
            "format_scope": "default-vpc-flow-log-fields",
        }
