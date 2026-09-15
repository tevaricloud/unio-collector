"""Preserve tagging exports without loading private interpretation on import.

Collection configuration imports tagging.defaults directly. Existing application
exports remain available lazily; retire them only through a versioned public
import migration.
"""

from __future__ import annotations

# pyright: reportUnsupportedDunderAll=false
from importlib import import_module
from typing import Any

_EXPORTS = {
    "DEFAULT_COST_GROUP_TAGS": ("unio_collector.evidence.tagging.defaults", "DEFAULT_COST_GROUP_TAGS"),
    "NAME_TOKEN_PATTERN": ("unio_collector.evidence.tagging.associations", "NAME_TOKEN_PATTERN"),
    "TagAssociationEdge": ("unio_collector.evidence.tagging.tag.association.edge", "TagAssociationEdge"),
    "TagAssociationGraph": ("unio_collector.evidence.tagging.tag.association.graph", "TagAssociationGraph"),
    "TagAssociationGraphBuilder": ("unio_collector.evidence.tagging.associations", "TagAssociationGraphBuilder"),
    "TagAssociationNode": ("unio_collector.evidence.tagging.tag.association.node", "TagAssociationNode"),
    "TagSuggestionCandidate": ("unio_collector.evidence.tagging.tag.suggestion_candidate", "TagSuggestionCandidate"),
    "TaggedCostGroupAccumulator": ("unio_collector.evidence.tagging.tagged.cost.group.accumulator", "TaggedCostGroupAccumulator"),
    "TaggedCostGroupBuilder": ("unio_collector.evidence.tagging.cost_grouping", "TaggedCostGroupBuilder"),
    "TaggedCostGroupRecord": ("unio_collector.evidence.tagging.tagged.cost.group.record", "TaggedCostGroupRecord"),
    "attach_tag_candidates_to_findings": ("unio_collector.evidence.tagging.associations", "attach_tag_candidates_to_findings"),
    "best_confidence": ("unio_collector.evidence.tagging.associations", "best_confidence"),
    "build_candidate_confidence_explanation": ("unio_collector.evidence.tagging.associations", "build_candidate_confidence_explanation"),
    "build_candidate_decision_factors": ("unio_collector.evidence.tagging.associations", "build_candidate_decision_factors"),
    "build_candidate_evidence_lines": ("unio_collector.evidence.tagging.associations", "build_candidate_evidence_lines"),
    "build_candidate_evidence_summary": ("unio_collector.evidence.tagging.associations", "build_candidate_evidence_summary"),
    "build_candidate_validation_guidance": ("unio_collector.evidence.tagging.associations", "build_candidate_validation_guidance"),
    "build_group_evidence_summary": ("unio_collector.evidence.tagging.associations", "build_group_evidence_summary"),
    "build_group_resource_summary": ("unio_collector.evidence.tagging.associations", "build_group_resource_summary"),
    "build_reference_group_key": ("unio_collector.evidence.tagging.cost_grouping", "build_reference_group_key"),
    "build_resource_group_key": ("unio_collector.evidence.tagging.cost_grouping", "build_resource_group_key"),
    "build_resource_key": ("unio_collector.evidence.tagging.associations", "build_resource_key"),
    "build_slug": ("unio_collector.evidence.tagging.associations", "build_slug"),
    "build_supporting_resource_summary": ("unio_collector.evidence.tagging.associations", "build_supporting_resource_summary"),
    "build_tag_value_counts": ("unio_collector.evidence.tagging.associations", "build_tag_value_counts"),
    "collect_dominant_name_tokens": ("unio_collector.evidence.tagging.associations", "collect_dominant_name_tokens"),
    "describe_candidate_method": ("unio_collector.evidence.tagging.associations", "describe_candidate_method"),
    "extract_volume_id_from_snapshot_record": ("unio_collector.evidence.tagging.associations", "extract_volume_id_from_snapshot_record"),
    "get_finding_cost": ("unio_collector.evidence.tagging.cost_grouping", "get_finding_cost"),
    "has_conflicting_or_weak_majority": ("unio_collector.evidence.tagging.associations", "has_conflicting_or_weak_majority"),
    "resource_reference": ("unio_collector.evidence.tagging.cost_grouping", "resource_reference"),
    "select_no_candidate_reason": ("unio_collector.evidence.tagging.associations", "select_no_candidate_reason"),
    "tokenize_name": ("unio_collector.evidence.tagging.associations", "tokenize_name"),
}

__all__ = list(_EXPORTS)


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve an existing public symbol from its canonical owner."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        message = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(message) from exc
    return getattr(import_module(module_name), attribute_name)


def __dir__() -> list[str]:
    """Keep intentional public exports discoverable without importing them."""
    return sorted(set(globals()) | set(__all__))
