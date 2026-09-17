from __future__ import annotations  # noqa: D104

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from unio_collector.scanners.tagging.association_collectors import (
        autoscaling_tags_to_dict,
        collect_auto_scaling_groups,
        collect_auto_scaling_taggable_records,
        collect_elbv2_load_balancers,
        collect_elbv2_tags,
        collect_elbv2_target_groups,
        collect_elbv2_target_ids,
        collect_elbv2_target_ids_for_load_balancer,
        collect_elbv2_target_ids_for_target_group,
        collect_load_balancer_taggable_records,
    )
    from unio_collector.scanners.tagging.evidence import TaggingEvidence
    from unio_collector.scanners.tagging.missing_cost_tags import MissingCostTagsScanner
    from unio_collector.scanners.tagging.packs import TAGGING_SCANNER_MODULE_REGISTRATION, TAGGING_SCANNER_PACKS, TAGGING_SCANNER_TYPES
    from unio_collector.scanners.tagging.record_merge import (
        build_nat_gateway_taggable_records,
        build_tagging_fast_path_disabled_note,
        build_tagging_fast_path_note,
        get_taggable_resource_key,
        merge_taggable_resource_record,
        merge_taggable_resource_records,
        pluralize,
        score_association_strength,
        select_preferred_association,
    )

_EXPORTS = {
    "TAGGING_SCANNER_MODULE_REGISTRATION": ("unio_collector.scanners.tagging.packs", "TAGGING_SCANNER_MODULE_REGISTRATION"),
    "TAGGING_SCANNER_PACKS": ("unio_collector.scanners.tagging.packs", "TAGGING_SCANNER_PACKS"),
    "TAGGING_SCANNER_TYPES": ("unio_collector.scanners.tagging.packs", "TAGGING_SCANNER_TYPES"),
    "MissingCostTagsScanner": ("unio_collector.scanners.tagging.missing_cost_tags", "MissingCostTagsScanner"),
    "TaggingEvidence": ("unio_collector.scanners.tagging.evidence", "TaggingEvidence"),
    "autoscaling_tags_to_dict": ("unio_collector.scanners.tagging.helpers", "autoscaling_tags_to_dict"),
    "build_nat_gateway_taggable_records": ("unio_collector.scanners.tagging.helpers", "build_nat_gateway_taggable_records"),
    "build_tagging_fast_path_disabled_note": ("unio_collector.scanners.tagging.helpers", "build_tagging_fast_path_disabled_note"),
    "build_tagging_fast_path_note": ("unio_collector.scanners.tagging.helpers", "build_tagging_fast_path_note"),
    "collect_auto_scaling_groups": ("unio_collector.scanners.tagging.helpers", "collect_auto_scaling_groups"),
    "collect_auto_scaling_taggable_records": ("unio_collector.scanners.tagging.helpers", "collect_auto_scaling_taggable_records"),
    "collect_elbv2_load_balancers": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_load_balancers"),
    "collect_elbv2_tags": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_tags"),
    "collect_elbv2_target_groups": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_target_groups"),
    "collect_elbv2_target_ids": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_target_ids"),
    "collect_elbv2_target_ids_for_load_balancer": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_target_ids_for_load_balancer"),
    "collect_elbv2_target_ids_for_target_group": ("unio_collector.scanners.tagging.helpers", "collect_elbv2_target_ids_for_target_group"),
    "collect_load_balancer_taggable_records": ("unio_collector.scanners.tagging.helpers", "collect_load_balancer_taggable_records"),
    "get_taggable_resource_key": ("unio_collector.scanners.tagging.helpers", "get_taggable_resource_key"),
    "merge_taggable_resource_record": ("unio_collector.scanners.tagging.helpers", "merge_taggable_resource_record"),
    "merge_taggable_resource_records": ("unio_collector.scanners.tagging.helpers", "merge_taggable_resource_records"),
    "pluralize": ("unio_collector.scanners.tagging.helpers", "pluralize"),
    "score_association_strength": ("unio_collector.scanners.tagging.helpers", "score_association_strength"),
    "select_preferred_association": ("unio_collector.scanners.tagging.helpers", "select_preferred_association"),
}

__all__ = [
    "TAGGING_SCANNER_MODULE_REGISTRATION",
    "TAGGING_SCANNER_PACKS",
    "TAGGING_SCANNER_TYPES",
    "MissingCostTagsScanner",
    "TaggingEvidence",
    "autoscaling_tags_to_dict",
    "build_nat_gateway_taggable_records",
    "build_tagging_fast_path_disabled_note",
    "build_tagging_fast_path_note",
    "collect_auto_scaling_groups",
    "collect_auto_scaling_taggable_records",
    "collect_elbv2_load_balancers",
    "collect_elbv2_tags",
    "collect_elbv2_target_groups",
    "collect_elbv2_target_ids",
    "collect_elbv2_target_ids_for_load_balancer",
    "collect_elbv2_target_ids_for_target_group",
    "collect_load_balancer_taggable_records",
    "get_taggable_resource_key",
    "merge_taggable_resource_record",
    "merge_taggable_resource_records",
    "pluralize",
    "score_association_strength",
    "select_preferred_association",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Resolve retained public exports without importing private analysis eagerly."""
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg) from exc
    return getattr(import_module(module_name), attribute_name)
