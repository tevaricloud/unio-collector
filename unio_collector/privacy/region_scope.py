"""Explicit privacy classifications for region-scope producer metadata."""

from __future__ import annotations

import re

from unio_collector.privacy.registry_entry import PrivacyRegistryEntry

REGION_SCOPE_MEMBERS = ("account-scope.json", "collection-summary.json", "manifest.json")
_METADATA = (
    "scope_version",
    "selection_mode",
    "explicit_region_scope",
    "discovery_status",
    "shared_region_discovery_scanner_id",
    "regions_from_billing_requested",
    "regions_from_billing_effective",
    "billing_region_source",
    "billing_region_status",
    "materiality_threshold",
    "excluded_region_count",
    "global_scope.enabled",
    "global_scope.pseudo_scope",
    "global_scope.regional_target",
    "control_sources.requested_regions",
    "control_sources.regions_from_billing",
    "control_sources.global_checks",
    "excluded_regions[].opt_in_status",
    "excluded_regions[].status",
    "excluded_regions[].stage",
)
_REGIONS = (
    "billing_active_regions",
    "normalized_candidate_regions",
    "material_billing_candidate_regions",
    "residual_billing_candidate_regions",
    "explicit_requested_regions",
    "selected_regional_targets",
    "selected_regions",
    "enabled_regions",
)
_CONTAINERS = ("", "global_scope", "control_sources", "excluded_regions", "excluded_regions[]", "service_specific_exclusions")
_CATEGORIES = {
    **{f"$.region_scope.{field}": "safe_metadata" for field in _METADATA},
    **{f"$.region_scope.{field}{suffix}": "region" for field in _REGIONS for suffix in ("", "[]")},
    **{f"$.region_scope{'.' if field else ''}{field}": "safe_metadata" for field in _CONTAINERS},
    **{f"$.region_scope.{field}{suffix}": "free_text" for field in ("limitations",) for suffix in ("", "[]")},
    "$.region_scope.excluded_regions[].reason": "free_text",
    "$.region_scope.excluded_regions[].region_name": "resource_name",
    "$.region_scope.unrecognized_billing_region_values": "resource_name",
    "$.region_scope.unrecognized_billing_region_values[]": "resource_name",
}


def region_scope_category(json_path: str) -> str | None:
    """Resolve only named producer paths, including optional/container values."""
    return _CATEGORIES.get(re.sub(r"\[[0-9]+\]", "[]", json_path))


def region_scope_entries() -> tuple[PrivacyRegistryEntry, ...]:
    """Classify each exact producer path without admitting unknown descendants."""
    return tuple(
        PrivacyRegistryEntry(
            domain="protected_bundle_input",
            member_pattern=member,
            json_path_pattern=path.replace("[]", "[*]"),
            value_category=category,
            treatment=(
                "generalise"
                if category == "region" and profile == "strict"
                else "tokenise"
                if category == "resource_name"
                else "profile_configurable"
                if category in {"region", "free_text"}
                else "preserve"
            ),
            allowed_profiles=(profile,),
            limitations=(
                (
                    "Exact region-scope producer field; no unknown descendants are admitted. "
                    "Raw unrecognized values are tokenised and strict regions are generalised."
                ),
            ),
        )
        for member in REGION_SCOPE_MEMBERS
        for path, category in _CATEGORIES.items()
        for profile in ("standard", "strict", "custom")
    )
