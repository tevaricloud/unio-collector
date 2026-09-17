from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unio_collector.privacy.profiles import PrivacyProfile


def is_strict_cost_key(profile: PrivacyProfile, key: str | None) -> bool:
    """Return true when the profile requires this cost-like key to be removed."""
    if profile.cost_data_included:
        return False
    lowered = (key or "").lower()
    if lowered == "rate" or lowered.endswith("_rate"):
        return True
    return any(
        part in lowered
        for part in (
            "cost",
            "saving",
            "spend",
            "price",
            "amount",
            "charge",
            "billing",
        )
    )


def is_strict_timestamp_key(profile: PrivacyProfile, key: str | None) -> bool:
    """Return true when the profile requires this timestamp-like key to be generalised."""
    if profile.timestamp_precision != "month":
        return False
    lowered = (key or "").lower()
    exact = {
        "timestamp",
        "time",
        "date",
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "generated_at",
    }
    return lowered in exact or lowered.endswith(
        ("_timestamp", "_date", "_created_at", "_updated_at", "_started_at", "_completed_at", "_generated_at"),
    )


def is_strict_region_key(profile: PrivacyProfile, key: str | None) -> bool:
    """Return true when the profile requires this region key to be generalised."""
    if profile.region_visibility != "generalised":
        return False
    lowered = (key or "").lower()
    return lowered in {"region", "regions", "scanned_regions", "selected_regions"} or lowered.endswith("_region")


def is_strict_topology_key(profile: PrivacyProfile, key: str | None) -> bool:
    """Return true when the profile requires this topology key to be reduced."""
    if profile.topology_detail != "reduced":
        return False
    lowered = (key or "").lower()
    return any(
        part in lowered
        for part in (
            "topology",
            "relationship",
            "relationships",
            "route_table",
            "routes",
            "attachment",
            "attachments",
            "edges",
            "network_path",
        )
    )


def is_strict_log_key(profile: PrivacyProfile, path: str, key: str | None) -> bool:
    """Return true when the profile requires this log/free-text key to be removed."""
    if profile.profile_id != "strict":
        return False
    lowered = (key or "").lower()
    return path.endswith("collection-log.jsonl") or lowered in {"error", "errors", "exception", "message", "traceback"}
