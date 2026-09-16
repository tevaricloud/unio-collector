"""Resolve compatible preset IDs using collection-only defaults."""

from __future__ import annotations

from unio_collector.collector.config.preset import CollectionPreset

SCAN_PRESET_IDS = (
    "dev-fast",
    "dev-report",
    "client-review",
    "full-evidence",
    "framework-readiness",
    "governance-readiness",
    "readiness-fast",
    "governance-readiness-only",
    "cyber-essentials-review",
    "security-readiness",
    "redacted-demo",
)

COLLECTION_PRESETS: dict[str, CollectionPreset] = {
    "dev-fast": CollectionPreset(preset_id="dev-fast", detail_profile="development"),
    "dev-report": CollectionPreset(preset_id="dev-report", detail_profile="development"),
    "client-review": CollectionPreset(preset_id="client-review", detail_profile="full"),
    "full-evidence": CollectionPreset(preset_id="full-evidence", detail_profile="full"),
    "framework-readiness": CollectionPreset(
        preset_id="framework-readiness", detail_profile="full", regions_from_billing=True, scan_mode="readiness", scan_pillars=("secure", "govern", "automate")
    ),
    "governance-readiness": CollectionPreset(
        preset_id="governance-readiness", detail_profile="full", regions_from_billing=True, scan_mode="readiness", scan_pillars=("secure", "govern", "automate")
    ),
    "readiness-fast": CollectionPreset(preset_id="readiness-fast", detail_profile="development", regions_from_billing=True, scan_mode="readiness"),
    "governance-readiness-only": CollectionPreset(
        preset_id="governance-readiness-only", detail_profile="full", regions_from_billing=True, scan_mode="readiness"
    ),
    "cyber-essentials-review": CollectionPreset(preset_id="cyber-essentials-review", detail_profile="full", regions_from_billing=True, scan_mode="readiness"),
    "security-readiness": CollectionPreset(
        preset_id="security-readiness", detail_profile="full", regions_from_billing=True, scan_mode="secure", scan_pillars=("secure", "govern")
    ),
    "redacted-demo": CollectionPreset(preset_id="redacted-demo"),
}


def get_collection_preset(preset_id: str | None) -> CollectionPreset | None:
    """Resolve a known preset without application policy or rendering defaults."""
    if preset_id in (None, ""):
        return None
    try:
        return COLLECTION_PRESETS[str(preset_id)]
    except KeyError as exc:
        allowed = ", ".join(SCAN_PRESET_IDS)
        msg = f"Scan preset must be one of: {allowed}."
        raise ValueError(msg) from exc
