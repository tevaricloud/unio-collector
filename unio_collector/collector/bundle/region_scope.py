from __future__ import annotations  # noqa: D100

from typing import Any


def get_region_scope_summary(bundle: Any) -> dict[str, Any]:  # noqa: ANN401
    """Return bundle-safe region scope metadata."""
    region_scope = bundle.summary.get("region_scope")
    return dict(region_scope) if isinstance(region_scope, dict) else {}


def build_region_scope_limitations(bundle: Any) -> list[dict[str, str]]:  # noqa: ANN401
    """Return manifest limitation records for region-scope exclusions."""
    region_scope = get_region_scope_summary(bundle)
    limitations = region_scope.get("limitations")
    if not isinstance(limitations, list):
        return []
    return [
        {
            "type": "region_scope",
            "service": "all",
            "permission": "region-scope",
            "reason": str(limitation),
        }
        for limitation in limitations
        if limitation
    ]
