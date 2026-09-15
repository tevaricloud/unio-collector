from __future__ import annotations  # noqa: D100

from typing import Any


def get_billing_context_summary(bundle: Any) -> dict[str, dict[str, Any]]:  # noqa: ANN401
    """Return typed billing context retained in a collector bundle summary."""
    summary: dict[str, dict[str, Any]] = {}
    for key in (
        "billing_region_coverage",
        "billing_region_scope_derivation",
    ):
        value = bundle.summary.get(key)
        if isinstance(value, dict):
            summary[key] = dict(value)
    return summary
