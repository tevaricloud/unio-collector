from __future__ import annotations  # noqa: D100

from typing import Any


def get_bundle_scanner_results(
    scan_result: Any,  # noqa: ANN401
    *,
    bundle_purpose: str,
) -> list[dict[str, Any]]:
    """Return scanner result rows appropriate for the bundle purpose."""
    fixture_parity_results = getattr(scan_result, "fixture_parity_scanner_results", [])
    source_results = fixture_parity_results if bundle_purpose == "collector_evidence" and fixture_parity_results else scan_result.scanner_results
    return [result.convert_to_dict() for result in source_results]


__all__ = ["get_bundle_scanner_results"]
