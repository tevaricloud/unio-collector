from __future__ import annotations  # noqa: D100

SUPPORTED_ANALYSIS_BOUNDARIES = {
    "result_bundle_only",
    "strict_evidence_only_ready",
}


def validate_scanner_analysis_boundary_summary(  # noqa: D103
    collection_summary: dict[str, object],
    errors: list[str],
) -> None:
    value = collection_summary.get("scanner_analysis_boundary_summary")
    if not isinstance(value, dict):
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary must be an object.",
        )
        return
    errors.extend(
        f"collection-summary.json scanner_analysis_boundary_summary.{key} must be a non-negative integer."
        for key in (
            "scanner_count",
            "strict_evidence_only_ready_count",
            "result_bundle_only_count",
        )
        if not _is_non_negative_int(value.get(key))
    )
    by_boundary = value.get("by_analysis_boundary")
    if not isinstance(by_boundary, dict):
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary.by_analysis_boundary must be an object.",
        )
        return
    _validate_boundary_counts(by_boundary, errors)
    deferred = value.get("deferred_scanner_ids")
    if not isinstance(deferred, list) or not all(isinstance(item, str) and item for item in deferred):
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary.deferred_scanner_ids must be a list of scanner IDs.",
        )
        return
    if len(set(deferred)) != len(deferred) or any(not item.strip() for item in deferred):
        errors.append("collection-summary.json scanner_analysis_boundary_summary.deferred_scanner_ids must be unique non-empty scanner IDs.")
    _validate_count_consistency(value, by_boundary, errors)


def _validate_boundary_counts(
    by_boundary: dict[object, object],
    errors: list[str],
) -> None:
    unknown = sorted(str(key) for key in by_boundary if key not in SUPPORTED_ANALYSIS_BOUNDARIES)
    errors.extend(f"collection-summary.json scanner_analysis_boundary_summary.by_analysis_boundary contains unsupported boundary: {key}." for key in unknown)
    for key, count in by_boundary.items():
        if not _is_non_negative_int(count):
            errors.append(
                f"collection-summary.json scanner_analysis_boundary_summary.by_analysis_boundary.{key} must be a non-negative integer.",
            )


def _validate_count_consistency(
    summary: dict[object, object],
    by_boundary: dict[object, object],
    errors: list[str],
) -> None:
    scanner_count = summary.get("scanner_count")
    strict_count = summary.get("strict_evidence_only_ready_count")
    result_only_count = summary.get("result_bundle_only_count")
    deferred = summary.get("deferred_scanner_ids")
    if not (
        isinstance(scanner_count, int)
        and scanner_count >= 0
        and isinstance(strict_count, int)
        and strict_count >= 0
        and isinstance(result_only_count, int)
        and result_only_count >= 0
        and isinstance(deferred, list)
    ):
        return
    if strict_count + result_only_count != scanner_count:
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary "
            "strict_evidence_only_ready_count plus result_bundle_only_count "
            "must equal scanner_count.",
        )
    by_boundary_total = sum(count for count in by_boundary.values() if isinstance(count, int))
    if by_boundary_total != scanner_count:
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary by_analysis_boundary counts must equal scanner_count.",
        )
    for boundary, expected in (("strict_evidence_only_ready", strict_count), ("result_bundle_only", result_only_count)):
        if by_boundary.get(boundary, 0) != expected:
            errors.append("collection-summary.json scanner_analysis_boundary_summary by_analysis_boundary values must match their individual counts.")
    if len(deferred) != result_only_count:
        errors.append(
            "collection-summary.json scanner_analysis_boundary_summary deferred_scanner_ids count must equal result_bundle_only_count.",
        )


def _is_non_negative_int(value: object) -> bool:
    return type(value) is int and value >= 0
