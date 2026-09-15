from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from zipfile import ZipFile


def validate_permission_degradation_records(
    archive: ZipFile,
    names: set[str],
    errors: list[str],
    read_json: Any,  # noqa: ANN401
    *,
    manifest: dict[str, object] | None = None,
) -> None:
    """Validate optional canonical permission-degradation records."""
    if "permissions/degradation-records.json" not in names:
        if manifest is not None and manifest.get("permission_degradation_record_count") not in (None, 0):
            errors.append("manifest.json claims permission degradation records but the records file is missing.")
        return
    payload = read_json(
        archive,
        "permissions/degradation-records.json",
        errors,
    )
    if not payload:
        return
    if payload.get("schema_version") != "2026-07":
        errors.append(
            "permissions/degradation-records.json schema_version must be '2026-07'.",
        )
    records = payload.get("records")
    if not isinstance(records, list):
        errors.append("permissions/degradation-records.json records must be a list.")
        return
    if manifest is not None and "permission_degradation_record_count" in manifest and manifest["permission_degradation_record_count"] != len(records):
        errors.append("manifest.json permission_degradation_record_count does not match permissions/degradation-records.json.")
    previous_key: tuple[str, ...] | None = None
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            errors.append(
                f"permissions/degradation-records.json records[{index}] must be an object.",
            )
            continue
        _validate_record_fields(item, index, errors)
        _validate_optional_bool_fields(item, index, errors)
        _validate_optional_context_fields(item, index, errors)
        current_key = _record_sort_key(item)
        if previous_key is not None and current_key < previous_key:
            errors.append(
                "permissions/degradation-records.json records must be sorted deterministically.",
            )
            return
        previous_key = current_key


def _validate_record_fields(
    item: dict[str, object],
    index: int,
    errors: list[str],
) -> None:
    required = (
        "schema_version",
        "record_id",
        "provider_id",
        "account_id",
        "region",
        "scanner_id",
        "api_action",
        "evidence_category",
        "outcome",
        "evidence_interpretation",
    )
    errors.extend(
        f"permissions/degradation-records.json records[{index}] {field} must be a non-empty string."
        for field in required
        if not isinstance(item.get(field), str) or not str(item[field]).strip()
    )
    if item.get("schema_version") != "2026-07":
        errors.append(f"permissions/degradation-records.json records[{index}] schema_version must be '2026-07'.")


def _validate_optional_bool_fields(
    item: dict[str, object],
    index: int,
    errors: list[str],
) -> None:
    errors.extend(
        f"permissions/degradation-records.json records[{index}] {field} must be a boolean or null."
        for field in (
            "api_call_succeeded",
            "scanner_continued",
            "collection_continued",
            "related_findings_may_be_incomplete",
        )
        if field in item and item[field] is not None and not isinstance(item[field], bool)
    )
    errors.extend(
        f"permissions/degradation-records.json records[{index}] {field} must be a list."
        for field in ("evidence_categories", "affected_fields")
        if field in item and not isinstance(item[field], list)
    )


def _validate_optional_context_fields(
    item: dict[str, object],
    index: int,
    errors: list[str],
) -> None:
    for field in (
        "requirement_type",
        "resource_type",
        "resource_id",
        "safe_scope",
        "requested_account_id",
        "requested_region",
        "remediation_permission",
        "ledger_event_id",
    ):
        value = item.get(field)
        if value is not None and not isinstance(value, str):
            errors.append(
                f"permissions/degradation-records.json records[{index}] {field} must be a string or null.",
            )
    for field in ("evidence_categories", "affected_fields"):
        value = item.get(field)
        if isinstance(value, list) and any(not isinstance(member, str) for member in value):
            errors.append(
                f"permissions/degradation-records.json records[{index}] {field} entries must be strings.",
            )


def _record_sort_key(item: dict[str, object]) -> tuple[str, ...]:
    return tuple(
        str(item.get(field) or "")
        for field in (
            "provider_id",
            "account_id",
            "region",
            "scanner_id",
            "api_action",
            "evidence_category",
            "outcome",
            "record_id",
        )
    )


__all__ = ["validate_permission_degradation_records"]
