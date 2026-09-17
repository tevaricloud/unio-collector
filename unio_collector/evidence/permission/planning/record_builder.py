from __future__ import annotations  # noqa: D100

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from unio_collector.evidence.permission.planning.degradation import (
    DEGRADATION_RECORD_SCHEMA_VERSION,
    KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN,
    PermissionDegradationRecord,
    build_degradation_records_from_ledger,
    build_record_id,
    confidence_effect_for_outcome,
    downstream_effect_for_outcome,
    evidence_interpretation_for_outcome,
    limitation_category_for_values,
    sort_degradation_records,
)
from unio_collector.evidence.permission.planning.scanner_result_context import (
    actions_for_scanner_result,
    evidence_category_for_scanner,
    exact_requirement_type_for_action,
    iam_action_requirement_for_scanner_action,
    region_for_scanner_result,
)


def build_degradation_records(
    *,
    ledger_records: list[dict[str, Any]],
    scanner_results: list[dict[str, Any]],
    provider_id: str,
    account_id: str,
    run_id: str | None,
) -> tuple[PermissionDegradationRecord, ...]:
    """Build canonical records from API observations and scanner outcomes."""
    api_degradations = _api_degradation_notes(scanner_results)
    ledger_degradations, unmatched_degradations = _apply_api_degradation_notes(
        records=build_degradation_records_from_ledger(
            ledger_records=ledger_records,
            provider_id=provider_id,
            account_id=account_id,
            run_id=run_id,
        ),
        notes=api_degradations,
        run_id=run_id,
    )
    records = [
        *ledger_degradations,
        *_build_api_degradation_note_records(
            notes=unmatched_degradations,
            provider_id=provider_id,
            account_id=account_id,
            run_id=run_id,
        ),
        *_build_scanner_outcome_records(
            scanner_results=scanner_results,
            provider_id=provider_id,
            account_id=account_id,
            run_id=run_id,
            scanners_with_api_degradations={str(note.get("scanner_id") or "") for note in api_degradations},
        ),
    ]
    return sort_degradation_records(records)


def _build_scanner_outcome_records(
    *,
    scanner_results: list[dict[str, Any]],
    provider_id: str,
    account_id: str,
    run_id: str | None,
    scanners_with_api_degradations: set[str] | None = None,
) -> tuple[PermissionDegradationRecord, ...]:
    records: list[PermissionDegradationRecord] = []
    occurrence_counts: dict[tuple[str, str, str, str, str], int] = {}
    for result in scanner_results:
        scanner_id = str(result.get("scanner_id") or "").strip()
        status = str(result.get("status") or "").strip()
        if not scanner_id or status == "completed":
            continue
        if status == "completed_with_warnings" and scanner_id in (scanners_with_api_degradations or set()):
            continue
        outcome = _outcome_for_scanner_result(result)
        if outcome == "available":
            continue
        for action in actions_for_scanner_result(result):
            region = region_for_scanner_result(result)
            evidence_category = evidence_category_for_scanner(scanner_id, action)
            iam_action_requirement = iam_action_requirement_for_scanner_action(
                result,
                action,
            )
            key = (region, scanner_id, action, evidence_category, outcome)
            occurrence = occurrence_counts.get(key, 0)
            occurrence_counts[key] = occurrence + 1
            records.append(
                PermissionDegradationRecord(
                    schema_version=DEGRADATION_RECORD_SCHEMA_VERSION,
                    record_id=build_record_id(
                        run_id=run_id,
                        provider_id=provider_id,
                        account_id=account_id,
                        region=region,
                        scanner_id=scanner_id,
                        api_action=action,
                        evidence_category=evidence_category,
                        outcome=outcome,
                        occurrence_index=occurrence,
                    ),
                    provider_id=provider_id,
                    account_id=account_id,
                    region=region,
                    scanner_id=scanner_id,
                    api_action=action,
                    evidence_category=evidence_category,
                    outcome=outcome,
                    error_code=_error_code(result),
                    error_classification=_error_classification(
                        status,
                        outcome,
                        action,
                        _error_code(result),
                    ),
                    collection_continued=outcome != "interrupted",
                    evidence_interpretation=evidence_interpretation_for_outcome(
                        outcome,
                    ),
                    confidence_effect=confidence_effect_for_outcome(outcome),
                    downstream_effect=downstream_effect_for_outcome(outcome),
                    client_explanation=_client_explanation(result, outcome, action),
                    technical_detail="",
                    timestamp=_timestamp(result),
                    run_id=run_id,
                    api_call_succeeded=False,
                    scanner_continued=(outcome != "interrupted"),
                    iam_action_requirement=iam_action_requirement,
                    limitation_category=limitation_category_for_values(
                        outcome=outcome,
                        iam_action_requirement=iam_action_requirement,
                    ),
                    requirement_type=exact_requirement_type_for_action(
                        scanner_id,
                        action,
                    ),
                    evidence_categories=(evidence_category,),
                    requested_account_id=account_id,
                    requested_region=region,
                    remediation_permission=(action if outcome not in {"available", "expected_absence"} else None),
                    related_findings_may_be_incomplete=(outcome not in {"available", "expected_absence"}),
                ),
            )
    return tuple(records)


def _api_degradation_notes(
    scanner_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    for result in scanner_results:
        scanner_id = str(result.get("scanner_id") or "")
        coverage_notes = result.get("coverage_notes")
        if not isinstance(coverage_notes, list):
            continue
        for raw in coverage_notes:
            if not isinstance(raw, dict) or raw.get("note_type") != "api_degradation":
                continue
            if raw.get("outcome") != "partial":
                continue
            occurrence_count = max(1, int(raw.get("occurrence_count") or 1))
            notes.extend({**raw, "scanner_id": scanner_id} for _index in range(occurrence_count))
    return notes


def _apply_api_degradation_notes(
    *,
    records: tuple[PermissionDegradationRecord, ...],
    notes: list[dict[str, Any]],
    run_id: str | None,
) -> tuple[tuple[PermissionDegradationRecord, ...], list[dict[str, Any]]]:
    unmatched = list(notes)
    updated: list[PermissionDegradationRecord] = []
    occurrence_counts: dict[tuple[str, str, str, str, str], int] = {}
    for record in records:
        note_index = next(
            (
                index
                for index, note in enumerate(unmatched)
                if record.outcome == "unknown"
                and record.scanner_id == str(note.get("scanner_id") or "")
                and record.api_action == str(note.get("api_action") or "")
                and record.region == str(note.get("region") or "")
            ),
            None,
        )
        if note_index is None:
            updated.append(record)
            continue
        note = unmatched.pop(note_index)
        outcome = "partial"
        key = (
            record.region,
            record.scanner_id,
            record.api_action,
            record.evidence_category,
            outcome,
        )
        occurrence = occurrence_counts.get(key, 0)
        occurrence_counts[key] = occurrence + 1
        updated.append(
            replace(
                record,
                record_id=build_record_id(
                    run_id=run_id,
                    provider_id=record.provider_id,
                    account_id=record.account_id,
                    region=record.region,
                    scanner_id=record.scanner_id,
                    api_action=record.api_action,
                    evidence_category=record.evidence_category,
                    outcome=outcome,
                    occurrence_index=occurrence,
                ),
                outcome=outcome,
                error_classification=str(
                    note.get("error_classification") or "partial_collection",
                ),
                collection_continued=True,
                evidence_interpretation=evidence_interpretation_for_outcome(outcome),
                confidence_effect=confidence_effect_for_outcome(outcome),
                downstream_effect=downstream_effect_for_outcome(outcome),
                client_explanation=(f"{record.api_action} returned incomplete resource-level evidence; collection continued for other resources."),
                scanner_continued=True,
                affected_fields=tuple(
                    sorted(str(value) for value in note.get("affected_fields", []) or [] if str(value)),
                ),
                resource_type=(str(note.get("resource_type")) if note.get("resource_type") else None),
                resource_id=(str(note.get("resource_id")) if note.get("resource_id") else None),
                safe_scope=(str(note.get("safe_scope")) if note.get("safe_scope") else None),
                requested_account_id=(str(note.get("requested_account_id")) if note.get("requested_account_id") else record.account_id),
                requested_region=(str(note.get("requested_region")) if note.get("requested_region") else record.region),
                related_findings_may_be_incomplete=True,
            ),
        )
    return tuple(updated), unmatched


def _build_api_degradation_note_records(
    *,
    notes: list[dict[str, Any]],
    provider_id: str,
    account_id: str,
    run_id: str | None,
) -> tuple[PermissionDegradationRecord, ...]:
    records: list[PermissionDegradationRecord] = []
    occurrence_counts: dict[tuple[str, str, str, str, str], int] = {}
    for note in notes:
        scanner_id = str(note.get("scanner_id") or "unknown-scanner")
        action = str(note.get("api_action") or "unknown:unknown")
        region = str(note.get("region") or "aws-global")
        outcome = "partial"
        note_evidence_categories = tuple(
            sorted(str(value) for value in note.get("evidence_categories", []) or [] if str(value)),
        )
        evidence_category = str(
            note.get("resource_type") or (note_evidence_categories[0] if note_evidence_categories else "") or action.split(":", maxsplit=1)[0]
        )
        key = (region, scanner_id, action, evidence_category, outcome)
        occurrence = occurrence_counts.get(key, 0)
        occurrence_counts[key] = occurrence + 1
        records.append(
            PermissionDegradationRecord(
                schema_version=DEGRADATION_RECORD_SCHEMA_VERSION,
                record_id=build_record_id(
                    run_id=run_id,
                    provider_id=provider_id,
                    account_id=account_id,
                    region=region,
                    scanner_id=scanner_id,
                    api_action=action,
                    evidence_category=evidence_category,
                    outcome=outcome,
                    occurrence_index=occurrence,
                ),
                provider_id=provider_id,
                account_id=account_id,
                region=region,
                scanner_id=scanner_id,
                api_action=action,
                evidence_category=evidence_category,
                outcome=outcome,
                error_code=None,
                error_classification=str(
                    note.get("error_classification") or "partial_collection",
                ),
                collection_continued=True,
                evidence_interpretation=evidence_interpretation_for_outcome(outcome),
                confidence_effect=confidence_effect_for_outcome(outcome),
                downstream_effect=downstream_effect_for_outcome(outcome),
                client_explanation=(f"{action} returned incomplete resource-level evidence; collection continued for other resources."),
                technical_detail="",
                timestamp=str(note.get("timestamp") or datetime.now(UTC).isoformat()),
                run_id=run_id,
                api_call_succeeded=False,
                scanner_continued=True,
                iam_action_requirement=str(
                    note.get("iam_action_requirement") or "required",
                ),
                limitation_category=limitation_category_for_values(
                    outcome=outcome,
                    iam_action_requirement=str(
                        note.get("iam_action_requirement") or "required",
                    ),
                ),
                requirement_type=exact_requirement_type_for_action(
                    scanner_id,
                    action,
                ),
                evidence_categories=(note_evidence_categories or (evidence_category,)),
                affected_fields=tuple(
                    sorted(str(value) for value in note.get("affected_fields", []) or [] if str(value)),
                ),
                resource_type=(str(note.get("resource_type")) if note.get("resource_type") else None),
                resource_id=(str(note.get("resource_id")) if note.get("resource_id") else None),
                safe_scope=(str(note.get("safe_scope")) if note.get("safe_scope") else None),
                requested_account_id=(str(note.get("requested_account_id") or account_id)),
                requested_region=str(
                    note.get("requested_region") or region,
                ),
                remediation_permission=action,
                related_findings_may_be_incomplete=True,
            ),
        )
    return tuple(records)


def _outcome_for_scanner_result(result: dict[str, Any]) -> str:
    status = str(result.get("status") or "")
    detail = _technical_detail(result).casefold()
    if status == "permission_denied":
        return "denied"
    if status in {"disabled", "skipped"}:
        return _skipped_outcome(detail)
    if status == "unavailable":
        return _unavailable_outcome(detail)
    if status == "completed_with_warnings":
        return "partial"
    if status == "failed":
        return _failed_outcome(result, detail)
    return "unknown"


def _skipped_outcome(detail: str) -> str:
    if "chargeable" in detail and "disabled" in detail:
        return "chargeable_disabled"
    return "not_exercised"


def _unavailable_outcome(detail: str) -> str:
    if _is_expected_absence_detail(detail):
        return "expected_absence"
    if "dependency" in detail or "module" in detail or "import" in detail:
        return "dependency_unavailable"
    if "unsupported region" in detail or "not opted" in detail:
        return "unsupported_region"
    return "service_unavailable"


def _failed_outcome(result: dict[str, Any], detail: str) -> str:
    if _is_expected_absence_detail(detail):
        return "expected_absence"
    if "interrupt" in detail or "cancel" in detail:
        return "interrupted"
    if int(result.get("evidence_count") or 0) > 0:
        return "partial"
    return "unknown"


def _error_code(result: dict[str, Any]) -> str | None:
    for error in result.get("errors", []) or []:
        text = str(error)
        if "AccessDenied" in text:
            return "AccessDenied"
        if "UnauthorizedOperation" in text:
            return "UnauthorizedOperation"
        if "ExpiredToken" in text:
            return "ExpiredToken"
    return None


def _error_classification(
    status: str,
    outcome: str,
    action: str,
    error_code: str | None,
) -> str:
    if outcome == "denied" and action.casefold() == "kms:describekey" and "accessdenied" in str(error_code or "").casefold():
        return KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN
    if outcome == "expected_absence":
        return "expected_absence"
    if outcome == "denied":
        return "permission_denied"
    if outcome == "chargeable_disabled":
        return "chargeable_api_disabled"
    if outcome == "unsupported_region":
        return "unsupported_region"
    if outcome == "unsupported_operation":
        return "unsupported_operation"
    if outcome == "service_unavailable":
        return "service_unavailable"
    if outcome == "interrupted":
        return "interrupted"
    if outcome == "partial":
        return "partial_collection"
    return status or "unknown"


def _client_explanation(
    result: dict[str, Any],
    outcome: str,
    action: str,
) -> str:
    scanner_id = str(result.get("scanner_id") or "unknown scanner")
    if outcome == "chargeable_disabled":
        return f"{scanner_id} did not use {action} because chargeable collection was not enabled."
    if outcome == "not_exercised":
        return f"{scanner_id} did not exercise {action} during collection."
    if outcome == "partial":
        return f"{scanner_id} collected only partial evidence for {action}."
    if outcome == "expected_absence":
        return f"{scanner_id} observed that the optional resource or configuration for {action} was absent."
    if outcome == "denied":
        if action == "kms:DescribeKey":
            return (
                "kms:DescribeKey was denied. KMS key visibility may require both IAM "
                "allowance and key-policy, grant, ownership, or key-state access; "
                "AWS did not expose which control caused the denial."
            )
        return f"{scanner_id} was denied access to {action}."
    return f"{scanner_id} could not establish complete evidence for {action}."


def _technical_detail(result: dict[str, Any]) -> str:
    values: list[str] = []
    for field_name in ("reason", "skip_reason", "disabled_reason"):
        value = result.get(field_name)
        if value:
            values.append(str(value))
    for field_name in ("errors", "warnings", "limitations"):
        raw = result.get(field_name)
        if isinstance(raw, list | tuple):
            values.extend(str(value) for value in raw if str(value))
    return "; ".join(dict.fromkeys(values))


def _is_expected_absence_detail(detail: str) -> bool:
    markers = (
        "nosuch",
        "not configured",
        "not found",
        "not present",
        "does not exist",
        "missing optional",
        "publicaccessblockconfiguration",
        "lifecycle configuration",
        "replication configuration",
        "login profile",
    )
    return any(marker in detail for marker in markers)


def _timestamp(result: dict[str, Any]) -> str:
    for field_name in ("completed_at", "started_at"):
        value = result.get(field_name)
        if value:
            return str(value)
    return datetime.now(UTC).isoformat()


__all__ = ["build_degradation_records"]
