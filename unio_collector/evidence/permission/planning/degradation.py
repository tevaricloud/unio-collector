from __future__ import annotations  # noqa: D100

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from unio_collector.aws import errors as aws_errors
from unio_collector.evidence.permission.planning.legacy import (
    classify_legacy_limitation_outcome,
)
from unio_collector.evidence.permission.planning.limitation_category import (
    limitation_category_for_record,
    limitation_category_for_values,
)
from unio_collector.evidence.permission.planning.outcome_effect import (
    confidence_effect_for_outcome,
    downstream_effect_for_outcome,
    evidence_interpretation_for_outcome,
)

DEGRADATION_RECORD_SCHEMA_VERSION = "2026-07"
KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN = "access_denied_policy_source_unknown"


@dataclass(frozen=True)
class PermissionDegradationRecord:
    """Canonical permission and evidence-degradation record."""

    schema_version: str
    record_id: str
    provider_id: str
    account_id: str
    region: str
    scanner_id: str
    api_action: str
    evidence_category: str
    outcome: str
    error_code: str | None
    error_classification: str
    collection_continued: bool
    evidence_interpretation: str
    confidence_effect: str
    downstream_effect: str
    client_explanation: str
    technical_detail: str
    timestamp: str
    run_id: str | None
    api_call_succeeded: bool | None = None
    scanner_continued: bool | None = None
    ledger_event_id: str | None = None
    iam_action_requirement: str | None = None
    limitation_category: str | None = None
    requirement_type: str | None = None
    evidence_categories: tuple[str, ...] = ()
    affected_fields: tuple[str, ...] = ()
    resource_type: str | None = None
    resource_id: str | None = None
    safe_scope: str | None = None
    requested_account_id: str | None = None
    requested_region: str | None = None
    remediation_permission: str | None = None
    related_findings_may_be_incomplete: bool | None = None

    def convert_to_dict(self) -> dict[str, object]:
        """Return deterministic client-safe JSON-compatible output."""
        payload = asdict(self)
        payload.pop("technical_detail", None)
        return payload


def build_degradation_records_from_ledger(
    *,
    ledger_records: list[dict[str, Any]],
    provider_id: str,
    account_id: str,
    run_id: str | None,
) -> tuple[PermissionDegradationRecord, ...]:
    """Build canonical records from observed API-call ledger records."""
    records: list[PermissionDegradationRecord] = []
    occurrence_counts: dict[tuple[str, str, str, str, str], int] = {}
    for raw in ledger_records:
        unio = raw.get("unio", {})
        if not isinstance(unio, dict):
            unio = {}
        scanner_id = str(unio.get("scanner_id") or "unknown-scanner")
        action = str(unio.get("declared_api_call") or _action_from_ledger(raw))
        region = str(raw.get("awsRegion") or "aws-global")
        outcome = _record_outcome(raw, unio)
        evidence_category = action.split(":", maxsplit=1)[0] if ":" in action else "unknown"
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
                error_code=(str(raw.get("errorCode")) if raw.get("errorCode") else None),
                error_classification=_ledger_error_classification(
                    raw,
                    unio,
                    action,
                    outcome,
                ),
                collection_continued=_collection_continued(raw, unio),
                evidence_interpretation=evidence_interpretation_for_outcome(outcome),
                confidence_effect=confidence_effect_for_outcome(outcome),
                downstream_effect=downstream_effect_for_outcome(outcome),
                client_explanation=_client_explanation(outcome, action),
                technical_detail="",
                timestamp=str(raw.get("eventTime") or datetime.now(UTC).isoformat()),
                run_id=run_id,
                api_call_succeeded=(outcome == "available"),
                scanner_continued=_scanner_continued(unio),
                ledger_event_id=(str(raw.get("eventID")) if raw.get("eventID") else None),
                iam_action_requirement=_iam_action_requirement(unio),
                limitation_category=limitation_category_for_values(
                    outcome=outcome,
                    iam_action_requirement=_iam_action_requirement(unio),
                ),
                requirement_type=_exact_requirement_type(
                    unio,
                    scanner_id=scanner_id,
                    api_action=action,
                ),
                evidence_categories=(evidence_category,),
                affected_fields=_string_tuple(
                    unio.get("affected_fields"),
                ),
                resource_type=_optional_string(unio.get("resource_type")),
                resource_id=_optional_string(unio.get("resource_id")),
                safe_scope=_optional_string(unio.get("safe_scope")),
                requested_account_id=str(
                    raw.get("recipientAccountId") or account_id,
                ),
                requested_region=region,
                remediation_permission=(action if outcome not in {"available", "expected_absence"} else None),
                related_findings_may_be_incomplete=(outcome not in {"available", "expected_absence"}),
            ),
        )
    return sort_degradation_records(records)


def build_legacy_degradation_records(
    *,
    limitations: list[dict[str, Any]],
    provider_id: str,
    account_id: str,
    run_id: str | None,
) -> tuple[PermissionDegradationRecord, ...]:
    """Adapt legacy manifest limitations into partial canonical records."""
    records: list[PermissionDegradationRecord] = []
    for index, limitation in enumerate(limitations):
        action = _legacy_action(limitation)
        outcome = classify_legacy_limitation_outcome(limitation)
        region = str(limitation.get("region") or "unknown")
        scanner_id = str(limitation.get("scanner_id") or "unknown-scanner")
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
                    evidence_category=action.split(":", maxsplit=1)[0],
                    outcome=outcome,
                    occurrence_index=index,
                ),
                provider_id=provider_id,
                account_id=account_id,
                region=region,
                scanner_id=scanner_id,
                api_action=action,
                evidence_category=action.split(":", maxsplit=1)[0],
                outcome=outcome,
                error_code=str(limitation.get("error_code") or ""),
                error_classification=str(limitation.get("type") or "legacy_limitation"),
                collection_continued=True,
                evidence_interpretation=evidence_interpretation_for_outcome(outcome),
                confidence_effect=confidence_effect_for_outcome(outcome),
                downstream_effect=downstream_effect_for_outcome(outcome),
                client_explanation=str(limitation.get("reason") or "Legacy permission limitation."),
                technical_detail="",
                timestamp=datetime.now(UTC).isoformat(),
                run_id=run_id,
                api_call_succeeded=(outcome == "available"),
                scanner_continued=True,
                iam_action_requirement=str(
                    limitation.get("iam_action_requirement") or "required",
                ),
                limitation_category=limitation_category_for_values(
                    outcome=outcome,
                    iam_action_requirement=str(
                        limitation.get("iam_action_requirement") or "required",
                    ),
                ),
                requirement_type=str(limitation.get("requirement_type") or limitation.get("iam_action_requirement") or "required"),
                evidence_categories=(action.split(":", maxsplit=1)[0],),
                requested_account_id=account_id,
                requested_region=region,
                remediation_permission=(action if outcome not in {"available", "expected_absence"} else None),
                related_findings_may_be_incomplete=(outcome not in {"available", "expected_absence"}),
            ),
        )
    return sort_degradation_records(records)


def sort_degradation_records(
    records: list[PermissionDegradationRecord] | tuple[PermissionDegradationRecord, ...],
) -> tuple[PermissionDegradationRecord, ...]:
    """Sort records by the stable canonical order."""
    return tuple(
        sorted(
            records,
            key=lambda item: (
                item.provider_id,
                item.account_id,
                item.region,
                item.scanner_id,
                item.api_action,
                item.evidence_category,
                item.outcome,
                item.record_id,
            ),
        ),
    )


def _optional_string(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        return ()
    return tuple(sorted({str(item) for item in value if str(item)}))


def _ledger_error_classification(
    raw: dict[str, Any],
    unio: dict[str, Any],
    action: str,
    outcome: str,
) -> str:
    if _is_kms_describe_key_access_denied(
        action=action,
        outcome=outcome,
        error_code=str(raw.get("errorCode") or ""),
    ):
        return KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN
    return str(unio.get("error_category") or "none")


def _iam_action_requirement(unio: dict[str, Any]) -> str:
    value = str(unio.get("iam_action_requirement") or "").strip().casefold()
    if value in {"conditional", "optional", "optional_enrichment"}:
        return "conditional"
    if value == "required":
        return "required"
    return "required"


def _exact_requirement_type(
    unio: dict[str, Any],
    *,
    scanner_id: str,
    api_action: str,
) -> str | None:
    explicit = str(unio.get("requirement_type") or "").strip()
    if explicit in {"required", "conditional", "optional_enrichment"}:
        return explicit
    observed = str(unio.get("iam_action_requirement") or "").strip()
    if observed == "required":
        return observed
    try:
        from unio_collector.scanners.registry.catalog import get_scanner  # noqa: PLC0415

        definition = get_scanner(scanner_id)
    except ValueError:
        return None
    values = {item.requirement_type for item in definition.iam_requirements or () if item.api_action == api_action}
    return values.pop() if len(values) == 1 else None


def _record_outcome(raw: dict[str, Any], unio: dict[str, Any]) -> str:
    if raw.get("errorCode") is None:
        return "available"
    error_code = str(raw.get("errorCode") or "")
    if unio.get("service_unavailable"):
        return "service_unavailable"
    if (
        unio.get("expected_absence")
        or str(unio.get("error_category") or "").lower() == "expected_absence"
        or aws_errors.is_expected_absence_error_code(error_code)
    ):
        return "expected_absence"
    if unio.get("permission_denied"):
        return "denied"
    error_category = str(unio.get("error_category") or "").lower()
    if error_category == "unsupported_operation":
        return "unsupported_operation"
    if error_category == "unsupported_region":
        return "unsupported_region"
    if error_category == "throttling":
        return "throttled"
    return "unknown"


def _collection_continued(raw: dict[str, Any], unio: dict[str, Any]) -> bool:
    if unio.get("collection_continued") is False:
        return False
    if (
        unio.get("interrupted")
        or unio.get("cancelled")
        or unio.get(
            "fatal",
        )
    ):
        return False
    text = " ".join(
        str(value or "")
        for value in (
            raw.get("errorCode"),
            raw.get("errorMessage"),
            unio.get("error_category"),
            unio.get("error_reason"),
        )
    ).casefold()
    return not any(marker in text for marker in ("interrupt", "cancelled", "canceled"))


def _scanner_continued(unio: dict[str, Any]) -> bool:
    return unio.get("scanner_continued") is not False


def _is_kms_describe_key_access_denied(
    *,
    action: str,
    outcome: str,
    error_code: str,
) -> bool:
    return outcome == "denied" and action.casefold() == "kms:describekey" and "accessdenied" in error_code.casefold()


def _client_explanation(outcome: str, action: str) -> str:
    if outcome == "available":
        return f"{action} was available during collection."
    if outcome == "denied":
        if action == "kms:DescribeKey":
            return (
                "kms:DescribeKey was denied. KMS key visibility may require both IAM "
                "allowance and key-policy, grant, ownership, or key-state access; "
                "AWS did not expose which control caused the denial."
            )
        return f"{action} was denied, so related evidence may be absent or incomplete."
    if outcome == "expected_absence":
        return f"{action} reported that the optional resource or configuration was absent."
    if outcome == "unsupported_operation":
        return f"{action} was not supported by the selected regional endpoint; other service evidence may still be available."
    return f"{action} did not provide complete evidence during collection."


def _action_from_ledger(raw: dict[str, Any]) -> str:
    source = str(raw.get("eventSource") or "unknown").split(".", maxsplit=1)[0]
    name = str(raw.get("eventName") or "unknown")
    return f"{source}:{name}"


def _legacy_action(limitation: dict[str, Any]) -> str:
    source = str(limitation.get("event_source") or limitation.get("service") or "unknown")
    name = str(limitation.get("event_name") or "unknown")
    if source.endswith(".amazonaws.com"):
        source = source.removesuffix(".amazonaws.com")
    return f"{source}:{name}"


def build_record_id(
    *,
    run_id: str | None,
    provider_id: str,
    account_id: str,
    region: str,
    scanner_id: str,
    api_action: str,
    evidence_category: str,
    outcome: str,
    occurrence_index: int,
) -> str:
    """Build the stable canonical degradation record ID."""
    raw = "|".join(
        (
            DEGRADATION_RECORD_SCHEMA_VERSION,
            run_id or "",
            provider_id,
            account_id,
            region,
            scanner_id,
            api_action,
            evidence_category,
            outcome,
            str(occurrence_index),
        ),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


__all__ = [
    "DEGRADATION_RECORD_SCHEMA_VERSION",
    "KMS_DESCRIBE_KEY_POLICY_SOURCE_UNKNOWN",
    "PermissionDegradationRecord",
    "build_degradation_records_from_ledger",
    "build_legacy_degradation_records",
    "build_record_id",
    "confidence_effect_for_outcome",
    "downstream_effect_for_outcome",
    "evidence_interpretation_for_outcome",
    "limitation_category_for_record",
    "limitation_category_for_values",
    "sort_degradation_records",
]
