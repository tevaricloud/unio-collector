from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.collector.analysis.coverage import ScannerEvidenceCoverage
from unio_collector.collector.analysis.readiness import (
    STRICT_ANALYSIS_READINESS_FILE,
    STRICT_ANALYSIS_REQUIRED_PAYLOAD_FILE,
)
from unio_collector.collector.bundle.encoding import load_json_object
from unio_collector.collector.evidence.scanner.payload import (
    SCANNER_EVIDENCE_PAYLOAD_FILE,
)

if TYPE_CHECKING:
    from zipfile import ZipFile


class StrictAnalysisReadinessValidator:  # noqa: D101
    def validate(  # noqa: D102
        self,
        archive: ZipFile,
        manifest: dict[str, object],
        collection_summary: dict[str, object],
        scanner_evidence_payload: dict[str, object],
        errors: list[str],
    ) -> None:
        if STRICT_ANALYSIS_READINESS_FILE not in archive.namelist():
            return
        payload = _read_json(archive, errors)
        if not payload:
            return
        _validate_schema(payload, manifest, errors)
        _validate_replay_fields(payload, scanner_evidence_payload, errors)
        _validate_counts(payload, collection_summary, errors)
        if manifest.get("bundle_purpose") == "collector_evidence":
            scanner_results_payload = _read_named_json(
                archive,
                "scan-result/scanner-results.json",
                errors,
            )
            raw_results = scanner_results_payload.get("scanner_results", [])
            raw_evidence = scanner_evidence_payload.get("scanner_evidence", [])
            coverage = ScannerEvidenceCoverage.assess(
                scanner_results=raw_results,
                scanner_evidence_payloads=raw_evidence,
            )
            errors.extend(f"Collector scanner-evidence coverage is invalid: {message}" for message in coverage.validation_errors)
            if not coverage.complete and any(
                payload.get(key) is True for key in ("scanner_evidence_payloads_serialized", "full_report_rebuild_from_scanner_evidence_supported")
            ):
                errors.append("analysis-readiness.json claims complete replay evidence without complete successful scanner coverage.")


def _validate_schema(
    payload: dict[str, object],
    manifest: dict[str, object],
    errors: list[str],
) -> None:
    if payload.get("bundle_schema_version") != manifest.get(
        "bundle_schema_version",
    ):
        errors.append(
            "analysis-readiness.json bundle_schema_version does not match manifest.json.",
        )
    expected_source = "scanner_evidence" if manifest.get("bundle_purpose") == "collector_evidence" else "completed_report_bundle"
    if payload.get("active_analysis_source") != expected_source:
        errors.append(
            f"analysis-readiness.json active_analysis_source must be '{expected_source}'.",
        )


def _read_named_json(
    archive: ZipFile,
    name: str,
    errors: list[str],
) -> dict[str, object]:
    try:
        value = load_json_object(archive.read(name).decode("utf-8"))
    except Exception:  # noqa: BLE001
        errors.append(f"{name} must contain a valid non-empty JSON object.")
        return {}
    if isinstance(value, dict):
        return value
    errors.append(f"{name} must contain a JSON object.")
    return {}


def _validate_replay_fields(
    payload: dict[str, object],
    scanner_evidence_payload: dict[str, object],
    errors: list[str],
) -> None:
    _require_bool(payload, "strict_scanner_analyzer_replay_supported", errors)
    _require_bool(
        payload,
        "full_report_rebuild_from_scanner_evidence_supported",
        errors,
    )
    _require_bool(payload, "scanner_evidence_payloads_serialized", errors)
    _validate_payload_file_fields(payload, scanner_evidence_payload, errors)
    _validate_required_rebuild_files(payload, errors)
    rebuild_supported = payload.get(
        "full_report_rebuild_from_scanner_evidence_supported",
    )
    reason = payload.get("deferred_reason")
    if rebuild_supported is False and (not isinstance(reason, str) or not reason.strip()):
        errors.append(
            "analysis-readiness.json deferred_reason must be a non-empty string when full report rebuild is unsupported.",
        )


def _validate_required_rebuild_files(
    payload: dict[str, object],
    errors: list[str],
) -> None:
    required = payload.get("required_for_full_report_rebuild")
    rebuild_supported = payload.get(
        "full_report_rebuild_from_scanner_evidence_supported",
    )
    if not isinstance(required, list):
        errors.append(
            "analysis-readiness.json required_for_full_report_rebuild must be a list.",
        )
    elif rebuild_supported is False and not required:
        errors.append(
            "analysis-readiness.json required_for_full_report_rebuild must be non-empty when full report rebuild is unsupported.",
        )
    elif any(not isinstance(item, str) or not item for item in required):
        errors.append(
            "analysis-readiness.json required_for_full_report_rebuild entries must be non-empty strings.",
        )


def _validate_payload_file_fields(
    payload: dict[str, object],
    scanner_evidence_payload: dict[str, object],
    errors: list[str],
) -> None:
    payload_file = payload.get("scanner_evidence_payload_file")
    if payload_file != STRICT_ANALYSIS_REQUIRED_PAYLOAD_FILE:
        errors.append(
            f"analysis-readiness.json scanner_evidence_payload_file must be {STRICT_ANALYSIS_REQUIRED_PAYLOAD_FILE}.",
        )
    serialized = payload.get("scanner_evidence_payloads_serialized")
    if serialized is True and not scanner_evidence_payload:
        errors.append(
            f"analysis-readiness.json claims scanner evidence payloads are serialized but {SCANNER_EVIDENCE_PAYLOAD_FILE} is missing.",
        )
    count = payload.get("scanner_evidence_payload_count")
    if type(count) is not int or count < 0:
        errors.append(
            "analysis-readiness.json scanner_evidence_payload_count must be a non-negative integer.",
        )
    records = scanner_evidence_payload.get("scanner_evidence")
    if isinstance(records, list) and count != len(records):
        errors.append(
            "analysis-readiness.json scanner_evidence_payload_count does not match scan-result/scanner-evidence.json.",
        )
    missing = payload.get("missing_scanner_evidence_payload_ids")
    if not isinstance(missing, list):
        errors.append(
            "analysis-readiness.json missing_scanner_evidence_payload_ids must be a list.",
        )


def _validate_counts(
    payload: dict[str, object],
    collection_summary: dict[str, object],
    errors: list[str],
) -> None:
    boundary = collection_summary.get("scanner_analysis_boundary_summary")
    if not isinstance(boundary, dict):
        return
    for key in (
        "scanner_count",
        "strict_evidence_only_ready_count",
        "result_bundle_only_count",
    ):
        _validate_matching_count(payload, boundary, key, errors)
    _validate_deferred_scanner_ids(payload, boundary, errors)


def _validate_deferred_scanner_ids(
    payload: dict[str, object],
    boundary: dict[str, object],
    errors: list[str],
) -> None:
    value = payload.get("deferred_scanner_ids")
    if not isinstance(value, list):
        errors.append("analysis-readiness.json deferred_scanner_ids must be a list.")
        return
    if any(not isinstance(item, str) or not item for item in value):
        errors.append(
            "analysis-readiness.json deferred_scanner_ids entries must be non-empty strings.",
        )
    boundary_ids = boundary.get("deferred_scanner_ids")
    if isinstance(boundary_ids, list) and value != boundary_ids:
        errors.append(
            "analysis-readiness.json deferred_scanner_ids do not match collection-summary.json scanner_analysis_boundary_summary.",
        )


def _require_bool(
    payload: dict[str, object],
    key: str,
    errors: list[str],
) -> None:
    if not isinstance(payload.get(key), bool):
        errors.append(f"analysis-readiness.json {key} must be a boolean.")


def _validate_matching_count(
    payload: dict[str, object],
    boundary: dict[str, object],
    key: str,
    errors: list[str],
) -> None:
    value = payload.get(key)
    if type(value) is not int or value < 0:
        errors.append(
            f"analysis-readiness.json {key} must be a non-negative integer.",
        )
        return
    if value != boundary.get(key):
        errors.append(
            f"analysis-readiness.json {key} does not match collection-summary.json scanner_analysis_boundary_summary.",
        )


def _read_json(archive: ZipFile, errors: list[str]) -> dict[str, object]:
    try:
        value = archive.read(STRICT_ANALYSIS_READINESS_FILE).decode("utf-8")
        payload = load_json_object(value)
    except Exception:  # noqa: BLE001
        errors.append(f"{STRICT_ANALYSIS_READINESS_FILE} must contain a valid non-empty JSON object.")
        return {}
    if isinstance(payload, dict):
        return payload
    errors.append(f"{STRICT_ANALYSIS_READINESS_FILE} must contain a JSON object.")
    return {}
