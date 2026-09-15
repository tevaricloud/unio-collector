from __future__ import annotations  # noqa: D100

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

SUCCESSFUL_SCANNER_STATUSES = frozenset({"completed", "completed_with_warnings"})
LIMITED_SCANNER_STATUSES = frozenset(
    {"disabled", "failed", "permission_denied", "skipped", "unavailable"},
)


@dataclass(frozen=True)
class ScannerEvidenceCoverage:
    """Identity-based coverage contract for collected scanner evidence."""

    selected_scanner_ids: tuple[str, ...] = ()
    successful_scanner_ids: tuple[str, ...] = ()
    failed_scanner_ids: tuple[str, ...] = ()
    permission_denied_scanner_ids: tuple[str, ...] = ()
    disabled_scanner_ids: tuple[str, ...] = ()
    skipped_scanner_ids: tuple[str, ...] = ()
    unavailable_scanner_ids: tuple[str, ...] = ()
    scanner_evidence_payload_ids: tuple[str, ...] = ()
    duplicate_payload_ids: tuple[str, ...] = ()
    unknown_payload_ids: tuple[str, ...] = ()
    unexpected_payload_ids: tuple[str, ...] = ()
    missing_payload_ids: tuple[str, ...] = ()
    malformed_payload_indexes: tuple[int, ...] = ()
    unserialized_payload_ids: tuple[str, ...] = ()
    provider_mismatch_payload_ids: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def complete(self) -> bool:
        """Return whether every successful scanner has one valid payload."""
        return bool(self.successful_scanner_ids) and not self.validation_errors

    @property
    def collection_status(self) -> str:
        """Return a machine-readable collection outcome."""
        if not self.successful_scanner_ids:
            return "failed"
        if any(
            (
                self.failed_scanner_ids,
                self.permission_denied_scanner_ids,
                self.disabled_scanner_ids,
                self.skipped_scanner_ids,
                self.unavailable_scanner_ids,
                self.validation_errors,
            ),
        ):
            return "degraded"
        return "complete"

    def convert_to_dict(self) -> dict[str, Any]:
        """Return deterministic machine-readable coverage metadata."""
        return {
            "status": "complete" if self.complete else "incomplete",
            "collection_status": self.collection_status,
            "selected_scanner_ids": list(self.selected_scanner_ids),
            "successful_scanner_ids": list(self.successful_scanner_ids),
            "failed_scanner_ids": list(self.failed_scanner_ids),
            "permission_denied_scanner_ids": list(
                self.permission_denied_scanner_ids,
            ),
            "disabled_scanner_ids": list(self.disabled_scanner_ids),
            "skipped_scanner_ids": list(self.skipped_scanner_ids),
            "unavailable_scanner_ids": list(self.unavailable_scanner_ids),
            "scanner_evidence_payload_ids": list(self.scanner_evidence_payload_ids),
            "duplicate_payload_ids": list(self.duplicate_payload_ids),
            "unknown_payload_ids": list(self.unknown_payload_ids),
            "unexpected_payload_ids": list(self.unexpected_payload_ids),
            "missing_payload_ids": list(self.missing_payload_ids),
            "malformed_payload_indexes": list(self.malformed_payload_indexes),
            "unserialized_payload_ids": list(self.unserialized_payload_ids),
            "provider_mismatch_payload_ids": list(
                self.provider_mismatch_payload_ids,
            ),
            "validation_errors": list(self.validation_errors),
        }

    @classmethod
    def assess(  # noqa: C901
        cls,
        *,
        scanner_results: object,
        scanner_evidence_payloads: object,
        provider_id: str | None = None,
    ) -> ScannerEvidenceCoverage:
        """Build exact scanner-result to payload coverage."""
        errors: list[str] = []
        result_statuses: dict[str, str] = {}
        if not isinstance(scanner_results, list):
            errors.append("Scanner results must be a list.")
            scanner_results = []
        for item in scanner_results:
            if not isinstance(item, dict):
                errors.append("Scanner results contain a malformed record.")
                continue
            scanner_id = item.get("scanner_id")
            status = item.get("status")
            if not isinstance(scanner_id, str) or not scanner_id.strip():
                errors.append("Scanner results contain an invalid scanner ID.")
                continue
            if scanner_id in result_statuses:
                errors.append("Scanner results contain duplicate scanner IDs.")
                continue
            if not isinstance(status, str) or status not in SUCCESSFUL_SCANNER_STATUSES | LIMITED_SCANNER_STATUSES:
                errors.append("Scanner results contain an unsupported status.")
                result_statuses[scanner_id] = "unavailable"
                continue
            result_statuses[scanner_id] = status
        selected = set(result_statuses)
        successful = {scanner_id for scanner_id, status in result_statuses.items() if status in SUCCESSFUL_SCANNER_STATUSES}
        payload_ids: list[str] = []
        malformed_indexes: list[int] = []
        unserialized: set[str] = set()
        provider_mismatches: set[str] = set()
        if not isinstance(scanner_evidence_payloads, list):
            errors.append("Scanner evidence payloads must be a list.")
            scanner_evidence_payloads = []
        for index, payload in enumerate(scanner_evidence_payloads):
            if not isinstance(payload, dict):
                malformed_indexes.append(index)
                continue
            scanner_id = payload.get("scanner_id")
            if not isinstance(scanner_id, str) or not scanner_id.strip():
                malformed_indexes.append(index)
                continue
            payload_ids.append(scanner_id)
            if payload.get("serialization_status") != "serialized":
                unserialized.add(scanner_id)
            payload_provider = payload.get("provider_id")
            if payload_provider is not None and (not isinstance(payload_provider, str) or not payload_provider.strip()):
                malformed_indexes.append(index)
                continue
            if provider_id and payload_provider and payload_provider != provider_id:
                provider_mismatches.add(scanner_id)
        payload_id_set = set(payload_ids)
        duplicates = {scanner_id for scanner_id, count in Counter(payload_ids).items() if count > 1}
        unknown = payload_id_set - selected
        unexpected = payload_id_set - successful
        missing = successful - payload_id_set
        if malformed_indexes:
            errors.append("Scanner evidence contains malformed payload records or identities.")
        if duplicates:
            errors.append("Scanner evidence contains duplicate scanner IDs.")
        if unknown:
            errors.append("Scanner evidence contains unknown scanner IDs.")
        if unexpected:
            errors.append("Scanner evidence exists for scanners that did not complete successfully.")
        if missing:
            errors.append("Successful scanners are missing scanner-evidence payloads.")
        if unserialized:
            errors.append("Scanner evidence contains payloads that were not safely serialized.")
        if provider_mismatches:
            errors.append("Scanner evidence contains payloads owned by another provider.")
        return cls(
            selected_scanner_ids=tuple(sorted(selected)),
            successful_scanner_ids=tuple(sorted(successful)),
            failed_scanner_ids=_ids_with_status(result_statuses, "failed"),
            permission_denied_scanner_ids=_ids_with_status(
                result_statuses,
                "permission_denied",
            ),
            disabled_scanner_ids=_ids_with_status(result_statuses, "disabled"),
            skipped_scanner_ids=_ids_with_status(result_statuses, "skipped"),
            unavailable_scanner_ids=_ids_with_status(
                result_statuses,
                "unavailable",
            ),
            scanner_evidence_payload_ids=tuple(sorted(payload_id_set)),
            duplicate_payload_ids=tuple(sorted(duplicates)),
            unknown_payload_ids=tuple(sorted(unknown)),
            unexpected_payload_ids=tuple(sorted(unexpected)),
            missing_payload_ids=tuple(sorted(missing)),
            malformed_payload_indexes=tuple(malformed_indexes),
            unserialized_payload_ids=tuple(sorted(unserialized)),
            provider_mismatch_payload_ids=tuple(sorted(provider_mismatches)),
            validation_errors=tuple(errors),
        )


def _ids_with_status(
    result_statuses: dict[str, str],
    status: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(scanner_id for scanner_id, scanner_status in result_statuses.items() if scanner_status == status),
    )
