from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING

from unio_collector.aws.cache import AwsScanCacheAccessPolicy
from unio_collector.scan_workflow.evidence.cache_policy import (
    AwsEvidenceCacheFailureClassifier,
)
from unio_collector.scan_workflow.scanner.runtime.cancellation_error import (
    ScannerDeadlineExceededError,
)

if TYPE_CHECKING:
    from unio_collector.scan_workflow.evidence.runtime import ScannerEvidenceRuntime
    from unio_collector.scanners.scanner.definition import ScannerDefinition


class EvidenceCollectionBase:
    """Shared state and cache-note helpers for evidence collection domains."""

    def __init__(self, runner: ScannerEvidenceRuntime) -> None:  # noqa: D107
        self.runner = runner
        self._cache_note_keys: set[tuple[str, str, str]] = set()

    def add_cached_evidence_note(  # noqa: D102
        self,
        definition: ScannerDefinition,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        self.raise_if_deadline_expired(
            definition.scanner_id,
            label=label,
            namespace=namespace,
        )
        self.add_cached_evidence_note_for_scanner(
            definition.scanner_id,
            namespace=namespace,
            label=label,
            access_status=access_status,
        )

    def add_cached_evidence_note_for_scanner(  # noqa: D102
        self,
        scanner_id: str,
        *,
        namespace: str,
        label: str,
        access_status: str,
    ) -> None:
        if access_status == "loaded":
            return
        note_key = (scanner_id, namespace, label)
        if note_key in self._cache_note_keys:
            return
        self._cache_note_keys.add(note_key)
        action = "waited for" if access_status == "waited" else "reused"
        self.runner.add_scanner_coverage_note(
            scanner_id,
            {
                "note_type": "cached_evidence_reuse",
                "cache_label": label,
                "summary": (f"{label} {action} same-scan cached evidence; a duplicate AWS API collection was skipped."),
                "cache_namespace": namespace,
                "cache_access_status": access_status,
                "cache_action": action,
                "result_scope": "same_scan",
                "impact": ("The scanner still ran against evidence collected during this scan. No previous scan results were used."),
            },
        )

    def raise_if_deadline_expired(
        self,
        scanner_id: str,
        *,
        label: str,
        namespace: str,
    ) -> None:
        """Stop new evidence work when a scanner deadline has expired."""
        token = self.runner.cancellation_token
        if not token.is_cancelled():
            return
        summary = f"{label} was not collected because the scanner deadline expired."
        self.runner.add_scanner_coverage_note(
            scanner_id,
            {
                "note_type": "scanner_deadline_limited_evidence",
                "cache_label": label,
                "cache_namespace": namespace,
                "summary": summary,
                "result_scope": "current_scan",
                "impact": ("Evidence for this scanner is incomplete because new AWS API collection was stopped at the configured scanner timeout."),
            },
        )
        raise ScannerDeadlineExceededError(summary)

    def ensure_can_start_evidence_collection(
        self,
        definition: ScannerDefinition,
        *,
        namespace: str,
        label: str,
    ) -> None:
        """Check the scanner deadline before starting new evidence work."""
        self.raise_if_deadline_expired(
            definition.scanner_id,
            namespace=namespace,
            label=label,
        )

    def build_cache_access_policy(
        self,
        *,
        consumer_id: str,
    ) -> AwsScanCacheAccessPolicy:
        """Build bounded cache policy from the active scanner attempt."""
        attempt = self.runner.active_attempt
        token = self.runner.cancellation_token
        return AwsScanCacheAccessPolicy(
            cancellation_token=token,
            deadline_monotonic=(attempt.deadline_monotonic if attempt is not None else getattr(token, "deadline_perf", None)),
            consumer_id=consumer_id,
            attempt_id=attempt.attempt_id if attempt is not None else None,
            failure_classifier=AwsEvidenceCacheFailureClassifier(),
        )
