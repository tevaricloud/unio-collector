"""Authoritative organization evidence-bundle promotion and checkpoint commits."""

from __future__ import annotations

# ruff: noqa: ANN401, EM101, FBT001, TRY003
from typing import TYPE_CHECKING, Any

from unio_collector.collector.bundle.checksums import build_sha256
from unio_collector.collector.bundle.validator import EvidenceBundleValidator
from unio_collector.scan_workflow.organization.commit.error import OrganizationAccountReportError
from unio_collector.scan_workflow.organization.commit.result import CommittedAccountBundle
from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from unio_collector.scan_workflow.organization.commit.request import OrganizationBundleCommitRequest


class OrganizationBundleCommitter:
    """Validate and promote evidence while retaining parent generation authority."""

    def __init__(self, write_state: Callable[[Path, dict[str, Any], Any], None]) -> None:
        """Retain the parent checkpoint writer."""
        self._write_state = write_state

    def commit_bundle(
        self,
        request: OrganizationBundleCommitRequest,
        *,
        completion_pending: bool,
    ) -> CommittedAccountBundle:
        """Commit the checksum-validated bundle before any optional completion work."""
        alias = request.alias
        child_result = request.child_result
        attempt_root = request.attempt_root
        bundles_dir = request.bundles_dir
        attempt = request.attempt
        state = request.state
        state_path = request.state_path
        state_lock = request.state_lock
        staged_bundle = attempt_root / "evidence-bundle.zip"
        validation = EvidenceBundleValidator().validate(staged_bundle)
        if not validation.passed:
            raise ValueError("Attempt child produced an invalid evidence bundle: " + "; ".join(validation.errors))
        if build_sha256(staged_bundle.read_bytes()) != child_result.bundle_sha256:
            raise ValueError("Attempt child bundle checksum changed before promotion.")
        base_state = {
            "status": "bundle_commit_pending",
            "stage": "bundle_promotion",
            "attempts": attempt,
            "commit_generation": attempt_root.name,
            "bundle_state": "pending",
            "bundle_sha256": child_result.bundle_sha256,
            "bundle_schema_version": child_result.bundle_schema_version,
            "bundle_purpose": child_result.bundle_purpose,
            "analysis": child_result.analysis_state,
            "degraded": bool(child_result.degraded),
            "report_state": ("pending" if completion_pending else "not_required"),
            "report_path": None,
        }
        self._store_account_state(alias, base_state, attempt, state, state_path, state_lock)
        bundle_path = bundles_dir / f"{alias}.zip"
        staged_bundle.replace(bundle_path)
        canonical = EvidenceBundleValidator().validate(bundle_path)
        if not canonical.passed or build_sha256(bundle_path.read_bytes()) != child_result.bundle_sha256:
            raise ValueError("Promoted evidence bundle failed authoritative validation.")
        bundle_result = self.bundle_result(
            alias,
            child_result.bundle_sha256,
            child_result.degraded,
            schema_version=child_result.bundle_schema_version,
            bundle_purpose=child_result.bundle_purpose,
            finding_counts=child_result.finding_counts,
        )
        committed_state = {
            **base_state,
            "status": "bundle_committed",
            "stage": "account_report",
            "bundle_state": "committed",
        }
        try:
            self._store_account_state(alias, committed_state, attempt, state, state_path, state_lock)
        except Exception as exc:
            raise OrganizationAccountReportError(
                bundle_result,
                child_result.role_audit,
                "bundle_checkpoint_write_failed",
            ) from exc
        return CommittedAccountBundle(bundle_result, committed_state)

    def complete_bundle(
        self,
        request: OrganizationBundleCommitRequest,
        committed_state: dict[str, Any],
        *,
        artifact_relative_path: str | None,
    ) -> tuple[PerAccountBundleResult, str | None]:
        """Persist final authority using the existing checkpoint wire fields."""
        alias = request.alias
        child_result = request.child_result
        attempt = request.attempt
        state = request.state
        state_path = request.state_path
        state_lock = request.state_lock
        report_path = artifact_relative_path
        completed_state = {
            **committed_state,
            "status": "degraded" if child_result.degraded else "completed",
            "stage": "committed",
            "report_state": "completed" if report_path else "not_required",
            "report_path": report_path,
        }
        try:
            self._store_account_state(alias, completed_state, attempt, state, state_path, state_lock)
        except Exception as exc:
            raise OrganizationAccountReportError(
                self.bundle_result(
                    alias,
                    child_result.bundle_sha256,
                    child_result.degraded,
                    schema_version=child_result.bundle_schema_version,
                    bundle_purpose=child_result.bundle_purpose,
                    report_path=report_path,
                    finding_counts=child_result.finding_counts,
                ),
                child_result.role_audit,
                "account_checkpoint_finalization_failed",
            ) from exc
        return self.bundle_result(
            alias,
            child_result.bundle_sha256,
            child_result.degraded,
            schema_version=child_result.bundle_schema_version,
            bundle_purpose=child_result.bundle_purpose,
            report_path=report_path,
            finding_counts=child_result.finding_counts,
        ), report_path

    def _store_account_state(
        self,
        alias: str,
        account_state: dict[str, Any],
        attempt: int,
        state: dict[str, Any],
        state_path: Path,
        state_lock: Any,
    ) -> None:
        """Write one generation without allowing stale attempts to downgrade it."""
        with state_lock:
            existing = state["accounts"].get(alias, {})
            if int(existing.get("attempts", 0)) > attempt:
                raise RuntimeError("A stale organization attempt cannot replace a later result.")
            state["accounts"][alias] = dict(account_state)
        self._write_state(state_path, state, state_lock)

    def bundle_result(
        self,
        alias: str,
        digest: str,
        degraded: bool,
        *,
        schema_version: str = "2026-02",
        bundle_purpose: str = "collector_evidence",
        report_path: str | None = None,
        finding_counts: dict[str, int] | None = None,
    ) -> PerAccountBundleResult:
        """Build the stable envelope-facing account result."""
        return PerAccountBundleResult(
            account_reference=alias,
            bundle_path=f"accounts/{alias}/evidence-bundle.zip",
            bundle_sha256=digest,
            bundle_schema_version=schema_version,
            bundle_purpose=bundle_purpose,
            protection_status="unprotected",
            report_path=report_path,
            finding_counts=finding_counts or {},
            limitations=(("One or more scanners completed with limitations.",) if degraded else ()),
        )
