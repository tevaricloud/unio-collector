"""Bounded collection and evidence-only account bundle commits."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from unio_collector.scan_workflow.organization.attempt.runner import OrganizationAccountAttemptRunner
from unio_collector.scan_workflow.organization.commit.bundle import OrganizationBundleCommitter
from unio_collector.scan_workflow.organization.commit.request import OrganizationBundleCommitRequest

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from unio_collector.scan_workflow.organization.attempt.context import OrganizationAccountAttemptContext
    from unio_collector.scan_workflow.organization.attempt.result import OrganizationAttemptResult
    from unio_collector.scan_workflow.organization.attempt.supervisor import OrganizationAttemptSupervisor
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult


class OrganizationCollectionAccountExecutor(OrganizationBundleCommitter):
    """Accept only collector outcomes while sharing attempt and commit authority."""

    def __init__(
        self,
        supervisor: OrganizationAttemptSupervisor,
        fixture_paths: dict[str, str],
        transition: Callable[[dict[str, Any], Path, Any, str, str, int], None],
        write_state: Callable[[Path, dict[str, Any], Any], None],
    ) -> None:
        """Retain common bounded-attempt and bundle-commit services."""
        super().__init__(write_state)
        self._attempt_runner = OrganizationAccountAttemptRunner(supervisor, fixture_paths, transition)

    def execute(self, context: OrganizationAccountAttemptContext) -> tuple[PerAccountBundleResult, dict[str, object]]:
        """Run collection and reject application output before bundle promotion."""

        def promote(child: OrganizationAttemptResult, attempt_root: Path, attempt: int) -> PerAccountBundleResult:
            if (
                child.bundle_purpose != "collector_evidence"
                or child.analysis_state != "not_analyzed"
                or child.report_relative_path is not None
                or child.report_failure_code is not None
                or child.finding_counts
            ):
                message = "Collector account attempt returned application output metadata."
                raise ValueError(message)
            request = OrganizationBundleCommitRequest(
                alias=context.account.alias,
                child_result=child,
                attempt_root=attempt_root,
                bundles_dir=context.bundles_dir,
                attempt=attempt,
                state=context.state,
                state_path=context.state_path,
                state_lock=context.state_lock,
            )
            committed = self.commit_bundle(request, completion_pending=False)
            return self.complete_bundle(request, committed.checkpoint_state, artifact_relative_path=None)[0]

        return self._attempt_runner.run(context, request_adapter=lambda request: request, promote=promote)
