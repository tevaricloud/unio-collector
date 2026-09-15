"""Bounded organization account scheduling without application report execution."""

from __future__ import annotations

# ruff: noqa: BLE001
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import TYPE_CHECKING

from unio_collector.providers.aws.organization.role import AwsOrganizationRoleAssumer
from unio_collector.scan_workflow.organization.commit.error import OrganizationAccountReportError
from unio_collector.scan_workflow.organization.failure import build_account_failure
from unio_collector.scan_workflow.organization.partition import arn_partition

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from unio_collector.scan_workflow.organization.attempt.supervisor import OrganizationAttemptSupervisor
    from unio_collector.scan_workflow.organization.checkpoint_store import OrganizationCheckpointStore
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult
    from unio_collector.scan_workflow.organization.run.context import OrganizationScheduleContext


class OrganizationAccountScheduler:
    """Collect parent-accepted outcomes under unchanged concurrency and cancellation bounds."""

    def __init__(self, supervisor: OrganizationAttemptSupervisor, checkpoint: OrganizationCheckpointStore) -> None:
        """Retain the shared attempt supervisor and checkpoint writer."""
        self._attempt_supervisor = supervisor
        self._checkpoint = checkpoint

    def run(
        self,
        context: OrganizationScheduleContext,
        execute: Callable[[AccountIdentity], tuple[PerAccountBundleResult, dict[str, object]]],
    ) -> None:
        """Schedule account operations and retain authoritative partial results."""
        pending = context.pending
        organization_config = context.organization_config
        bundles_dir = context.bundles_dir
        state = context.state
        state_path = context.state_path
        state_lock = context.state_lock
        results = context.results
        children = results.children
        bundle_results = results.bundle_results
        failures = results.failures
        audits = results.audits
        executor = ThreadPoolExecutor(
            max_workers=organization_config.execution.max_concurrency,
            thread_name_prefix="unio-collector-org-account",
        )
        active: dict[Future[tuple[PerAccountBundleResult, dict[str, object]]], AccountIdentity] = {}
        cancelled = False
        try:
            iterator = iter(pending)
            self._fill(active, iterator, executor, execute, organization_config.execution.max_concurrency)
            while active:
                done, _ = wait(active, return_when=FIRST_COMPLETED, timeout=1)
                if not done:
                    continue
                for future in done:
                    account = active.pop(future)
                    alias = account.alias
                    try:
                        result, audit = future.result()
                        bundle_results[alias] = result
                        children[alias] = bundles_dir / f"{alias}.zip"
                        audits.append(audit)
                    except Exception as exc:
                        if isinstance(exc, OrganizationAccountReportError):
                            bundle_results[alias] = exc.bundle_result
                            children[alias] = bundles_dir / f"{alias}.zip"
                            audits.append(exc.role_audit)
                        attempts = int(
                            state["accounts"].get(alias, {}).get("attempts", 1),
                        )
                        failure = build_account_failure(alias, exc, attempts)
                        failures[alias] = failure
                        audits.append(
                            {
                                "account_reference": alias,
                                "role_arn": AwsOrganizationRoleAssumer().render_role_arn(
                                    organization_config.audit_role,
                                    account.account_id,
                                    arn_partition(account.arn),
                                ),
                                "duration_seconds": organization_config.audit_role.duration_seconds,
                                "external_id_present": organization_config.audit_role.external_id is not None,
                                "external_id_source_kind": (
                                    "environment_variable"
                                    if organization_config.audit_role.external_id and organization_config.audit_role.external_id.environment_variable
                                    else "file"
                                    if organization_config.audit_role.external_id
                                    else None
                                ),
                                "request_id": None,
                                "outcome": "failed",
                                "failure_category": failure.category,
                            },
                        )
                        with state_lock:
                            existing = state["accounts"].get(alias, {})
                            retained = existing if existing.get("bundle_state") == "committed" or existing.get("status") == "bundle_committed" else {}
                            state["accounts"][alias] = {
                                **retained,
                                "status": ("bundle_committed" if isinstance(exc, OrganizationAccountReportError) else "failed"),
                                "stage": failure.stage,
                                "code": failure.code,
                                "category": failure.category,
                                "retryable": failure.retryable,
                                "attempts": failure.attempts,
                            }
                        self._checkpoint.write(state_path, state, state_lock)
                    self._fill(active, iterator, executor, execute, organization_config.execution.max_concurrency)
        except KeyboardInterrupt:
            cancelled = True
            self._attempt_supervisor.cancel_all(
                cancellation_grace_seconds=organization_config.execution.cancellation_grace_seconds,
            )
            wait(
                active,
                timeout=organization_config.execution.cancellation_grace_seconds,
            )
            with state_lock:
                for account in active.values():
                    state["accounts"][account.alias] = {
                        "status": "cancelled",
                        "stage": "cancelled",
                        "retryable": True,
                        "attempts": int(state["accounts"].get(account.alias, {}).get("attempts", 1)),
                    }
            self._checkpoint.write(state_path, state, state_lock)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        results.cancelled = cancelled
        results.cancelled_count = len(active) if cancelled else 0

    def _fill(
        self,
        active: dict[Future[tuple[PerAccountBundleResult, dict[str, object]]], AccountIdentity],
        iterator: Iterator[AccountIdentity],
        executor: ThreadPoolExecutor,
        execute: Callable[[AccountIdentity], tuple[PerAccountBundleResult, dict[str, object]]],
        max_concurrency: int,
    ) -> None:
        while len(active) < max_concurrency:
            try:
                account = next(iterator)
            except StopIteration:
                return
            active[executor.submit(execute, account)] = account
