"""Shared account attempt deadlines, retry bounds and parent transitions."""

from __future__ import annotations

# ruff: noqa: BLE001, EM102, S101, TRY003, TRY300, TRY301
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.scan_workflow.organization.attempt.request import OrganizationAttemptRequest
from unio_collector.scan_workflow.organization.attempt.timeout_error import OrganizationAttemptTimeoutError

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.scan_workflow.organization.attempt.context import OrganizationAccountAttemptContext
    from unio_collector.scan_workflow.organization.attempt.result import OrganizationAttemptResult
    from unio_collector.scan_workflow.organization.attempt.supervisor import OrganizationAttemptSupervisor
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult


class OrganizationAccountAttemptRunner:
    """Run one account under the existing deadline and chargeable-retry policy."""

    def __init__(
        self,
        supervisor: OrganizationAttemptSupervisor,
        fixture_paths: dict[str, str],
        transition: Callable[[dict[str, Any], Path, Any, str, str, int], None],
    ) -> None:
        """Retain the parent supervisor and checkpoint transition authority."""
        self._supervisor = supervisor
        self._fixture_paths = fixture_paths
        self._transition = transition

    def run(
        self,
        context: OrganizationAccountAttemptContext,
        *,
        request_adapter: Callable[[OrganizationAttemptRequest[object]], OrganizationAttemptRequest[object]],
        promote: Callable[[OrganizationAttemptResult, Path, int], PerAccountBundleResult],
    ) -> tuple[PerAccountBundleResult, dict[str, object]]:
        """Return only the result accepted by the parent promotion operation."""
        account = context.account
        management_session = context.management_session
        organization_config = context.organization_config
        scan_config = context.scan_config
        scanner_selection = context.scanner_selection
        staging_dir = context.staging_dir
        minimisation = context.minimisation
        run_id = context.run_id
        state = context.state
        state_path = context.state_path
        state_lock = context.state_lock
        last_error: Exception | None = None
        account_started = time.monotonic()
        for attempt in range(1, organization_config.execution.max_attempts + 1):
            self._transition(state, state_path, state_lock, account.alias, "assuming_role", attempt)
            try:
                self._transition(state, state_path, state_lock, account.alias, "collecting", attempt)
                fixture_value = self._fixture_paths.get(account.alias) if management_session is None else None
                if management_session is None and not fixture_value:
                    raise ValueError(f"Synthetic account {account.alias} has no collection_fixture.")
                attempt_root = staging_dir / account.alias / f"{attempt}-{uuid.uuid4().hex}"
                remaining_seconds = organization_config.execution.account_timeout_seconds - (time.monotonic() - account_started)
                if remaining_seconds <= 0:
                    message = "Organization account execution exceeded its configured deadline."
                    raise OrganizationAttemptTimeoutError(message)
                child_result = self._supervisor.run(
                    request_adapter(
                        OrganizationAttemptRequest(
                            account=account,
                            organization_config=organization_config,
                            scan_config=scan_config,
                            scanner_selection=scanner_selection,
                            staging_root=attempt_root,
                            run_id=run_id,
                            attempt=attempt,
                            fixture_path=Path(fixture_value) if fixture_value else None,
                            minimisation=minimisation,
                        )
                    ),
                    timeout_seconds=remaining_seconds,
                    cancellation_grace_seconds=organization_config.execution.cancellation_grace_seconds,
                )
                bundle_result = promote(child_result, attempt_root, attempt)
                return bundle_result, child_result.role_audit
            except Exception as exc:
                last_error = exc
                chargeable_retry_blocked = bool(getattr(scan_config, "allow_chargeable_scanners", False)) and not (
                    organization_config.authorization.allow_chargeable_retry
                )
                if chargeable_retry_blocked or not aws_errors.is_retryable_error(exc) or attempt >= organization_config.execution.max_attempts:
                    break
                remaining_seconds = organization_config.execution.account_timeout_seconds - (time.monotonic() - account_started)
                backoff_seconds = organization_config.execution.retry_backoff_seconds * attempt
                if remaining_seconds <= backoff_seconds:
                    last_error = OrganizationAttemptTimeoutError(
                        "Organization account retry budget exhausted its configured deadline.",
                    )
                    break
                time.sleep(backoff_seconds)
        assert last_error is not None
        raise last_error
