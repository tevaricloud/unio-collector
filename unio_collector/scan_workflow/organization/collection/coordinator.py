"""Organization evidence collection with no application report lifecycle."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from unio_collector.scan_workflow.organization.attempt.context import OrganizationAccountAttemptContext
from unio_collector.scan_workflow.organization.attempt.supervisor import OrganizationAttemptSupervisor
from unio_collector.scan_workflow.organization.checkpoint_store import OrganizationCheckpointStore
from unio_collector.scan_workflow.organization.collection.account import OrganizationCollectionAccountExecutor
from unio_collector.scan_workflow.organization.model.failure import AccountFailure
from unio_collector.scan_workflow.organization.request.fingerprint import OrganizationRequestFingerprint
from unio_collector.scan_workflow.organization.run.context import OrganizationScheduleContext
from unio_collector.scan_workflow.organization.run.envelope import OrganizationEnvelopeAssembler
from unio_collector.scan_workflow.organization.run.envelope_context import OrganizationEnvelopeContext
from unio_collector.scan_workflow.organization.run.results import OrganizationRunResults
from unio_collector.scan_workflow.organization.run.resume import OrganizationBundleResumer
from unio_collector.scan_workflow.organization.run.scheduler import OrganizationAccountScheduler
from unio_collector.scan_workflow.organization.run_identity import organization_run_id

if TYPE_CHECKING:
    from pathlib import Path

    from unio_collector.aws.audited.session import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.collector.minimisation import EvidenceMinimisationOptions
    from unio_collector.config.organization import AwsOrganizationConfig
    from unio_collector.providers.aws.organization.discovery_result import OrganizationDiscoveryResult
    from unio_collector.scan_workflow.organization.model.account import AccountIdentity
    from unio_collector.scan_workflow.organization.model.bundle import PerAccountBundleResult
    from unio_collector.scan_workflow.organization.model.coverage import ConsolidatedCoverageSummary
    from unio_collector.scanners.selection import ScannerSelection


class OrganizationCollectionCoordinator:
    """Collect selected accounts under unchanged resume, attempt and envelope rules."""

    def __init__(self, *, attempt_supervisor: OrganizationAttemptSupervisor | None = None) -> None:
        """Create the collector-default spawned attempt supervisor."""
        self._attempt_supervisor = attempt_supervisor or OrganizationAttemptSupervisor()

    def collect(
        self,
        *,
        management_session: AuditedAwsSession | None,
        discovery: OrganizationDiscoveryResult,
        organization_config: AwsOrganizationConfig,
        scan_config: CollectionConfigProtocol,
        scanner_selection: ScannerSelection,
        output: Path,
        minimisation: EvidenceMinimisationOptions | None = None,
        signing_key: Path | None = None,
        signing_key_id: str | None = None,
        resume: bool = False,
        retry_failed_accounts: frozenset[str] = frozenset(),
    ) -> tuple[Path, ConsolidatedCoverageSummary, tuple[AccountFailure, ...]]:
        """Collect or resume selected account evidence and write its envelope."""
        output.mkdir(parents=True, exist_ok=True)
        self._fixture_paths = dict(discovery.fixture_collection_paths or {})
        self._checkpoint = OrganizationCheckpointStore()
        bundles_dir = output / "bundles"
        state_dir = output / "state"
        bundles_dir.mkdir(parents=True, exist_ok=True)
        state_dir.mkdir(parents=True, exist_ok=True)
        staging_dir = state_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        self._account_executor = OrganizationCollectionAccountExecutor(
            self._attempt_supervisor,
            self._fixture_paths,
            self._checkpoint.transition,
            self._checkpoint.write,
        )
        run_id = organization_run_id(output)
        fingerprint = OrganizationRequestFingerprint().build_digest(
            organization_config,
            scan_config,
            scanner_selection,
            discovery,
            operation="collect",
            minimisation=minimisation,
            report_payload=None,
        )
        state_path = state_dir / "organization-run-state.json"
        state = self._checkpoint.load(state_path, fingerprint, resume)
        state.update(
            {
                "schema_version": self._checkpoint.schema_version,
                "run_id": run_id,
                "request_fingerprint": fingerprint,
                "operation": "collect",
            },
        )
        state.setdefault("accounts", {})
        state_lock = threading.RLock()
        results = OrganizationRunResults()
        children = results.children
        bundle_results = results.bundle_results
        failures = results.failures
        pending = []
        for account in discovery.selection.selected:
            saved = state["accounts"].get(account.alias, {})
            bundle_path = bundles_dir / f"{account.alias}.zip"
            digest = OrganizationBundleResumer().restore(saved, bundle_path, resume=resume)
            if digest is not None:
                state["accounts"][account.alias] = saved
                report_path = str(saved.get("report_path") or "")
                children[account.alias] = bundle_path
                bundle_results[account.alias] = self._account_executor.bundle_result(
                    account.alias,
                    digest,
                    bool(saved.get("degraded", saved.get("status") == "degraded")),
                    schema_version=str(saved.get("bundle_schema_version") or "2026-02"),
                    bundle_purpose=str(saved.get("bundle_purpose") or "collector_evidence"),
                    report_path=report_path or None,
                )
                continue
            if resume and saved.get("retryable") is False and account.alias not in retry_failed_accounts:
                failures[account.alias] = AccountFailure(
                    account_reference=account.alias,
                    stage=str(saved.get("stage", "unknown")),
                    code=str(saved.get("code", "previous_non_retryable_failure")),
                    category=str(saved.get("category", "non_retryable")),
                    sanitized_detail="Preserved non-retryable failure from resumed run.",
                    retryable=False,
                    attempts=int(saved.get("attempts", 1)),
                )
                continue
            pending.append(account)
        self._checkpoint.write(state_path, state, state_lock)

        def execute_account(account: AccountIdentity) -> tuple[PerAccountBundleResult, dict[str, object]]:
            return self._account_executor.execute(
                OrganizationAccountAttemptContext(
                    account=account,
                    management_session=management_session,
                    organization_config=organization_config,
                    scan_config=scan_config,
                    scanner_selection=scanner_selection,
                    bundles_dir=bundles_dir,
                    staging_dir=staging_dir,
                    minimisation=minimisation,
                    run_id=run_id,
                    state=state,
                    state_path=state_path,
                    state_lock=state_lock,
                ),
            )

        OrganizationAccountScheduler(self._attempt_supervisor, self._checkpoint).run(
            OrganizationScheduleContext(
                pending=tuple(pending),
                organization_config=organization_config,
                bundles_dir=bundles_dir,
                state=state,
                state_path=state_path,
                state_lock=state_lock,
                results=results,
            ),
            execute_account,
        )
        return OrganizationEnvelopeAssembler().write(
            OrganizationEnvelopeContext(
                discovery=discovery,
                run_id=run_id,
                fingerprint=fingerprint,
                output=output,
                results=results,
                bundle_purpose="collector_evidence",
                analysis_state="not_analyzed",
                signing_key=signing_key,
                signing_key_id=signing_key_id,
            ),
        )
