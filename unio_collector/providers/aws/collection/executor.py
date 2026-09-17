from __future__ import annotations  # noqa: D100

from datetime import UTC, datetime
from importlib import import_module
from pathlib import Path
from typing import TYPE_CHECKING, cast

from unio_collector.aws.api.call_ledger import ApiCallLedger
from unio_collector.aws.cost_explorer.baseline_service import (
    AwsBillingBaselineService,
)
from unio_collector.collector.execution.result import CollectorExecutionResult
from unio_collector.evidence.collection_store import CollectionEvidenceStore
from unio_collector.providers.aws.collection.fixture import AwsCollectionFixture
from unio_collector.providers.aws.collection.pricing_context import (
    AwsCollectorPricingContextService,
)
from unio_collector.scan_workflow.aws.scan.billing_scope import BillingRegionScopeService
from unio_collector.scan_workflow.scope.billing.region_coverage import (
    BillingRegionCoverageBuilder,
)
from unio_collector.scanners.cost_explorer.service_delta.evidence import (
    CostExplorerServiceDeltaEvidence,
)
from unio_collector.scanners.scanner.evidence_serializer import (
    build_scanner_evidence_payload,
    require_serialized_scanner_evidence,
)
from unio_collector.scanners.scanner.result import ScannerExecutionResult

if TYPE_CHECKING:
    from collections.abc import Callable

    from unio_collector.aws.audited.session import AuditedAwsSession
    from unio_collector.collector.config.protocol import CollectionConfigProtocol
    from unio_collector.scan_workflow.progress import ScanProgressEvent
    from unio_collector.scanners.selection import ScannerSelection


class AwsProviderCollectionExecutor:
    """Collect AWS evidence without invoking scanner analysis."""

    def execute_collection(
        self,
        config: object,
        selection: object,
        progress: object | None = None,
        *,
        minimisation: object | None = None,
    ) -> CollectorExecutionResult:
        """Execute fixture or live read-only AWS collection."""
        scan_config = cast("CollectionConfigProtocol", config)
        scanner_selection = cast("ScannerSelection", selection)
        progress_handler = cast(
            "Callable[[ScanProgressEvent], None] | None",
            progress,
        )
        if scan_config.fixture:
            return self._collect_fixture(scan_config)
        return self._collect_live(
            scan_config,
            scanner_selection,
            progress_handler,
            no_cost_data=bool(getattr(minimisation, "no_cost_data", False)),
        )

    def execute_with_context(
        self,
        config: object,
        selection: object,
        *,
        session: AuditedAwsSession,
        ledger: object,
        account_context: dict[str, object],
        progress: object | None = None,
        minimisation: object | None = None,
    ) -> CollectorExecutionResult:
        """Collect through an isolated, already verified cross-account session."""
        scan_config = cast("CollectionConfigProtocol", config)
        scanner_selection = cast("ScannerSelection", selection)
        progress_handler = cast("Callable[[ScanProgressEvent], None] | None", progress)
        return self._collect_live(
            scan_config,
            scanner_selection,
            progress_handler,
            no_cost_data=bool(getattr(minimisation, "no_cost_data", False)),
            session=session,
            ledger=cast("ApiCallLedger", ledger),
            account_context=account_context,
        )

    def _collect_fixture(self, config: CollectionConfigProtocol) -> CollectorExecutionResult:
        fixture_path = config.fixture
        if fixture_path is None:
            msg = "Fixture collection requires a fixture path."
            raise ValueError(msg)
        fixture = AwsCollectionFixture.read(Path(fixture_path), default_currency=config.default_currency)
        evidence = CostExplorerServiceDeltaEvidence.capture(fixture.costs, config)
        scanner_id = "cost-explorer-service-delta"
        payload = build_scanner_evidence_payload(scanner_id=scanner_id, evidence=evidence, provider_id="aws")
        require_serialized_scanner_evidence(payload)
        now = datetime.now(UTC)
        scanner_result = ScannerExecutionResult(
            scanner_id=scanner_id,
            status="completed",
            started_at=now,
            completed_at=now,
            regions_scanned=["global"],
            findings_count=0,
            evidence_count=1,
            implementation_type="fixture_collection",
            implementation_class=self.__class__.__name__,
            implementation_module=self.__class__.__module__,
        )
        account_context = dict(fixture.account_context)
        account_context["account_id"] = "123456789012"
        return CollectorExecutionResult(
            provider_id="aws",
            generated_at=now,
            account_context=account_context,
            scan_period=fixture.costs.current_period,
            scanner_results=[scanner_result],
            ledger=ApiCallLedger(),
            evidence_store=CollectionEvidenceStore(),
            config=config,
            scanner_evidence_payloads=[payload],
            collection_summary={
                "source": "fixture",
                "fixture": str(config.fixture),
                "currency": fixture.currency,
            },
        )

    def _collect_live(
        self,
        config: CollectionConfigProtocol,
        selection: ScannerSelection,
        progress: Callable[[ScanProgressEvent], None] | None,
        *,
        no_cost_data: bool = False,
        session: AuditedAwsSession | None = None,
        ledger: ApiCallLedger | None = None,
        account_context: dict[str, object] | None = None,
    ) -> CollectorExecutionResult:
        runtime_type = import_module(
            "unio_collector.providers.aws.runtime",
        ).AwsProviderRuntime
        runtime = runtime_type()
        effective_ledger = ledger or cast("ApiCallLedger", runtime.create_scan_ledger(config))
        effective_session = session or cast(
            "AuditedAwsSession",
            runtime.create_session(config, effective_ledger),
        )
        effective_account_context = account_context or cast(
            "dict[str, object]",
            runtime.resolve_identity(effective_session),
        )
        account_id = str(effective_account_context.get("account_id") or "unknown-account")
        billing_baseline = None
        if not no_cost_data:
            billing_baseline = AwsBillingBaselineService().collect(
                session=effective_session,
                account_id=account_id,
            )
        scan_state = runtime.build_scan_state(
            config=config,
            session=effective_session,
            scope_id=account_id,
            ledger=effective_ledger,
        )
        runner_type = import_module("unio_collector.scan_workflow.runner").ScannerRunner
        runner = runner_type(
            scan_state,
            progress=progress,
            scanner_total=len(selection.enabled_ids),
        )
        effective_config, billing_scope_derivation = self._apply_region_scope_derivation(
            config,
            runner,
        )
        scan_state.config = effective_config
        collection_run_service = import_module(
            "unio_collector.scan_workflow.scanner.collection.run_service",
        ).ScannerCollectionRunService
        collection_run_service().run_many(
            runner,
            selection.enabled_ids,
            progress=progress,
            scanner_total=len(selection.enabled_ids),
        )
        billing_region_coverage = self._build_billing_region_coverage(
            config=effective_config,
            runner=runner,
            no_cost_data=no_cost_data,
        )
        if billing_region_coverage and billing_scope_derivation:
            billing_region_coverage["region_scope_derivation"] = dict(
                billing_scope_derivation,
            )
        payloads = list(runner.output_state.scanner_evidence_payloads)
        for payload in payloads:
            payload.setdefault("provider_id", "aws")
        pricing_context = AwsCollectorPricingContextService().collect(
            session=effective_session,
            account_id=account_id,
            config=effective_config,
            scanner_evidence_payloads=payloads,
            no_cost_data=no_cost_data,
        )
        effective_account_context.setdefault("provider", "aws")
        region_scope_summary = BillingRegionScopeService().build_region_scope_provenance(
            effective_config,
            billing_scope_derivation,
            self._get_region_scope_summary(runner),
        )
        return CollectorExecutionResult(
            provider_id="aws",
            generated_at=datetime.now(UTC),
            account_context=effective_account_context,
            scan_period=config.scan_period,
            scanner_results=list(runner.results),
            ledger=effective_ledger,
            evidence_store=runner.evidence_store,
            config=effective_config,
            api_telemetry=effective_session.telemetry.convert_to_summary(),
            scanner_evidence_payloads=payloads,
            pricing_context=pricing_context.model_dump(mode="json"),
            collection_summary={
                "source": "live",
                "account_id": account_id,
                **(
                    {
                        "last_completed_month_billing_baseline": (billing_baseline.model_dump(mode="json")),
                    }
                    if billing_baseline is not None
                    else {
                        "billing_baseline_status": "not_collected",
                        "billing_baseline_limitations": [
                            "Completed-month billing evidence was excluded by the collector cost-data policy.",
                        ],
                    }
                ),
                **(
                    {
                        "billing_region_coverage": billing_region_coverage,
                        "billing_region_scope_derivation": billing_scope_derivation,
                    }
                    if billing_region_coverage
                    else {}
                ),
                **({"region_scope": region_scope_summary} if region_scope_summary else {}),
                "pricing_replay": {
                    "status": pricing_context.status,
                    "provider": pricing_context.provider,
                    "rate_count": len(pricing_context.rates),
                    "usage_record_count": len(pricing_context.usage_records),
                    "limitations": list(pricing_context.limitations),
                },
                "limitations": (region_scope_summary.get("limitations", []) if region_scope_summary else []),
            },
        )

    def _apply_region_scope_derivation(
        self,
        config: CollectionConfigProtocol,
        runner: object,
    ) -> tuple[CollectionConfigProtocol, dict[str, object]]:
        if not hasattr(config, "regions_from_billing_enabled"):
            return config, {
                "enabled": False,
                "status": "not_requested",
                "requested_regions": [],
                "billing_active_regions": [],
                "normalized_candidate_regions": [],
                "derived_material_regions": [],
                "residual_regions": [],
                "unrecognized_billing_region_values": [],
                "final_regions": [],
            }
        return BillingRegionScopeService().apply_scope_derivation(config, runner)  # type: ignore[arg-type]

    def _build_billing_region_coverage(
        self,
        *,
        config: CollectionConfigProtocol,
        runner: object,
        no_cost_data: bool,
    ) -> dict[str, object]:
        current_period = getattr(runner, "current_period", None)
        if current_period is None:
            return {}
        if no_cost_data:
            return (
                BillingRegionCoverageBuilder()
                .build_unavailable(
                    selected_regions=list(config.regions),
                    explicit_region_scope=config.explicit_region_scope,
                    current_period=current_period,
                    currency=current_period.currency,
                    reason=("Cost Explorer billing-region coverage was excluded by the collector cost-data policy."),
                )
                .convert_to_dict()
            )
        return BillingRegionScopeService().build_region_coverage(
            config,
            runner,  # type: ignore[arg-type]
        )

    def _get_region_scope_summary(self, runner: object) -> dict[str, object]:
        runtime_state = getattr(runner, "runtime_state", None)
        get_region_scope_summary = getattr(runtime_state, "get_region_scope_summary", None)
        if not callable(get_region_scope_summary):
            return {}
        summary = get_region_scope_summary()
        return dict(summary) if isinstance(summary, dict) else {}
