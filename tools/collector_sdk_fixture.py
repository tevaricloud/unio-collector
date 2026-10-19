"""Synthetic runtime gateways for the remaining registered inventory wrappers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_scanner_fixture import add_scanner_producer_payload
from unio_collector.aws.audit.context import AwsAuditContext
from unio_collector.scanners.account_risk.cost.collector import AccountCostRiskSignalCollector
from unio_collector.scanners.analytics_ai.athena.collector import AthenaQueryEfficiencyReviewCollector
from unio_collector.scanners.analytics_ai.bedrock.collector import BedrockCostReviewCollector
from unio_collector.scanners.analytics_ai.glue.collector import GlueJobCrawlerCostReviewCollector
from unio_collector.scanners.analytics_ai.sagemaker.collector import SageMakerCostReviewCollector
from unio_collector.scanners.platform.api_gateway.collector import ApiGatewayCostReviewCollector
from unio_collector.scanners.platform.ecs.collector import EcsCostGovernanceReviewCollector
from unio_collector.scanners.platform.eks.collector import EksCostRiskReviewCollector
from unio_collector.scanners.platform.elasticache.collector import ElastiCacheCostReviewCollector
from unio_collector.scanners.platform.opensearch.collector import OpenSearchCostReviewCollector
from unio_collector.scanners.platform.redshift.collector import RedshiftCostReviewCollector
from unio_collector.scanners.scanner.context import ScannerContext
from unio_collector.scanners.scanner.evidence_serializer import build_scanner_evidence_payload
from unio_collector.scanners.scanner.result import ScannerExecutionResult

if TYPE_CHECKING:
    from unio_collector.core.scan.period import ScanPeriod
    from unio_collector.scanners.base.unio_scanner import BaseUnioScanner

WRAPPERS: dict[str, type[BaseUnioScanner]] = {
    "ecs-cost-governance-review": EcsCostGovernanceReviewCollector,
    "eks-cost-risk-review": EksCostRiskReviewCollector,
    "elasticache-cost-review": ElastiCacheCostReviewCollector,
    "opensearch-cost-review": OpenSearchCostReviewCollector,
    "redshift-cost-review": RedshiftCostReviewCollector,
    "glue-job-crawler-cost-review": GlueJobCrawlerCostReviewCollector,
    "sagemaker-cost-review": SageMakerCostReviewCollector,
    "account-cost-risk-signal-review": AccountCostRiskSignalCollector,
    "api-gateway-cost-review": ApiGatewayCostReviewCollector,
    "athena-query-efficiency-review": AthenaQueryEfficiencyReviewCollector,
    "bedrock-cost-review": BedrockCostReviewCollector,
}


class SyntheticWrapperRuntime:
    """Return local provider inputs and retain actual gateway callback observations."""

    def __init__(
        self,
        session: object,
        *,
        options: dict[str, object],
        service_costs: object,
        daily_costs: list[Any],
        scan_period: ScanPeriod | None = None,
        selected_regions: tuple[str, ...] = ("eu-west-2",),
    ) -> None:
        """Keep provider data in one operation without constructing SDK sessions."""
        self.options = dict(options)
        self.service_costs = service_costs
        self.daily_costs = daily_costs
        self.notes: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.callbacks: list[str] = []
        self.runtime_state = SimpleNamespace(
            account_id="123456789012",
            session=session,
            config=SimpleNamespace(scan_period=scan_period),
            get_selected_regions=lambda: list(selected_regions),
            has_explicit_region_scope=lambda: True,
            get_scanner_option=lambda _scanner, key, default: self.options.get(key, default),
        )

    def create_audit_context(self, definition: Any, collector_name: str) -> AwsAuditContext:  # noqa: ANN401
        """Record real security-gateway composition and return its local audit identity."""
        self.callbacks.append("audit:" + collector_name)
        return AwsAuditContext(scanner_id=definition.scanner_id, collector=collector_name, allowed_api_calls=())

    def collect_cached_service_costs(self, _definition: object) -> object:
        """Feed the actual cost-context helper through its real cost gateway."""
        self.callbacks.append("service_costs")
        if self.service_costs is None:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic cost context unavailable"}}, "GetCostAndUsage")
        return self.service_costs

    def collect_cached_daily_costs(self, _definition: object, *, group_keys: tuple[str, ...]) -> list[Any]:
        """Retain requested cost dimensions without rewriting collected payloads."""
        self.callbacks.append("daily_costs:" + ",".join(group_keys))
        return self.daily_costs

    def add_scanner_warning(self, _scanner: str, text: str) -> None:
        """Retain actual wrapper-generated warnings for privacy and parity checks."""
        self.warnings.append(text)

    def add_scanner_coverage_note(self, _scanner: str, note: dict[str, Any]) -> None:
        """Retain actual optional, limitation and execution-detail notes unchanged."""
        self.notes.append(note)


def wrapper_producer_observation(
    scanner: str,
    session: object,
    *,
    options: dict[str, object] | None = None,
    service_costs: object = None,
    daily_costs: list[Any] | None = None,
    scan_period: ScanPeriod | None = None,
    selected_regions: tuple[str, ...] = ("eu-west-2",),
) -> dict[str, Any]:
    """Invoke actual registered collection and canonical evidence/result serialization."""
    runtime: Any = SyntheticWrapperRuntime(
        session, options=options or {}, service_costs=service_costs, daily_costs=daily_costs or [], scan_period=scan_period, selected_regions=selected_regions
    )
    definition: Any = SimpleNamespace(scanner_id=scanner, display_name=scanner)
    evidence = WRAPPERS[scanner](definition).collect(ScannerContext(runtime=runtime, definition=definition))
    row = build_scanner_evidence_payload(scanner_id=scanner, evidence=evidence)
    execution = ScannerExecutionResult(
        scanner_id=scanner,
        status="completed_with_warnings" if runtime.warnings else "completed",
        warnings=runtime.warnings,
        coverage_notes=runtime.notes,
        regions_scanned=getattr(evidence, "regions", []),
    ).convert_to_dict()
    return {"evidence": row, "execution": execution, "callbacks": runtime.callbacks}


def add_wrapper_observation(files: dict[str, bytes], observed: dict[str, Any]) -> None:
    """Keep actual wrapper notes beside its actual evidence in the shared smoke input."""
    add_scanner_producer_payload(files, observed["evidence"], execution=observed["execution"])
