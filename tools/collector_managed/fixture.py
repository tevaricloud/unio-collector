"""Actual ECS/EKS/ElastiCache wrapper, callback and canonical serialization proof."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from tools.collector_managed.cache import SyntheticCacheSession
from tools.collector_managed.ecs import SyntheticEcsSession
from tools.collector_managed.eks import SyntheticEksSession
from tools.collector_sdk_fixture import add_wrapper_observation, wrapper_producer_observation
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod
from unio_collector.core.scan.period import ScanPeriod

ECS = "ecs-cost-governance-review"
EKS = "eks-cost-risk-review"
CACHE = "elasticache-cost-review"
SERVICES = {ECS: ("ecs", "Amazon Elastic Container Service"), EKS: ("eks", "Amazon Elastic Kubernetes Service"), CACHE: ("elasticache", "Amazon ElastiCache")}
SESSIONS = {ECS: SyntheticEcsSession, EKS: SyntheticEksSession, CACHE: SyntheticCacheSession}
COMMON_VARIANTS = ("success", "empty", "denied", "unsupported", "failure", "unavailable", "partial", "nullable")
VARIANTS = {ECS: (*COMMON_VARIANTS, "summary", "billing_active"), EKS: COMMON_VARIANTS, CACHE: (*COMMON_VARIANTS, "summary", "no_data")}


def managed_producer_observation(scanner: str, variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Run actual registered collectors through real scanner gateways and providers."""
    service, billing_service = SERVICES[scanner]
    session = SESSIONS[scanner](service, variant)
    options: dict[str, object] = {}
    if variant == "summary":
        options.update(task_definition_detail_mode="summary", metric_detail_mode="summary")
    if variant == "billing_active":
        options["regional_collection_mode"] = "billing-active"
    selected = ("eu-west-2", "us-east-1") if variant == "billing_active" else ("eu-west-2",)
    period = ScanPeriod(
        kind="days",
        raw_input={"days": 30},
        current_start_date=date(2026, 9, 1),
        current_end_date=date(2026, 9, 30),
        previous_start_date=date(2026, 8, 2),
        previous_end_date=date(2026, 8, 31),
    )
    costs = None
    daily = []
    if billing:
        costs = CostExplorerResult(
            previous_period=CostPeriod(start_date=date(2026, 8, 1), end_date=date(2026, 8, 31), total_cost=Decimal("9.5"), currency="USD"),
            current_period=CostPeriod(start_date=date(2026, 9, 1), end_date=date(2026, 9, 30), total_cost=Decimal("17.25"), currency="USD"),
            service_costs=[{"service_name": billing_service, "current_cost": "17.25", "previous_cost": "9.50", "currency": "USD"}],
        )
        daily = [
            DailyCostRecord(
                date=date(2026, 9, 1),
                service_name=billing_service,
                region="eu-west-2",
                usage_type="synthetic-customer-usage",
                cost=Decimal("17.25"),
                currency="USD",
            )
        ]
    observed = wrapper_producer_observation(
        scanner, session, options=options, service_costs=costs, daily_costs=daily, scan_period=period, selected_regions=selected
    )
    observed["provider_calls"] = session.calls
    observed["statuses"] = [result.status for result in session.collection_diagnostics.get_results_since(0)]
    observed["diagnostic_warnings"] = session.collection_diagnostics.build_warning_messages_since(0)
    return observed


def add_managed_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Use actual full metric and conditional scope envelopes in the packaged input."""
    for scanner in SERVICES:
        observed = managed_producer_observation(scanner)
        if scanner == ECS:
            extra = managed_producer_observation(scanner, "billing_active")
            observed["execution"]["coverage_notes"].extend(extra["execution"]["coverage_notes"])
            extra = managed_producer_observation(scanner, "summary")
            observed["execution"]["coverage_notes"].extend(extra["execution"]["coverage_notes"])
        if unknown:
            observed["evidence"]["payload"]["records"][0]["unknown_managed_control"] = None
            observed["execution"]["coverage_notes"][0]["detail_counts"]["unknown_managed_note"] = None
        add_wrapper_observation(files, observed)
