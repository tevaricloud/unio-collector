"""Actual Glue/SageMaker wrappers with populated local providers and callbacks."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any

from tools.collector_analytics.search import SyntheticSearchSession
from tools.collector_analytics.session import SyntheticAnalyticsSession
from tools.collector_sdk_fixture import add_wrapper_observation, wrapper_producer_observation
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod

GLUE = "glue-job-crawler-cost-review"
SAGEMAKER = "sagemaker-cost-review"
OPENSEARCH = "opensearch-cost-review"
REDSHIFT = "redshift-cost-review"
SERVICES = {
    OPENSEARCH: ("opensearch", "Amazon OpenSearch Service"),
    REDSHIFT: ("redshift", "Amazon Redshift"),
    GLUE: ("glue", "AWS Glue"),
    SAGEMAKER: ("sagemaker", "Amazon SageMaker"),
}
VARIANTS = {
    OPENSEARCH: ("success", "empty", "denied", "unsupported", "failure", "unavailable", "partial", "nullable"),
    REDSHIFT: ("success", "empty", "denied", "unsupported", "failure", "unavailable", "partial", "nullable"),
    GLUE: (
        "success",
        "empty",
        "denied",
        "unsupported",
        "failure",
        "unavailable",
        "partial",
        "nullable",
        "capped",
        "defaults",
        "negative",
        "malformed",
        "omitted",
    ),
    SAGEMAKER: ("success", "empty", "denied", "unsupported", "failure", "unavailable", "partial", "nullable"),
}


def analytics_producer_observation(scanner: str, variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Collect and serialize actual registered output, preserving every callback."""
    service, billing_service = SERVICES[scanner]
    session = SyntheticSearchSession(service, variant) if scanner in {OPENSEARCH, REDSHIFT} else SyntheticAnalyticsSession(service, variant)
    options: dict[str, object] = {"max_job_run_jobs": 1, "max_job_runs_per_job": 2}
    if variant != "defaults":
        options.update(long_running_job_seconds=-1 if variant == "negative" else 100, high_dpu_seconds=-1.5 if variant == "negative" else 100.5)
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
    observed = wrapper_producer_observation(scanner, session, options=options, service_costs=costs, daily_costs=daily)
    observed["provider_calls"] = session.calls
    observed["statuses"] = [result.status for result in session.collection_diagnostics.get_results_since(0)]
    observed["diagnostic_warnings"] = session.collection_diagnostics.build_warning_messages_since(0)
    return observed


def add_analytics_producer_payloads(files: dict[str, bytes], *, unknown: bool = False) -> None:
    """Distribute the same actual populated primary and capped callback envelopes."""
    for scanner in SERVICES:
        observed = analytics_producer_observation(scanner, "capped" if scanner == GLUE else "success")
        if unknown:
            observed["evidence"]["payload"]["records"][0]["unknown_analytics_control"] = None
            observed["execution"]["coverage_notes"][0]["detail_counts"]["unknown_analytics_note"] = None
        add_wrapper_observation(files, observed)
