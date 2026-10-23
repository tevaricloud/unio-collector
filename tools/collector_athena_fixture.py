"""Actual athena producer fixture using fixed offline provider responses."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING, Any, cast

from botocore.exceptions import ClientError

from tools.collector_sdk_fixture import add_wrapper_observation, wrapper_producer_observation
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.core.cost_period import CostPeriod

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext

NULL_QUERY_INDEX = 2
SCANNER = "athena-query-efficiency-review"
VARIANTS = ("negative", "complete", "success", "empty", "denied", "unsupported", "partial", "capped", "unavailable", "omitted", "defaults", "failure")


class SyntheticAthenaSession:
    """Fixed synthetic endpoints; no network or SDK-client construction."""

    def __init__(self, variant: str) -> None:
        """Select a fixed offline provider-response branch."""
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticAthenaSession:
        """Return only this synthetic service endpoint; never construct an SDK client."""
        del audit_context
        if service_name != "athena" or region_name != "eu-west-2":
            message = "Unexpected synthetic Athena service or region."
            raise ValueError(message)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Synthetic service unavailable"}}, "CreateClient")
        return self

    def can_paginate(self, name: str) -> bool:
        """Use the actual collector fallback path with one deterministic page."""
        del name
        return False

    def list_work_groups(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        return {
            "WorkGroups": []
            if self.variant == "empty"
            else [{"Name": f"synthetic-customer-workgroup-{i}"} for i in range(45 if self.variant == "omitted" else 1)]
        }

    def get_work_group(self, **kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        return {
            "WorkGroup": {
                "Name": kwargs["WorkGroup"],
                "Configuration": {
                    "EnforceWorkGroupConfiguration": True,
                    "PublishCloudWatchMetricsEnabled": True,
                    "RequesterPaysEnabled": True,
                    "BytesScannedCutoffPerQuery": 100000000,
                },
            }
        }

    def list_data_catalogs(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        return {"DataCatalogsSummary": [{"CatalogName": "synthetic-customer-catalog", "Type": "GLUE"}]}

    def list_query_executions(self, **_kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        if self.variant in ("denied", "unsupported", "failure"):
            raise ClientError(
                {
                    "Error": {
                        "Code": {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}[self.variant],
                        "Message": "Synthetic query failure",
                    }
                },
                "ListQueryExecutions",
            )
        return {
            "QueryExecutionIds": [f"synthetic-query-{i}" for i in range(50 if self.variant == "omitted" else 3)],
            **({"NextToken": "synthetic-next"} if self.variant == "capped" else {}),
        }

    def batch_get_query_execution(self, **kwargs: object) -> dict[str, Any]:
        """Return the fixed synthetic response for this provider operation."""
        ids = cast("list[str]", kwargs["QueryExecutionIds"])
        ids = ids[:1] if self.variant == "partial" else ids
        return {
            "QueryExecutions": [
                {
                    "QueryExecutionId": qid,
                    "Status": {"State": "FAILED" if index == 1 else "SUCCEEDED"},
                    "Statistics": {
                        "TotalExecutionTimeInMillis": 1500 + index,
                        "EngineExecutionTimeInMillis": 1000 + index,
                        "DataScannedInBytes": None if index == NULL_QUERY_INDEX and self.variant not in {"complete", "negative"} else 3000 + index,
                    },
                }
                for index, qid in enumerate(ids)
            ]
        }


def athena_producer_observation(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Collect real DTOs and serialize optional cost-enriched producer output."""
    if variant not in VARIANTS:
        message = "Unknown synthetic inventory variant."
        raise ValueError(message)
    session = SyntheticAthenaSession(variant)
    costs = None
    daily: list[DailyCostRecord] = []
    options: dict[str, object] = {
        "max_query_execution_workgroups": 45 if variant == "omitted" else 10,
        "max_query_executions_per_workgroup": 50 if variant == "omitted" else 25,
    }
    if variant != "defaults":
        options.update(long_running_query_ms=-100 if variant == "negative" else 1000, high_bytes_scanned=-200 if variant == "negative" else 2000)
    if billing:
        current = CostPeriod(start_date=date(2026, 9, 1), end_date=date(2026, 9, 30), total_cost=Decimal("17.25"), currency="USD")
        previous = CostPeriod(start_date=date(2026, 8, 1), end_date=date(2026, 8, 31), total_cost=Decimal("9.50"), currency="USD")
        costs = CostExplorerResult(
            previous_period=previous,
            current_period=current,
            service_costs=[{"service_name": "Amazon Athena", "current_cost": "17.25", "previous_cost": "9.50", "currency": "USD"}],
        )
        daily = [
            DailyCostRecord(
                date=date(2026, 9, 1), service_name="Amazon Athena", region="eu-west-2", usage_type="synthetic-usage", cost=Decimal("17.25"), currency="USD"
            )
        ]
    return wrapper_producer_observation("athena-query-efficiency-review", session, options=options, service_costs=costs, daily_costs=daily)


def athena_producer_payload(variant: str = "success", *, billing: bool = True) -> dict[str, Any]:
    """Retain the fixture API while exercising the registered wrapper and gateways."""
    return athena_producer_observation(variant, billing=billing)["evidence"]


def add_athena_producer_payload(files: dict[str, bytes], *, unknown_field: bool = False, unknown_note: bool | None = None) -> None:
    """Use populated partial actual producer output in the distributed smoke input."""
    observed = athena_producer_observation("partial")
    row = observed["evidence"]
    additional = athena_producer_observation("capped")
    row["payload"]["records"].extend(additional["evidence"]["payload"]["records"])
    observed["execution"]["coverage_notes"].extend(additional["execution"]["coverage_notes"])
    if unknown_field:
        row["payload"]["records"][0]["unknown_athena_field"] = {}
    if unknown_field if unknown_note is None else unknown_note:
        observed["execution"]["coverage_notes"][0]["detail_counts"]["unknown_inventory_note_count"] = None
    add_wrapper_observation(files, observed)
