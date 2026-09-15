"""Read-only AWS collection for the commitment portfolio scanner."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from unio_collector.aws import errors as aws_errors
from unio_collector.aws.response_admission import ProviderResponseError, require_complete_response, require_response_mapping, require_response_rows
from unio_collector.commitments.ec2_adapter import Ec2ReservedInstanceAdapter
from unio_collector.commitments.observation import ObservedCommitmentPortfolio
from unio_collector.commitments.observed_metric import ObservedCommitmentMetric
from unio_collector.commitments.savings_adapter import SavingsPlanAdapter
from unio_collector.commitments.source import CommitmentSourceOutcome
from unio_collector.commitments.types import CommitmentValueNature
from unio_collector.scanners.cost_explorer.commitment.parsing import (
    CommitmentAccountScopeError,
    assessment_time,
    currencies_by_service,
    decimal_value,
    global_region,
    object_dict,
    period_dates,
    selected_regions,
    validate_account_scope,
)
from unio_collector.scanners.cost_explorer.commitment.response_collector import CommitmentResponseCollector

if TYPE_CHECKING:
    from collections.abc import Mapping

    from unio_collector.commitments.inventory import CommitmentInventoryItem
    from unio_collector.core.scan.period import ScanPeriod
    from unio_collector.scanners.base import ScannerContext


class AwsCommitmentPortfolioCollector:
    """Collect account-scoped AWS commitment evidence using read-only APIs."""

    def collect(self, context: ScannerContext) -> ObservedCommitmentPortfolio:
        """Collect typed inventory, utilization, coverage, and source outcomes."""
        period = context.options.get_scan_period()
        account_id = context.security.account_id
        regions = selected_regions(context.options.get_selected_regions(), context.security.session.get_region_name())
        inventory: list[CommitmentInventoryItem] = []
        outcomes: list[CommitmentSourceOutcome] = []
        limitations: list[str] = []

        for region in regions:
            source = f"ec2:DescribeReservedInstances:{region}"
            try:
                response = context.security.create_client(
                    "ec2",
                    region_name=region,
                    collector_name="AwsCommitmentPortfolioCollector",
                ).describe_reserved_instances()
            except Exception as exc:  # noqa: BLE001
                outcomes.append(self._failure(source, exc))
                continue
            records = response.get("ReservedInstances") if isinstance(response, dict) else None
            if not isinstance(records, list):
                outcomes.append(CommitmentSourceOutcome(source, "malformed", limitation="ReservedInstances was not a list."))
                continue
            try:
                require_complete_response(response)
            except ProviderResponseError as exc:
                outcomes.append(self._failure(source, exc))
                continue
            parsed = [
                item
                for record in records
                if isinstance(record, dict)
                and (
                    item := Ec2ReservedInstanceAdapter().parse(
                        record,
                        account_id=account_id,
                        region=region,
                        as_of=assessment_time(period.current_end_exclusive),
                    )
                )
                is not None
            ]
            inventory.extend(parsed)
            outcomes.append(self._success(source, len(records), len(parsed)))

        savings_source = "savingsplans:DescribeSavingsPlans"
        try:
            savings_client = context.security.create_client(
                "savingsplans",
                region_name=global_region(context.security.session.get_region_name()),
                collector_name="AwsCommitmentPortfolioCollector",
            )
            savings_records = CommitmentResponseCollector().collect_pages(
                savings_client,
                "describe_savings_plans",
                "savingsPlans",
                request_page_key="nextToken",
                response_page_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            outcomes.append(self._failure(savings_source, exc))
        else:
            parsed_savings = [
                item
                for record in savings_records
                if (
                    item := SavingsPlanAdapter().parse(
                        record,
                        account_id=account_id,
                        as_of=assessment_time(period.current_end_exclusive),
                    )
                )
                is not None
            ]
            inventory.extend(parsed_savings)
            outcomes.append(self._success(savings_source, len(savings_records), len(parsed_savings)))

        observed, cost_outcomes = self._collect_cost_explorer(context, period)
        outcomes.extend(cost_outcomes)
        currencies = currencies_by_service(inventory)
        observed = [
            replace(metric, currency=next(iter(currencies.get(metric.service, ())), None))
            if len(currencies.get(metric.service, ())) == 1 and metric.currency is None
            else metric
            for metric in observed
        ]
        if not regions:
            limitations.append("No selected AWS region was available for EC2 Reserved Instance inventory.")
        return ObservedCommitmentPortfolio(
            account_id=account_id,
            period_start=period.current_start_date,
            period_end_exclusive=period.current_end_exclusive,
            inventory=tuple(inventory),
            observed_metrics=tuple(observed),
            source_outcomes=tuple(outcomes),
            regions=tuple(regions),
            limitations=tuple(limitations),
        )

    def _collect_cost_explorer(
        self,
        context: ScannerContext,
        period: ScanPeriod,
    ) -> tuple[list[ObservedCommitmentMetric], list[CommitmentSourceOutcome]]:
        metrics: list[ObservedCommitmentMetric] = []
        outcomes: list[CommitmentSourceOutcome] = []
        account_id = context.security.account_id
        try:
            client = context.security.create_client(
                "ce",
                region_name="us-east-1",
                collector_name="AwsCommitmentPortfolioCollector",
            )
        except Exception as exc:  # noqa: BLE001
            sources = (
                "ce:GetReservationUtilization",
                "ce:GetReservationCoverage",
                "ce:GetSavingsPlansUtilization",
                "ce:GetSavingsPlansCoverage",
            )
            return metrics, [self._failure(source, exc) for source in sources]
        time_period = {
            "Start": period.current_start_date.isoformat(),
            "End": period.current_end_exclusive.isoformat(),
        }
        ri_filter = self._ri_filter(account_id)
        account_filter = self._account_filter(account_id)

        self._collect_ce_source(
            client,
            source="ce:GetReservationUtilization",
            method="get_reservation_utilization",
            result_key="UtilizationsByTime",
            kwargs={"TimePeriod": time_period, "Filter": ri_filter, "GroupBy": [{"Type": "DIMENSION", "Key": "SUBSCRIPTION_ID"}], "MaxResults": 100},
            metrics=metrics,
            outcomes=outcomes,
            parser=self._parse_ri_utilization,
            account_id=account_id,
        )
        for grouping in (("REGION", "AZ"), ("INSTANCE_TYPE", "PLATFORM"), ("TENANCY",)):
            self._collect_ce_source(
                client,
                source=f"ce:GetReservationCoverage:{'_'.join(grouping).lower()}",
                method="get_reservation_coverage",
                result_key="CoveragesByTime",
                kwargs={
                    "TimePeriod": time_period,
                    "Filter": ri_filter,
                    "GroupBy": [{"Type": "DIMENSION", "Key": key} for key in grouping],
                    "Metrics": ["Hour", "Unit", "Cost"],
                    "MaxResults": 100,
                },
                metrics=metrics,
                outcomes=outcomes,
                parser=self._parse_ri_coverage,
                account_id=account_id,
            )
        self._collect_ce_source(
            client,
            source="ce:GetSavingsPlansUtilization",
            method="get_savings_plans_utilization",
            result_key="SavingsPlansUtilizationsByTime",
            kwargs={"TimePeriod": time_period, "Filter": account_filter, "Granularity": "DAILY"},
            metrics=metrics,
            outcomes=outcomes,
            parser=self._parse_savings_utilization,
            paginated=False,
            account_id=account_id,
        )
        for grouping in (("REGION", "INSTANCE_FAMILY"), ("SERVICE",)):
            grouping_name = "_".join(grouping).lower()
            self._collect_ce_source(
                client,
                source=f"ce:GetSavingsPlansCoverage:{grouping_name}",
                method="get_savings_plans_coverage",
                result_key="SavingsPlansCoverages",
                kwargs={
                    "TimePeriod": time_period,
                    "Filter": account_filter,
                    "GroupBy": [{"Type": "DIMENSION", "Key": key} for key in grouping],
                    "Metrics": ["SpendCoveredBySavingsPlans"],
                    "MaxResults": 100,
                },
                metrics=metrics,
                outcomes=outcomes,
                parser=lambda pages, active_period, name=grouping_name: self._parse_savings_coverage(pages, active_period, name),
                request_page_key="NextToken",
                response_page_key="NextToken",
                account_id=account_id,
            )
        return metrics, outcomes

    def _collect_ce_source(
        self,
        client: Any,  # noqa: ANN401
        *,
        source: str,
        method: str,
        result_key: str,
        kwargs: dict[str, object],
        metrics: list[ObservedCommitmentMetric],
        outcomes: list[CommitmentSourceOutcome],
        parser: Any,  # noqa: ANN401
        account_id: str,
        paginated: bool = True,
        request_page_key: str = "NextPageToken",
        response_page_key: str = "NextPageToken",
    ) -> None:
        try:
            pages = CommitmentResponseCollector().collect_response_pages(
                client,
                method,
                kwargs,
                request_page_key=request_page_key,
                response_page_key=response_page_key,
                paginated=paginated,
            )
            validate_account_scope(pages, account_id)
            records = [item for page in pages for item in require_response_rows(page, result_key)]
            parsed = parser(pages, kwargs["TimePeriod"])
        except Exception as exc:  # noqa: BLE001
            outcomes.append(self._failure(source, exc))
            return
        metrics.extend(parsed)
        if any(metric.value is None and metric.limitations for metric in parsed):
            outcomes.append(CommitmentSourceOutcome(source, "malformed", len(parsed), "One or more numeric fields were malformed."))
        else:
            outcomes.append(self._success(source, len(records), len(parsed)))

    def _parse_ri_utilization(self, pages: list[dict[str, Any]], period: object) -> list[ObservedCommitmentMetric]:
        metrics: list[ObservedCommitmentMetric] = []
        if pages:
            metrics.extend(self._ri_utilization_metrics(pages[0].get("Total"), period))
        for page in pages:
            for row in page.get("UtilizationsByTime", []):
                if not isinstance(row, dict):
                    continue
                for group in require_response_rows(row, "Groups") if "Groups" in row else []:
                    if not isinstance(group, dict):
                        continue
                    attributes = object_dict(group.get("Attributes"))
                    dimensions = tuple(sorted((str(key), str(value)) for key, value in attributes.items() if value not in (None, "")))
                    metrics.extend(
                        self._ri_utilization_metrics(
                            require_response_mapping(group.get("Utilization")),
                            period,
                            source_id=str(group.get("Value") or group.get("Key") or "") or None,
                            dimensions=dimensions,
                        ),
                    )
        return metrics

    def _ri_utilization_metrics(
        self,
        values: object,
        period: object,
        *,
        source_id: str | None = None,
        dimensions: tuple[tuple[str, str], ...] = (),
    ) -> list[ObservedCommitmentMetric]:
        if values is None:
            return []
        values = require_response_mapping(values)
        mapping = {
            "UtilizationPercentageInUnits": ("utilization_percentage", "percent", CommitmentValueNature.AWS_CALCULATED),
            "UtilizationPercentage": ("utilization_percentage", "percent", CommitmentValueNature.AWS_CALCULATED),
            "PurchasedHours": ("purchased_hours", "hours", CommitmentValueNature.AWS_OBSERVED),
            "PurchasedUnits": ("purchased_units", "normalized_units", CommitmentValueNature.AWS_OBSERVED),
            "UnusedHours": ("unused_hours", "hours", CommitmentValueNature.AWS_OBSERVED),
            "UnusedUnits": ("unused_units", "normalized_units", CommitmentValueNature.AWS_OBSERVED),
            "TotalAmortizedFee": ("effective_cost", "currency", CommitmentValueNature.AWS_CALCULATED),
            "RICostForUnusedHours": ("estimated_waste", "currency", CommitmentValueNature.AWS_CALCULATED),
            "RealizedSavings": ("estimated_avoided_ondemand_spend", "currency", CommitmentValueNature.AWS_CALCULATED),
            "OnDemandCostOfRIHoursUsed": ("ondemand_equivalent", "currency", CommitmentValueNature.AWS_CALCULATED),
        }
        return self._metrics_from_mapping("ec2_reserved_instance", "ce:GetReservationUtilization", values, mapping, period, source_id, dimensions)

    def _parse_ri_coverage(self, pages: list[dict[str, Any]], period: object) -> list[ObservedCommitmentMetric]:
        metrics: list[ObservedCommitmentMetric] = []
        if pages:
            metrics.extend(self._coverage_metrics("ec2_reserved_instance", pages[0].get("Total"), period))
        for page in pages:
            for row in page.get("CoveragesByTime", []):
                if not isinstance(row, dict):
                    continue
                for group in require_response_rows(row, "Groups") if "Groups" in row else []:
                    if not isinstance(group, dict):
                        continue
                    attributes = object_dict(group.get("Attributes"))
                    dimensions = tuple(sorted((str(key), str(value)) for key, value in attributes.items() if value not in (None, "")))
                    coverage = require_response_mapping(group.get("Coverage"))
                    metrics.extend(self._coverage_metrics("ec2_reserved_instance", coverage, period, dimensions=dimensions))
        return metrics

    def _coverage_metrics(
        self,
        service: str,
        values: object,
        period: object,
        *,
        dimensions: tuple[tuple[str, str], ...] = (),
    ) -> list[ObservedCommitmentMetric]:
        if values is None:
            return []
        values = require_response_mapping(values)
        units = object_dict(values.get("CoverageNormalizedUnits"))
        hours = object_dict(values.get("CoverageHours"))
        cost = object_dict(values.get("CoverageCost"))
        source = units or hours
        raw = {
            "CoveragePercentage": source.get("CoverageNormalizedUnitsPercentage", source.get("CoverageHoursPercentage")),
            "OnDemand": source.get("OnDemandNormalizedUnits", source.get("OnDemandHours")),
            "Reserved": source.get("ReservedNormalizedUnits", source.get("ReservedHours")),
            "Total": source.get("TotalRunningNormalizedUnits", source.get("TotalRunningHours")),
            "OnDemandCost": cost.get("OnDemandCost"),
        }
        unit = "normalized_units" if units else "hours"
        mapping = {
            "CoveragePercentage": ("coverage_percentage", "percent", CommitmentValueNature.AWS_CALCULATED),
            "OnDemand": ("uncovered_eligible_usage", unit, CommitmentValueNature.AWS_OBSERVED),
            "Reserved": ("covered_usage", unit, CommitmentValueNature.AWS_OBSERVED),
            "Total": ("total_eligible_usage", unit, CommitmentValueNature.AWS_OBSERVED),
            "OnDemandCost": ("uncovered_ondemand_cost", "currency", CommitmentValueNature.AWS_CALCULATED),
        }
        return self._metrics_from_mapping(service, "ce:GetReservationCoverage", raw, mapping, period, None, dimensions)

    def _parse_savings_utilization(self, pages: list[dict[str, Any]], period: object) -> list[ObservedCommitmentMetric]:
        if not pages:
            return []
        total = object_dict(pages[0].get("Total"))
        if not total:
            return []
        utilization = object_dict(total.get("Utilization"))
        savings = object_dict(total.get("Savings"))
        amortized = object_dict(total.get("AmortizedCommitment"))
        values = {
            "UtilizationPercentage": utilization.get("UtilizationPercentage"),
            "TotalCommitment": utilization.get("TotalCommitment"),
            "UsedCommitment": utilization.get("UsedCommitment"),
            "UnusedCommitment": utilization.get("UnusedCommitment"),
            "TotalAmortizedCommitment": amortized.get("TotalAmortizedCommitment"),
            "NetSavings": savings.get("NetSavings"),
            "OnDemandCostEquivalent": savings.get("OnDemandCostEquivalent"),
        }
        mapping = {
            "UtilizationPercentage": ("utilization_percentage", "percent", CommitmentValueNature.AWS_CALCULATED),
            "TotalCommitment": ("total_commitment", "currency", CommitmentValueNature.AWS_OBSERVED),
            "UsedCommitment": ("used_commitment", "currency", CommitmentValueNature.AWS_OBSERVED),
            "UnusedCommitment": ("unused_commitment", "currency", CommitmentValueNature.AWS_OBSERVED),
            "TotalAmortizedCommitment": ("effective_cost", "currency", CommitmentValueNature.AWS_CALCULATED),
            "NetSavings": ("estimated_avoided_ondemand_spend", "currency", CommitmentValueNature.AWS_CALCULATED),
            "OnDemandCostEquivalent": ("ondemand_equivalent", "currency", CommitmentValueNature.AWS_CALCULATED),
        }
        return self._metrics_from_mapping("savings_plans", "ce:GetSavingsPlansUtilization", values, mapping, period, None, ())

    def _parse_savings_coverage(self, pages: list[dict[str, Any]], period: object, grouping: str) -> list[ObservedCommitmentMetric]:
        metrics: list[ObservedCommitmentMetric] = []
        for page in pages:
            for row in page.get("SavingsPlansCoverages", []):
                if not isinstance(row, dict):
                    continue
                attributes = object_dict(row.get("Attributes"))
                dimensions = tuple(sorted([("_grouping", grouping), *((str(key), str(value)) for key, value in attributes.items() if value not in (None, ""))]))
                coverage = require_response_mapping(row.get("Coverage"))
                mapping = {
                    "CoveragePercentage": ("coverage_percentage", "percent", CommitmentValueNature.AWS_CALCULATED),
                    "OnDemandCost": ("uncovered_ondemand_cost", "currency", CommitmentValueNature.AWS_CALCULATED),
                    "SpendCoveredBySavingsPlans": ("spend_covered", "currency", CommitmentValueNature.AWS_CALCULATED),
                    "TotalCost": ("total_eligible_cost", "currency", CommitmentValueNature.AWS_CALCULATED),
                }
                metrics.extend(self._metrics_from_mapping("savings_plans", "ce:GetSavingsPlansCoverage", coverage, mapping, period, None, dimensions))
        return metrics

    def _metrics_from_mapping(
        self,
        service: str,
        operation: str,
        values: Mapping[str, object],
        mapping: dict[str, tuple[str, str, CommitmentValueNature]],
        period: object,
        source_id: str | None,
        dimensions: tuple[tuple[str, str], ...],
    ) -> list[ObservedCommitmentMetric]:
        start, end = period_dates(period)
        if start is None or end is None:
            raise ProviderResponseError
        metrics: list[ObservedCommitmentMetric] = []
        for field, (name, unit, nature) in mapping.items():
            if field not in values or values[field] is None:
                continue
            metrics.append(
                ObservedCommitmentMetric(
                    service=service,
                    name=name,
                    value=decimal_value(values[field]),
                    unit=unit,
                    source_operation=operation,
                    source_field=field,
                    nature=nature,
                    evidence_timestamp=assessment_time(end) if end else None,
                    period_start=start,
                    period_end_exclusive=end,
                    source_id=source_id,
                    dimensions=dimensions,
                    limitations=("Malformed numeric value.",) if decimal_value(values[field]) is None else (),
                ),
            )
        return metrics

    def _ri_filter(self, account_id: str) -> dict[str, object]:
        return {
            "And": [
                {"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Elastic Compute Cloud - Compute"]}},
                self._account_filter(account_id),
            ],
        }

    def _account_filter(self, account_id: str) -> dict[str, object]:
        return {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [account_id]}}

    def _failure(self, source: str, exc: Exception) -> CommitmentSourceOutcome:
        code = aws_errors.get_aws_error_code(exc) or exc.__class__.__name__
        scope_error = code in {"ValidationException", "InvalidParameterException"} or isinstance(exc, CommitmentAccountScopeError)
        status = "account_scope_unproven" if scope_error else "unavailable"
        return CommitmentSourceOutcome(source, status, limitation=f"{code}: {exc}")

    def _success(self, source: str, records: int, parsed: int) -> CommitmentSourceOutcome:
        if parsed < records:
            return CommitmentSourceOutcome(source, "partial", parsed, f"Skipped {records - parsed} malformed records.")
        return CommitmentSourceOutcome(source, "success" if records or parsed else "success_empty", parsed)
