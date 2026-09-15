from __future__ import annotations  # noqa: D100

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cost_explorer.utils import parse_decimal
from unio_collector.aws.daily_cost_record import DailyCostRecord
from unio_collector.aws.period_costs import PeriodCosts
from unio_collector.billing.baseline import (
    BillingBaselineStatus,
    LastCompletedMonthBillingBaseline,
)

if TYPE_CHECKING:
    from unio_collector.billing.period import CompletedMonthPeriod


@dataclass(frozen=True)
class CostExplorerResponseParser:
    """Parse Cost Explorer daily grouped cost responses."""

    metric_name: str = "UnblendedCost"

    def parse_monthly_total(
        self,
        pages: list[dict[str, Any]],
        *,
        expected_period: CompletedMonthPeriod,
    ) -> LastCompletedMonthBillingBaseline:
        """Parse one ungrouped completed-month total fail-closed."""
        results = [result for page in pages for result in self._get_results_by_time(page)]
        if len(results) != 1:
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                reason=("Cost Explorer returned no completed-month total." if not results else "Cost Explorer returned duplicate completed-month totals."),
            )
        result = results[0]
        time_period = result.get("TimePeriod")
        if not isinstance(time_period, dict) or not all(isinstance(time_period.get(key), str) and time_period.get(key) for key in ("Start", "End")):
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                reason="Cost Explorer did not return a complete billing period.",
            )
        if time_period != {
            "Start": expected_period.start_date.isoformat(),
            "End": expected_period.end_date_exclusive.isoformat(),
        }:
            return self._unavailable_monthly_total(
                expected_period,
                status="period_mismatch",
                reason="Cost Explorer returned a billing period that did not match the requested completed month.",
            )
        if result.get("Estimated") is not False:
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                estimated=(result.get("Estimated") if isinstance(result.get("Estimated"), bool) else None),
                reason=(
                    "Cost Explorer marked the completed-month total as estimated."
                    if result.get("Estimated") is True
                    else "Cost Explorer did not confirm that the completed-month total was final."
                ),
            )
        total = result.get("Total")
        if not isinstance(total, dict):
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                reason="Cost Explorer did not return an ungrouped billing total.",
            )
        metric = total.get(self.metric_name)
        if not isinstance(metric, dict):
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                reason=f"Cost Explorer did not return the {self.metric_name} metric.",
            )
        amount_value = metric.get("Amount")
        currency_value = metric.get("Unit")
        if amount_value in (None, "") or currency_value in (None, ""):
            return self._unavailable_monthly_total(
                expected_period,
                status="incomplete",
                reason="Cost Explorer returned a completed-month total without an amount or currency.",
            )
        try:
            amount = Decimal(str(amount_value))
        except (InvalidOperation, TypeError, ValueError):
            return self._unavailable_monthly_total(
                expected_period,
                status="invalid",
                reason="Cost Explorer returned a malformed completed-month amount.",
            )
        return LastCompletedMonthBillingBaseline(
            period=expected_period,
            amount=amount,
            currency=str(currency_value),
            estimated=False,
            complete=True,
            status="available",
        )

    def parse_period_costs(self, pages: list[dict[str, Any]]) -> PeriodCosts:  # noqa: D102
        costs: dict[str, Decimal] = {}
        currency: str | None = None
        for response in pages:
            for result in self._get_results_by_time(response):
                for group in self._get_groups(result):
                    service_name = self._get_group_values(group)[0]
                    metric = self._get_metric(group)
                    amount = parse_decimal(metric.get("Amount"))
                    currency = metric.get("Unit") or currency
                    costs[service_name] = costs.get(service_name, Decimal(0)) + amount
        return PeriodCosts(cost_by_service=costs, currency=currency)

    def parse_daily_cost_response(  # noqa: D102
        self,
        response: dict[str, Any],
        group_keys: tuple[str, ...],
    ) -> list[DailyCostRecord]:
        records: list[DailyCostRecord] = []
        for result in self._get_results_by_time(response):
            start = date.fromisoformat(result["TimePeriod"]["Start"])
            for group in self._get_groups(result):
                values = self._get_group_values(group)
                metric = self._get_metric(group)
                keyed = dict(zip(group_keys, values, strict=False))
                records.append(
                    DailyCostRecord(
                        date=start,
                        service_name=keyed.get(
                            "SERVICE",
                            values[0] if values else "Unknown",
                        ),
                        region=keyed.get("REGION", "global"),
                        usage_type=keyed.get("USAGE_TYPE"),
                        cost=parse_decimal(metric.get("Amount")),
                        currency=metric.get("Unit") or "USD",
                    ),
                )
        return records

    def _get_results_by_time(
        self,
        response: dict[str, Any],
    ) -> list[dict[str, Any]]:
        results = response.get("ResultsByTime", [])
        if not isinstance(results, list):
            return []
        return [item for item in results if isinstance(item, dict)]

    def _get_groups(self, result: dict[str, Any]) -> list[dict[str, Any]]:
        groups = result.get("Groups", [])
        if not isinstance(groups, list):
            return []
        return [item for item in groups if isinstance(item, dict)]

    def _get_group_values(self, group: dict[str, Any]) -> list[str]:
        values = group.get("Keys", [])
        if not isinstance(values, list):
            return ["Unknown"]
        return [str(value) for value in values] or ["Unknown"]

    def _get_metric(self, group: dict[str, Any]) -> dict[str, str]:
        metrics = group.get("Metrics", {})
        if not isinstance(metrics, dict):
            return {}
        metric = metrics.get(self.metric_name, {})
        if not isinstance(metric, dict):
            return {}
        return {str(key): str(value) for key, value in metric.items()}

    def _unavailable_monthly_total(
        self,
        period: CompletedMonthPeriod,
        *,
        status: BillingBaselineStatus,
        reason: str,
        estimated: bool | None = None,
    ) -> LastCompletedMonthBillingBaseline:
        return LastCompletedMonthBillingBaseline(
            period=period,
            estimated=estimated,
            complete=False,
            status=status,
            limitations=[reason],
        )
