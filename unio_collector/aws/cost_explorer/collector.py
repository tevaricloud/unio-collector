from __future__ import annotations  # noqa: D100

from datetime import date, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from unio_collector.aws.cost_explorer.request_factory import CostExplorerRequestFactory
from unio_collector.aws.cost_explorer.response_parser import CostExplorerResponseParser
from unio_collector.aws.cost_explorer.result import CostExplorerResult
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.billing.period_resolver import CompletedMonthPeriodResolver
from unio_collector.core.cost_period import CostPeriod
from unio_collector.core.scan.period import ScanPeriod  # noqa: TC001
from unio_collector.core.scan.period_resolver import ScanPeriodResolver

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext
    from unio_collector.aws.daily_cost_record import DailyCostRecord
    from unio_collector.aws.period_costs import PeriodCosts
    from unio_collector.billing.baseline import LastCompletedMonthBillingBaseline


class CostExplorerCollector:
    """Read-only Cost Explorer collector."""

    def __init__(self, session: Any, *, audit_context: AwsAuditContext) -> None:  # noqa: ANN401, D107
        self.session = session
        self.client = session.create_client(
            "ce",
            region_name="us-east-1",
            audit_context=audit_context,
        )
        self._pagination = AwsPaginationHelper()
        self._requests = CostExplorerRequestFactory()
        self._parser = CostExplorerResponseParser()

    def collect_service_costs(  # noqa: D102
        self,
        *,
        days: int | None = None,
        scan_period: ScanPeriod | None = None,
    ) -> CostExplorerResult:
        resolved_period = scan_period or ScanPeriodResolver().resolve(days=days or 14)
        current_start = resolved_period.current_start_date
        current_end_exclusive = resolved_period.current_end_exclusive
        previous_start = resolved_period.previous_start_date
        previous_end_exclusive = resolved_period.previous_end_exclusive

        previous = self._collect_period(previous_start, previous_end_exclusive)
        current = self._collect_period(current_start, current_end_exclusive)
        currency = current.currency or previous.currency or "USD"

        service_names = sorted(
            set(previous.cost_by_service) | set(current.cost_by_service),
        )
        service_costs = [
            {
                "service_name": service_name,
                "region": "global",
                "previous_cost": str(
                    previous.cost_by_service.get(service_name, Decimal(0)),
                ),
                "current_cost": str(
                    current.cost_by_service.get(service_name, Decimal(0)),
                ),
                "currency": currency,
            }
            for service_name in service_names
        ]

        return CostExplorerResult(
            previous_period=CostPeriod(
                start_date=previous_start,
                end_date=previous_end_exclusive - timedelta(days=1),
                total_cost=sum(previous.cost_by_service.values(), Decimal(0)),
                currency=currency,
            ),
            current_period=CostPeriod(
                start_date=current_start,
                end_date=current_end_exclusive - timedelta(days=1),
                total_cost=sum(current.cost_by_service.values(), Decimal(0)),
                currency=currency,
            ),
            service_costs=service_costs,
        )

    def collect_last_completed_month_baseline(
        self,
        *,
        reference_date: date | None = None,
    ) -> LastCompletedMonthBillingBaseline:
        """Collect the ungrouped total for the last completed UTC month."""
        period = CompletedMonthPeriodResolver().resolve(
            reference_date=reference_date,
        )
        pages = self._pagination.collect_token_pages(
            self.client,
            "get_cost_and_usage",
            result_key="ResultsByTime",
            request_parameters=self._requests.build_monthly_total_request(
                start=period.start_date,
                end_exclusive=period.end_date_exclusive,
            ),
            request_cursor_key="NextPageToken",
            response_cursor_keys=("NextPageToken",),
        ).pages
        return self._parser.parse_monthly_total(
            pages,
            expected_period=period,
        )

    def collect_daily_costs(  # noqa: D102
        self,
        *,
        scan_period: ScanPeriod,
        group_keys: tuple[str, ...] = ("SERVICE",),
    ) -> list[DailyCostRecord]:
        if len(group_keys) > 2:  # noqa: PLR2004
            msg = "AWS Cost Explorer GetCostAndUsage supports at most two GroupBy dimensions per request."
            raise ValueError(
                msg,
            )
        records: list[DailyCostRecord] = []
        pages = self._pagination.collect_token_pages(
            self.client,
            "get_cost_and_usage",
            result_key="ResultsByTime",
            request_parameters=self._requests.build_daily_request(
                start=scan_period.current_start_date,
                end_exclusive=scan_period.current_end_exclusive,
                group_keys=group_keys,
            ),
            request_cursor_key="NextPageToken",
            response_cursor_keys=("NextPageToken",),
        ).pages
        for response in pages:
            records.extend(self._parse_daily_cost_response(response, group_keys))
        return records

    def _collect_period(self, start: date, end_exclusive: date) -> PeriodCosts:
        pages = self._pagination.collect_token_pages(
            self.client,
            "get_cost_and_usage",
            result_key="ResultsByTime",
            request_parameters=self._requests.build_service_request(
                start=start,
                end_exclusive=end_exclusive,
            ),
            request_cursor_key="NextPageToken",
            response_cursor_keys=("NextPageToken",),
        ).pages
        return self._parser.parse_period_costs(pages)

    def _parse_daily_cost_response(
        self,
        response: dict[str, Any],
        group_keys: tuple[str, ...],
    ) -> list[DailyCostRecord]:
        return self._parser.parse_daily_cost_response(response, group_keys)
