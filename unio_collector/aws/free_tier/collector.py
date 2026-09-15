from __future__ import annotations  # noqa: D100

from typing import TYPE_CHECKING, Any

from unio_collector.aws.free_tier.api_error import FreeTierApiErrorRecorder
from unio_collector.aws.free_tier.collection_result import FreeTierCollectionResult
from unio_collector.aws.free_tier.facts import FREE_TIER_REGION
from unio_collector.aws.free_tier.response_parser import FreeTierResponseParser
from unio_collector.aws.pagination import AwsPaginationHelper
from unio_collector.aws.response_admission import ProviderResponseError, require_complete_response, require_response_rows

if TYPE_CHECKING:
    from unio_collector.aws.audit import AuditedAwsSession, AwsAuditContext
    from unio_collector.aws.free_tier.account_plan import FreeTierAccountPlanRecord
    from unio_collector.aws.free_tier.usage_record import FreeTierUsageRecord


class FreeTierCollector:
    """Collect account-level AWS Free Tier visibility with read-only APIs."""

    def __init__(  # noqa: D107
        self,
        session: AuditedAwsSession,
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        pagination: AwsPaginationHelper | None = None,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.pagination = pagination or AwsPaginationHelper()
        self._parser = FreeTierResponseParser(fallback_account_id=self.account_id)
        self._errors = FreeTierApiErrorRecorder()

    def collect(self) -> FreeTierCollectionResult:  # noqa: D102
        client = self.session.create_client(
            "freetier",
            region_name=FREE_TIER_REGION,
            audit_context=self.audit_context,
        )
        permission_errors: list[str] = []
        api_errors: list[str] = []
        account_plan = self._collect_account_plan(
            client,
            permission_errors=permission_errors,
            api_errors=api_errors,
        )
        usage_records, page_count = self._collect_usage_records(
            client,
            permission_errors=permission_errors,
            api_errors=api_errors,
        )
        return FreeTierCollectionResult(
            account_id=self.account_id,
            account_plan=account_plan,
            usage_records=usage_records,
            page_count=page_count,
            permission_errors=permission_errors,
            api_errors=api_errors,
        )

    def _collect_account_plan(
        self,
        client: Any,  # noqa: ANN401
        *,
        permission_errors: list[str],
        api_errors: list[str],
    ) -> FreeTierAccountPlanRecord | None:
        try:
            response = client.get_account_plan_state()
            return self._parser.parse_account_plan(response)
        except Exception as exc:  # noqa: BLE001
            self._errors.record_error(
                exc,
                operation="freetier:GetAccountPlanState",
                permission_errors=permission_errors,
                api_errors=api_errors,
            )
            return None

    def _collect_usage_records(
        self,
        client: Any,  # noqa: ANN401
        *,
        permission_errors: list[str],
        api_errors: list[str],
    ) -> tuple[list[FreeTierUsageRecord], int]:
        try:
            result = self.pagination.collect_pages(
                client,
                "get_free_tier_usage",
                result_key="freeTierUsages",
                request_parameters={"maxResults": 1000},
            )
        except Exception as exc:  # noqa: BLE001
            self._errors.record_error(
                exc,
                operation="freetier:GetFreeTierUsage",
                permission_errors=permission_errors,
                api_errors=api_errors,
            )
            return [], 0

        records: list[FreeTierUsageRecord] = []
        try:
            self._append_usage_records(result.pages, records)
        except ProviderResponseError as exc:
            self._errors.record_error(
                exc,
                operation="freetier:GetFreeTierUsage",
                permission_errors=permission_errors,
                api_errors=api_errors,
            )
        return records, result.page_count

    def _append_usage_records(self, pages: list[dict[str, Any]], records: list[FreeTierUsageRecord]) -> None:
        if not pages:
            raise ProviderResponseError
        for page in pages:
            records.extend(self._parser.parse_usage_record(item) for item in require_response_rows(page, "freeTierUsages"))
        require_complete_response(pages[-1])
