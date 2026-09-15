from __future__ import annotations  # noqa: D100

from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

from unio_collector.aws.account.risk.base_signals import AccountCostRiskBaseSignals
from unio_collector.aws.account.risk.record import AccountCostRiskRecord
from unio_collector.aws.response_admission import ProviderResponseError, require_complete_response, require_response_mapping, require_response_rows

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext


class AccountCostRiskCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context

    def collect(self) -> AccountCostRiskRecord:  # noqa: D102
        base_signals = self._collect_base_signals()
        errors: list[str] = []
        trails: list[dict[str, Any]] = []
        cloudtrail_available = False
        try:
            trails = require_response_rows(base_signals.trails_response, "trailList")
            require_complete_response(base_signals.trails_response)
            cloudtrail_available = True
        except ProviderResponseError as exc:
            errors.append(f"DescribeTrails:{exc.aws_error_code}")
        summary: dict[str, Any] = {}
        iam_available = False
        try:
            summary = require_response_mapping(require_response_mapping(base_signals.iam_summary).get("SummaryMap"))
            iam_available = True
        except ProviderResponseError as exc:
            errors.append(f"GetAccountSummary:{exc.aws_error_code}")
        statuses = self._collect_trail_statuses(trails)
        omitted = max(0, len(trails) - 25)
        statuses_complete = (
            cloudtrail_available and not omitted and len(statuses) == len(trails) and all(isinstance(status["is_logging"], bool) for status in statuses)
        )
        if omitted:
            errors.append("GetTrailStatus:CappedEvidence")
        if len(statuses) != min(25, len(trails)) or any(not isinstance(status["is_logging"], bool) for status in statuses):
            errors.append("GetTrailStatus:UnavailableEvidence")
        return AccountCostRiskRecord(
            account_id=self.account_id,
            cloudtrail_available=cloudtrail_available,
            trails=trails,
            trail_statuses=statuses,
            iam_summary_available=iam_available,
            iam_summary=summary,
            trail_statuses_complete=statuses_complete,
            trail_status_omitted_count=omitted,
            collection_errors=tuple(errors),
        )

    def _collect_base_signals(self) -> AccountCostRiskBaseSignals:
        with ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="unio-collector-account-risk",
        ) as executor:
            trails_future = executor.submit(self._collect_trails)
            iam_future = executor.submit(self._collect_iam_summary)
            return AccountCostRiskBaseSignals(
                trails_response=trails_future.result(),
                iam_summary=iam_future.result(),
            )

    def _collect_trails(self) -> dict[str, Any] | None:
        return self._safe_call(
            "cloudtrail",
            "describe_trails",
            {"includeShadowTrails": True},
            region_name="us-east-1",
        )

    def _collect_iam_summary(self) -> dict[str, Any] | None:
        return self._safe_call(
            "iam",
            "get_account_summary",
            {},
            region_name="us-east-1",
        )

    def _collect_trail_statuses(
        self,
        trails: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        statuses: list[dict[str, Any]] = []
        for trail in trails[:25]:
            trail_name = trail.get("TrailARN") or trail.get("Name")
            if not isinstance(trail_name, str) or not trail_name:
                continue
            response = self._safe_call(
                "cloudtrail",
                "get_trail_status",
                {"Name": trail_name},
                region_name="us-east-1",
            )
            if response:
                statuses.append(
                    {
                        "trail": trail_name,
                        "is_logging": response.get("IsLogging"),
                        "latest_delivery_error": response.get("LatestDeliveryError"),
                    },
                )
        return statuses

    def _safe_call(
        self,
        service_name: str,
        method_name: str,
        kwargs: dict[str, Any],
        *,
        region_name: str,
    ) -> dict[str, Any] | None:
        client = self.session.create_client(
            service_name,
            region_name=region_name,
            audit_context=self.audit_context,
        )
        try:
            return require_response_mapping(getattr(client, method_name)(**kwargs))
        except Exception:  # noqa: BLE001
            return None
