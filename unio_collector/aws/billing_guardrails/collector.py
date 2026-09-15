from __future__ import annotations  # noqa: D100

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from unio_collector.aws.billing_guardrails.modes import (
    BILLING_ALARM_SKIPPED_ERROR,
    BILLING_ANOMALY_MONITOR_SKIPPED_ERROR,
    BILLING_ANOMALY_SUBSCRIPTION_SKIPPED_ERROR,
    BILLING_SUBSCRIBER_DETAIL_SKIPPED_ERROR,
    normalize_billing_monitor_detail_mode,
    normalize_billing_subscriber_detail_mode,
)
from unio_collector.aws.billing_guardrails.record import BillingGuardrailRecord
from unio_collector.aws.collection import (
    AwsCollectionExecutor,
    AwsCollectionTask,
    record_collection_results,
)
from unio_collector.aws.inventory_helpers import AwsInventoryValueHelper
from unio_collector.aws.pagination import AwsPaginationHelper

if TYPE_CHECKING:
    from unio_collector.aws.audit import AwsAuditContext

GuardrailTaskCollector = Callable[[], list[dict[str, Any]]]


class BillingGuardrailCollector:  # noqa: D101
    def __init__(  # noqa: D107
        self,
        session: Any,  # noqa: ANN401
        *,
        account_id: str,
        audit_context: AwsAuditContext,
        subscriber_detail_mode: str = "full",
        monitor_detail_mode: str = "full",
    ) -> None:
        self.session = session
        self.account_id = account_id
        self.audit_context = audit_context
        self.subscriber_detail_mode = normalize_billing_subscriber_detail_mode(
            subscriber_detail_mode,
        )
        self.monitor_detail_mode = normalize_billing_monitor_detail_mode(
            monitor_detail_mode,
        )
        self.permission_errors: list[str] = []
        self._pagination = AwsPaginationHelper()
        self._values = AwsInventoryValueHelper()
        self.max_workers = self._get_max_workers()

    def collect(self) -> BillingGuardrailRecord:  # noqa: D102
        results = AwsCollectionExecutor(
            max_workers=min(4, self.max_workers),
        ).run(self._build_guardrail_tasks())
        record_collection_results(self.session, results)
        values: dict[str, object] = {str(result.task.payload.get("evidence_type")): result.value for result in results if result.status == "completed"}
        return BillingGuardrailRecord(
            account_id=self.account_id,
            budgets=self._get_list_value(values, "budgets"),
            anomaly_monitors=self._get_list_value(values, "anomaly_monitors"),
            anomaly_subscriptions=self._get_list_value(
                values,
                "anomaly_subscriptions",
            ),
            billing_alarms=self._get_list_value(values, "billing_alarms"),
            permission_errors=list(self.permission_errors),
        )

    def _build_guardrail_tasks(self) -> list[AwsCollectionTask[list[dict[str, Any]]]]:
        tasks = [
            self._build_guardrail_task(
                name="BillingGuardrailCollector:budgets",
                service="budgets",
                operation=self._get_budget_operation_summary(),
                evidence_type="budgets",
                collect=self._collect_budgets,
            ),
        ]
        if self.monitor_detail_mode == "budgets-only":
            self._record_unique_permission_error(BILLING_ANOMALY_MONITOR_SKIPPED_ERROR)
            self._record_unique_permission_error(
                BILLING_ANOMALY_SUBSCRIPTION_SKIPPED_ERROR,
            )
            self._record_unique_permission_error(BILLING_ALARM_SKIPPED_ERROR)
            return tasks
        tasks.extend(
            [
                self._build_guardrail_task(
                    name="BillingGuardrailCollector:anomaly-monitors",
                    region="aws-global",
                    service="ce",
                    operation="GetAnomalyMonitors",
                    evidence_type="anomaly_monitors",
                    collect=self._collect_anomaly_monitors,
                ),
                self._build_guardrail_task(
                    name="BillingGuardrailCollector:anomaly-subscriptions",
                    region="aws-global",
                    service="ce",
                    operation="GetAnomalySubscriptions",
                    evidence_type="anomaly_subscriptions",
                    collect=self._collect_anomaly_subscriptions,
                ),
                self._build_guardrail_task(
                    name="BillingGuardrailCollector:billing-alarms",
                    region="us-east-1",
                    service="cloudwatch",
                    operation="DescribeAlarms",
                    evidence_type="billing_alarms",
                    collect=self._collect_billing_alarms,
                ),
            ],
        )
        return tasks

    def _build_guardrail_task(
        self,
        *,
        name: str,
        service: str,
        operation: str,
        evidence_type: str,
        collect: GuardrailTaskCollector,
        region: str = "us-east-1",
    ) -> AwsCollectionTask[list[dict[str, Any]]]:
        return AwsCollectionTask(
            name=name,
            scanner_id=self.audit_context.scanner_id,
            collector_id=self.audit_context.collector,
            account_id=self.account_id,
            region=region,
            service=service,
            operation=operation,
            payload={"evidence_type": evidence_type},
            collect=collect,
        )

    def _get_list_value(
        self,
        values: dict[str, object],
        key: str,
    ) -> list[dict[str, Any]]:
        value = values.get(key)
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    def _collect_budgets(self) -> list[dict[str, Any]]:
        budgets = self._safe_token_pages(
            "budgets",
            "describe_budgets",
            result_key="Budgets",
            kwargs={"AccountId": self.account_id, "MaxResults": 100},
            region_name="us-east-1",
        )
        tasks = [
            AwsCollectionTask(
                name=(f"BillingGuardrailCollector:budget-notifications:{budget.get('BudgetName')}"),
                scanner_id=self.audit_context.scanner_id,
                collector_id=self.audit_context.collector,
                account_id=self.account_id,
                region="us-east-1",
                service="budgets",
                operation=self._get_budget_notification_operation_summary(),
                payload={"budget_name": str(budget.get("BudgetName") or "")},
                collect=lambda budget=budget: self._collect_budget_record(budget),
            )
            for budget in budgets
            if isinstance(budget, dict)
        ]
        results = AwsCollectionExecutor(max_workers=self.max_workers).run(tasks)
        record_collection_results(self.session, results)
        return [result.value for result in results if result.status == "completed" and isinstance(result.value, dict)]

    def _collect_budget_record(self, budget: dict[str, Any]) -> dict[str, Any]:
        budget_name = budget.get("BudgetName")
        notifications = []
        if budget_name:
            notifications = self._collect_budget_notifications(str(budget_name))
        if self.subscriber_detail_mode == "summary":
            self._record_unique_permission_error(
                BILLING_SUBSCRIBER_DETAIL_SKIPPED_ERROR,
            )
            return {
                "budget": budget,
                "notifications": notifications,
            }
        notification_details = [
            {
                "notification": notification,
                "subscriber_count": len(
                    self._collect_notification_subscribers(
                        str(budget_name),
                        notification,
                    ),
                ),
            }
            for notification in notifications
            if budget_name
        ]
        record: dict[str, Any] = {
            "budget": budget,
            "notifications": notifications,
        }
        if notification_details:
            record["notification_details"] = notification_details
        return record

    def _collect_budget_notifications(
        self,
        budget_name: str,
    ) -> list[dict[str, Any]]:
        return self._safe_token_pages(
            "budgets",
            "describe_notifications_for_budget",
            result_key="Notifications",
            kwargs={"AccountId": self.account_id, "BudgetName": budget_name},
            region_name="us-east-1",
        )

    def _collect_anomaly_monitors(self) -> list[dict[str, Any]]:
        return self._safe_token_pages(
            "ce",
            "get_anomaly_monitors",
            result_key="AnomalyMonitors",
            kwargs={},
            region_name="us-east-1",
            request_cursor_key="NextPageToken",
            response_cursor_keys=("NextPageToken", "NextToken"),
        )

    def _collect_anomaly_subscriptions(self) -> list[dict[str, Any]]:
        return self._safe_token_pages(
            "ce",
            "get_anomaly_subscriptions",
            result_key="AnomalySubscriptions",
            kwargs={},
            region_name="us-east-1",
            request_cursor_key="NextPageToken",
            response_cursor_keys=("NextPageToken", "NextToken"),
        )

    def _collect_billing_alarms(self) -> list[dict[str, Any]]:
        alarms = self._safe_token_pages(
            "cloudwatch",
            "describe_alarms",
            result_key="MetricAlarms",
            kwargs={},
            region_name="us-east-1",
        )
        return self._filter_billing_alarms(alarms)

    def _safe_token_pages(
        self,
        service_name: str,
        method_name: str,
        *,
        result_key: str,
        kwargs: dict[str, Any],
        region_name: str = "us-east-1",
        request_cursor_key: str = "NextToken",
        response_cursor_keys: tuple[str, ...] = ("NextToken",),
    ) -> list[dict[str, Any]]:
        client = self.session.create_client(
            service_name,
            region_name=region_name,
            audit_context=self.audit_context,
        )
        try:
            result = self._pagination.collect_token_pages(
                client,
                method_name,
                result_key=result_key,
                request_parameters=kwargs,
                request_cursor_key=request_cursor_key,
                response_cursor_keys=response_cursor_keys,
            )
        except Exception as exc:  # noqa: BLE001
            self.permission_errors.append(f"{service_name}:{method_name}:{exc}")
            return []
        return self._values.collect_dict_items(result.pages, result_key)

    def _collect_notification_subscribers(
        self,
        budget_name: str | None,
        notification: dict[str, Any],
    ) -> list[dict[str, Any]]:
        if not budget_name:
            return []
        return self._safe_token_pages(
            "budgets",
            "describe_subscribers_for_notification",
            result_key="Subscribers",
            kwargs={
                "AccountId": self.account_id,
                "BudgetName": budget_name,
                "Notification": notification,
            },
            region_name="us-east-1",
        )

    def _filter_billing_alarms(
        self,
        alarms: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        billing_alarms: list[dict[str, Any]] = []
        for alarm in alarms:
            if alarm.get("Namespace") == "AWS/Billing":
                billing_alarms.append(alarm)
                continue
            if alarm.get("MetricName") == "EstimatedCharges":
                billing_alarms.append(alarm)
        return billing_alarms

    def _get_budget_operation_summary(self) -> str:
        operations = "DescribeBudgets+DescribeNotificationsForBudget"
        if self.subscriber_detail_mode == "full":
            return f"{operations}+DescribeSubscribersForNotification"
        return operations

    def _get_budget_notification_operation_summary(self) -> str:
        operations = "DescribeNotificationsForBudget"
        if self.subscriber_detail_mode == "full":
            return f"{operations}+DescribeSubscribersForNotification"
        return operations

    def _record_unique_permission_error(self, error: str) -> None:
        if error not in self.permission_errors:
            self.permission_errors.append(error)

    def _get_max_workers(self) -> int:
        runtime_config = getattr(self.session, "runtime_config", None)
        value = getattr(runtime_config, "max_workers", 4)
        if isinstance(value, int) and value > 0:
            return min(8, value)
        return 4
