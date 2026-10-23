"""Synthetic six-operation provider endpoint; no SDK clients or credentials."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

from tools.collector_billing.client import SyntheticBillingClient
from tools.collector_billing.response import OPERATIONS, BillingSdkShape, sample
from tools.collector_recommendation.response import sdk_model
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticBillingSession:
    """Drive actual readers with validated populated or limited SDK responses."""

    def __init__(self, variant: str) -> None:
        """Bind one offline variant and record the actual calls."""
        self.variant = variant
        self.calls: list[dict[str, Any]] = []
        self.endpoints: list[dict[str, str]] = []
        self.collection_diagnostics = AwsCollectionDiagnostics()
        self.runtime_config = SimpleNamespace(max_workers=1)
        self.models = {service: sdk_model(service) for service in ("budgets", "ce", "cloudwatch")}

    def create_client(self, service: str, *, region_name: str, audit_context: AwsAuditContext) -> SyntheticBillingClient:
        """Permit only actual billing endpoints and the owning audit identity."""
        if service not in self.models or region_name != "us-east-1" or audit_context.scanner_id != "billing-alerts-and-budgets-review":
            message = "Unexpected synthetic billing endpoint"
            raise ValueError(message)
        self.endpoints.append({"service": service, "region": region_name, "scanner_id": audit_context.scanner_id})
        return SyntheticBillingClient(self, service)

    def response(self, operation: str, params: dict[str, Any]) -> dict[str, Any]:
        """Validate actual SDK requests and preserve populated/failure responses."""
        service, name, key = OPERATIONS[operation]
        model = self.models[service].operation_model(name)
        validate_parameters(params, model.input_shape)
        self.calls.append({"operation": operation, "parameters": deepcopy(params)})
        self._failure(service, name, params)
        shape = cast("BillingSdkShape", model.output_shape).members[key].member
        row = cast("dict[str, Any]", sample(cast("BillingSdkShape", shape), variant=self.variant))
        if self.variant == "optional":
            row = {field: value for field, value in row.items() if field in shape.required_members}
        if operation == "describe_alarms" and self.variant == "optional":
            row.update(Namespace="AWS/Billing", MetricName="EstimatedCharges")
        self._mutate(row, operation)
        result: dict[str, Any] = {key: [] if self.variant == "empty" else [row]}
        if self.variant == "later_page" and operation == "describe_budgets":
            result["NextToken"] = "synthetic-next-page"
        if self.variant not in {"null_field", "unknown"}:
            validate_parameters(result, model.output_shape)
        return result

    def _failure(self, service: str, name: str, params: dict[str, Any]) -> None:
        """Return only the explicitly supported synthetic failure branch."""
        if self.variant == "later_page" and service == "budgets" and params.get("NextToken"):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Synthetic later page"}}, name)
        limited = self.variant in {"denied", "unavailable", "failure"} or (self.variant == "partial" and service == "ce")
        if limited:
            if self.variant == "failure":
                message = "Synthetic billing failure only"
                raise RuntimeError(message)
            code = "ServiceUnavailableException" if self.variant == "unavailable" else "AccessDeniedException"
            raise ClientError({"Error": {"Code": code, "Message": "SyntheticBillingDiagnostic"}}, name)

    def _mutate(self, row: dict[str, Any], operation: str) -> None:
        """Inject only declared synthetic SDK adversarial or malformed branches."""
        if self.variant == "adversarial":
            for field in ("BudgetName", "MonitorName", "SubscriptionName", "AlarmName"):
                if field in row:
                    row[field] = "COST"
            if operation == "describe_budgets":
                row["BudgetType"] = "COST"
        if self.variant == "null_field" and operation == "describe_budgets":
            row["BudgetName"] = None
        if self.variant == "malformed" and operation == "describe_budgets":
            row["BudgetLimit"]["Amount"] = "NaN"
        if self.variant == "unknown" and operation == "describe_budgets":
            row["BudgetLimit"]["unknown_billing_control"] = None
