"""Finite actual SDK response variants for commitment inventory and grouped metrics."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from tools.collector_commitment.responses import RESPONSES


class CommitmentResponseScenario:
    """Vary provider inputs without replacing or rewriting producer output."""

    def __init__(self, variant: str, service: str) -> None:
        """Carry the selected synthetic SDK response branch."""
        self.variant = variant
        self.service = service

    def response(self, operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Return a fresh local SDK response, preserving explicit absent and malformed cases."""
        result = deepcopy(RESPONSES[operation])
        if self.variant == "empty":
            return {key: [] if isinstance(value, list) else {} if key == "Total" else value for key, value in result.items()}
        self.inventory(operation, result)
        if self.variant == "cross_account" and self.service == "ce":
            result["AccountId"] = "999999999999"
        if self.variant == "malformed_numeric" and operation == "get_reservation_utilization":
            result["Total"]["PurchasedHours"] = "NaN"
        self.groups(operation, parameters, result)
        self.coverage(operation, result)
        return result

    def inventory(self, operation: str, result: dict[str, Any]) -> None:
        """Use actual provider identities and omitted optional values."""
        name = {"collision": "aws_observed", "dimension_collision": "region", "financial_collision": "100.5"}.get(self.variant, "synthetic-customer-commitment")
        if operation == "describe_reserved_instances":
            result["ReservedInstances"][0]["ReservedInstancesId"] = name
            if self.variant == "nullable":
                result["ReservedInstances"] = [{"ReservedInstancesId": name}]
        if operation == "describe_savings_plans":
            result["savingsPlans"][0]["savingsPlanId"] = name
            if self.variant == "nullable":
                result["savingsPlans"] = [{"savingsPlanId": name}]

    def groups(self, operation: str, parameters: dict[str, Any], result: dict[str, Any]) -> None:
        """Populate actual group requests and every supported RI grouping dimension."""
        name = "synthetic-customer-commitment"
        if self.variant == "groups" and operation == "get_reservation_utilization":
            result["UtilizationsByTime"] = [
                {
                    "Groups": [
                        {
                            "Value": name,
                            "Attributes": {"region": "eu-west-2", "instanceType": "m6i.large", "tenancy": "default", "platform": "Linux/UNIX"},
                            "Utilization": deepcopy(result["Total"]),
                        }
                    ]
                }
            ]
        if operation == "get_reservation_coverage" and self.variant == "groups":
            values = {
                "REGION": ("region", "eu-west-2"),
                "AZ": ("availabilityZone", "eu-west-2a"),
                "INSTANCE_TYPE": ("instanceType", "m6i.large"),
                "PLATFORM": ("platform", "Linux/UNIX"),
                "TENANCY": ("tenancy", "default"),
            }
            attrs = dict(values[item["Key"]] for item in parameters["GroupBy"])
            result["CoveragesByTime"] = [{"Groups": [{"Attributes": attrs, "Coverage": deepcopy(result["Total"])}]}]

    def coverage(self, operation: str, result: dict[str, Any]) -> None:
        """Exercise provider attribute data keys independently of structural JSON fields."""
        if operation == "get_savings_plans_coverage":
            attrs = result["SavingsPlansCoverages"][0]["Attributes"]
            attrs["region"] = "eu-west-2"
            if self.variant == "unknown_dimension":
                attrs["synthetic.customer.COST[0]"] = "synthetic-customer-dimension"
