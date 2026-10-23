"""Finite synthetic attribution endpoints with observed calls and provider failures."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from tools.collector_attribution.responses import responses
from tools.collector_audit_fixture import SyntheticAuditSession

if TYPE_CHECKING:
    from collections.abc import Callable


class SyntheticAttributionSession(SyntheticAuditSession):
    """Keep all clients offline while executing production collector branches unchanged."""

    def __init__(self, variant: str, *, service: str = "ec2", calls: list[str] | None = None) -> None:
        """Share only the synthetic operation record across finite local endpoints."""
        super().__init__(service, variant)
        self.calls = [] if calls is None else calls

    def create_client(self, service: str, **kwargs: object) -> SyntheticAttributionSession:
        """Never construct a live SDK session or accept unlisted endpoint identities."""
        if service not in {"ec2", "logs", "elbv2", "autoscaling", "resourcegroupstaggingapi"} or kwargs.get("region_name") != "eu-west-2":
            message = "Unexpected synthetic attribution endpoint"
            raise AssertionError(message)
        return SyntheticAttributionSession(self.variant, service=service, calls=self.calls)

    def __getattr__(self, operation: str) -> Callable[..., dict[str, Any]]:
        """Expose declared SDK methods and fail unrecognized operation access closed."""
        try:
            responses(self.service, operation, self.variant, {})
        except KeyError:
            raise AttributeError(operation) from None

        def invoke(**parameters: Any) -> dict[str, Any]:  # noqa: ANN401
            self.calls.append(self.service + ":" + operation)
            code = {"denied": "AccessDenied", "unavailable": "ServiceUnavailable", "unsupported": "UnsupportedOperation", "failure": "InternalFailure"}.get(
                self.variant
            )
            if self.variant == "partial" and operation in {"describe_tags", "describe_network_interfaces", "get_resources"}:
                code = "AccessDenied"
            denied_operations = {
                "query_denied": "start_query",
                "route_denied": "describe_route_tables",
                "tags_denied": "describe_tags",
                "fast_denied": "get_resources",
                "direct_denied": "describe_vpcs",
                "target_groups_denied": "describe_target_groups",
                "target_health_denied": "describe_target_health",
                "asg_denied": "describe_auto_scaling_groups",
            }
            if operation == denied_operations.get(self.variant):
                code = "AccessDenied"
            if code:
                raise ClientError({"Error": {"Code": code, "Message": "synthetic-customer-provider-failure"}}, operation)
            return responses(self.service, operation, self.variant, parameters)

        return invoke
