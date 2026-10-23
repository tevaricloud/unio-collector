"""Variant-controlled SDK calls around retained synthetic response providers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from tools.collector_dynamodb.metric_client import SyntheticMetricClient
    from tools.collector_dynamodb.scaling_client import SyntheticScalingClient
    from tools.collector_dynamodb.table_client import SyntheticTableClient
    from tools.collector_dynamodb.tagging_client import SyntheticTaggingClient

from botocore.exceptions import ClientError, EndpointConnectionError


class SyntheticDynamoClient:
    """Change SDK responses before real collection, never rewrite producer DTOs."""

    def __init__(self, backend: SyntheticTableClient | SyntheticScalingClient | SyntheticTaggingClient | SyntheticMetricClient, variant: str) -> None:
        """Keep one synthetic service provider and its declared fault variant."""
        self.backend, self.variant = backend, variant
        self.calls = backend.calls

    def __getattr__(self, operation: str) -> Callable[..., Any]:
        """Wrap only methods exposed by the local SDK response provider."""
        target = getattr(self.backend, operation)

        def invoke(*args: object, **kwargs: object) -> Any:  # noqa: ANN401
            if operation == "can_paginate":
                return False
            self._fault(operation, kwargs)
            if self.variant == "empty" and operation == "list_tables":
                self.calls.append(operation)
                return {"TableNames": []}
            request = self._values(kwargs, reverse=True)
            response = target(*args, **request)
            if self.variant == "metrics_partial" and operation == "get_metric_data":
                for result in response["MetricDataResults"]:
                    result["StatusCode"] = "PartialData"
            if self.variant in {"nullable", "malformed"} and operation == "describe_table":
                names = (
                    ("BillingModeSummary", "TableClassSummary", "StreamSpecification")
                    if self.variant == "malformed"
                    else ("TableClassSummary", "StreamSpecification")
                )
                for name in names:
                    response["Table"].pop(name, None)
            return self._values(response)

        return invoke

    def _fault(self, operation: str, request: dict[str, Any]) -> None:
        root = operation == "list_tables"
        variant = self.variant
        denied = (
            (root and variant == "denied")
            or (variant == "partial" and operation == "describe_table" and request.get("TableName") == "events")
            or (variant == "retention_denied" and operation in {"describe_continuous_backups", "describe_time_to_live"})
            or (variant == "tags_denied" and operation in {"get_resources", "list_tags_of_resource"})
            or (variant == "autoscaling_denied" and operation in {"describe_scalable_targets", "describe_scaling_policies"})
        )
        if denied or (root and variant in {"unsupported", "failure", "unavailable"}):
            self.calls.append("failed:" + operation)
            if variant == "unavailable":
                raise EndpointConnectionError(endpoint_url="https://synthetic.invalid")
            code = "UnknownOperationException" if variant == "unsupported" else "InternalFailure" if variant == "failure" else "AccessDeniedException"
            raise ClientError({"Error": {"Code": code, "Message": "synthetic local provider limitation"}}, operation)

    def _values(self, value: object, *, reverse: bool = False) -> Any:  # noqa: ANN401
        if self.variant != "literal_collision":
            return value
        if isinstance(value, dict):
            return {key: child if reverse and key == "MetricName" else self._values(child, reverse=reverse) for key, child in value.items()}
        if isinstance(value, list):
            return [self._values(child, reverse=reverse) for child in value]
        if isinstance(value, str):
            old, new = ("ConsumedReadCapacityUnits", "orders") if reverse else ("orders", "ConsumedReadCapacityUnits")
            return value.replace(old, new)
        return value
