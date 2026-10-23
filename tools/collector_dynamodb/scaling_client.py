"""Synthetic SDK response shapes retained from existing DynamoDB owning fixtures."""

from __future__ import annotations

from typing import Any


class SyntheticScalingClient:  # noqa: D101
    def __init__(self: Any) -> None:  # noqa: D107
        self.calls: list[str] = []

    def can_paginate(self: Any, operation_name: str) -> bool:  # noqa: D102
        del operation_name
        return False

    def describe_scalable_targets(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        self.calls.append(f"describe_scalable_targets:{kwargs.get('ServiceNamespace')}")
        return {
            "ScalableTargets": [
                {
                    "ResourceId": "table/orders",
                    "ScalableDimension": "dynamodb:table:ReadCapacityUnits",
                },
            ],
        }

    def describe_scaling_policies(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        self.calls.append(f"describe_scaling_policies:{kwargs.get('ServiceNamespace')}")
        return {
            "ScalingPolicies": [
                {
                    "PolicyName": "orders-read-scaling",
                    "ResourceId": "table/orders",
                },
            ],
        }
