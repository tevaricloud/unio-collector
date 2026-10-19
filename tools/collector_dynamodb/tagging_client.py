"""Synthetic SDK response shapes retained from existing DynamoDB owning fixtures."""

from __future__ import annotations

from typing import Any

from tools.collector_serverless.base import synthetic_arn


class SyntheticTaggingClient:  # noqa: D101
    def __init__(self: Any) -> None:  # noqa: D107
        self.calls: list[str] = []

    def can_paginate(self: Any, operation_name: str) -> bool:  # noqa: D102
        del operation_name
        return False

    def get_resources(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        self.calls.append(
            f"get_resources:{','.join(kwargs.get('ResourceTypeFilters', []))}",
        )
        return {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": synthetic_arn("dynamodb", "table/orders"),
                    "Tags": [
                        {"Key": "Owner", "Value": "payments"},
                        {"Key": "Environment", "Value": "prod"},
                    ],
                },
            ],
        }
