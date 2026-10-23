"""Synthetic SDK response shapes retained from existing DynamoDB owning fixtures."""

from __future__ import annotations

from typing import Any

from tools.collector_serverless.base import synthetic_arn


class SyntheticTableClient:  # noqa: D101
    def __init__(self: Any) -> None:  # noqa: D107
        self.calls: list[str] = []

    def can_paginate(self: Any, operation_name: str) -> bool:  # noqa: D102
        del operation_name
        return False

    def list_tables(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        del kwargs
        self.calls.append("list_tables")
        return {"TableNames": ["orders", "events"]}

    def describe_table(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        table_name = kwargs["TableName"]
        self.calls.append(f"describe_table:{table_name}")
        if table_name == "orders":
            return {
                "Table": {
                    "TableName": "orders",
                    "TableStatus": "ACTIVE",
                    "TableArn": synthetic_arn("dynamodb", "table/orders"),
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 50,
                        "WriteCapacityUnits": 25,
                    },
                    "GlobalSecondaryIndexes": [
                        {
                            "IndexName": "orders-by-status",
                            "ProvisionedThroughput": {
                                "ReadCapacityUnits": 20,
                                "WriteCapacityUnits": 10,
                            },
                        },
                    ],
                    "StreamSpecification": {"StreamEnabled": True},
                },
            }
        return {
            "Table": {
                "TableName": "events",
                "TableStatus": "ACTIVE",
                "TableArn": synthetic_arn("dynamodb", "table/events"),
                "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                "TableClassSummary": {"TableClass": "STANDARD_INFREQUENT_ACCESS"},
            },
        }

    def describe_continuous_backups(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        table_name = kwargs["TableName"]
        self.calls.append(f"describe_continuous_backups:{table_name}")
        status = "ENABLED" if table_name == "orders" else "DISABLED"
        return {
            "ContinuousBackupsDescription": {
                "PointInTimeRecoveryDescription": {
                    "PointInTimeRecoveryStatus": status,
                },
            },
        }

    def describe_time_to_live(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        table_name = kwargs["TableName"]
        self.calls.append(f"describe_time_to_live:{table_name}")
        status = "ENABLED" if table_name == "events" else "DISABLED"
        return {"TimeToLiveDescription": {"TimeToLiveStatus": status}}

    def list_tags_of_resource(self: Any, **kwargs: Any) -> dict[str, Any]:  # noqa: ANN401, D102
        resource_arn = kwargs["ResourceArn"]
        table_name = resource_arn.rsplit("/", 1)[-1]
        self.calls.append(f"list_tags_of_resource:{table_name}")
        if table_name == "orders":
            return {
                "Tags": [
                    {"Key": "Owner", "Value": "payments"},
                    {"Key": "Environment", "Value": "prod"},
                ],
            }
        return {"Tags": []}
