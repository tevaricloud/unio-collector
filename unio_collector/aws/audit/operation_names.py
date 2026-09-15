from __future__ import annotations  # noqa: D100

from typing import Any


def snake_to_pascal(value: str) -> str:  # noqa: D103
    special_names = {
        "describe_db_instances": "DescribeDBInstances",
    }
    if value in special_names:
        return special_names[value]
    return "".join(part.capitalize() for part in value.split("_"))


def get_api_operation_name(raw_client: Any, method_name: str) -> str:  # noqa: ANN401, D103
    meta = getattr(raw_client, "meta", None)
    operation_mapping = getattr(meta, "method_to_api_mapping", None)
    if isinstance(operation_mapping, dict):
        operation_name = operation_mapping.get(method_name)
        if isinstance(operation_name, str) and operation_name:
            return operation_name
    return snake_to_pascal(method_name)
