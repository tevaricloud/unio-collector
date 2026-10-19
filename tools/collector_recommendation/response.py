"""Pinned SDK response shapes and synthetic populated provider values."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

import botocore
from botocore.loaders import Loader
from botocore.model import ServiceModel

OPS = {
    "get_recommendation_summaries": ("GetRecommendationSummaries", "recommendationSummaries"),
    "get_ec2_instance_recommendations": ("GetEC2InstanceRecommendations", "instanceRecommendations"),
    "get_ebs_volume_recommendations": ("GetEBSVolumeRecommendations", "volumeRecommendations"),
    "get_lambda_function_recommendations": ("GetLambdaFunctionRecommendations", "lambdaFunctionRecommendations"),
    "get_rds_database_recommendations": ("GetRDSDatabaseRecommendations", "rdsDBRecommendations"),
    "get_ecs_service_recommendations": ("GetECSServiceRecommendations", "ecsServiceRecommendations"),
    "get_idle_recommendations": ("GetIdleRecommendations", "idleRecommendations"),
    "list_recommendation_summaries": ("ListRecommendationSummaries", "items"),
    "list_recommendations": ("ListRecommendations", "items"),
}
VARIANTS = (
    "success",
    "empty",
    "partial",
    "denied",
    "not_enabled",
    "unavailable",
    "unsupported",
    "failure",
    "missing_page",
    "malformed_record",
    "malformed_identity",
    "capped",
    "oversized",
    "nullable",
    "null_fields",
    "missing_scope",
    "adversarial",
    "error_code_collision",
    "count_collision",
    "metric_collision",
)


class SdkShape(Protocol):
    """Typed SDK descriptor view; source models remain the independent authority."""

    type_name: str
    metadata: dict[str, object]
    members: dict[str, SdkShape]
    member: SdkShape
    value: SdkShape


def sample(shape: SdkShape, key: str = "") -> object:
    """Populate every pinned SDK field without hand-written normalized DTOs."""
    if shape.type_name == "structure":
        return {name: sample(child, name) for name, child in shape.members.items()}
    if shape.type_name == "list":
        return [sample(shape.member, key)]
    if shape.type_name == "map":
        return {"SyntheticCustomerKey": sample(shape.value, key)}
    choices = shape.metadata.get("enum")
    if isinstance(choices, list) and choices:
        return choices[0]
    return _scalar(shape, key)


def _scalar(shape: SdkShape, key: str) -> object:
    if shape.type_name == "string":
        return _text(key)
    if shape.type_name == "boolean":
        return True
    if shape.type_name in {"integer", "long"}:
        minimum = shape.metadata.get("min", 0)
        if isinstance(minimum, int):
            return max(2, minimum)
    if shape.type_name in {"double", "float"}:
        return 12.25
    if shape.type_name == "timestamp":
        return datetime(2026, 9, 1, 12, tzinfo=UTC)
    message = "Unsupported synthetic SDK scalar shape"
    raise ValueError(message)


def _text(key: str) -> str:
    if "account" in key.lower() and key.lower().endswith("id"):
        return "123456789012"
    if "arn" in key.lower():
        return "arn:aws:ec2:eu-west-2:123456789012:instance/i-synthetic-native"
    if key == "region":
        return "eu-west-2"
    if "currency" in key.lower():
        return "USD"
    return "SyntheticCustomer-" + key


def sdk_model(service: str) -> ServiceModel:
    """Read only installed SDK package data; never credentials or user model paths."""
    data = Path(botocore.__file__).resolve().parent / "data"
    loader = Loader(extra_search_paths=[str(data)], include_default_search_paths=False)
    return ServiceModel(loader.load_service_model(service, "service-2"))
