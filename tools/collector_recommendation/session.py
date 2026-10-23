"""Offline SDK session with actual page/error shapes and no AWS clients."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from botocore.exceptions import ClientError
from botocore.validate import validate_parameters

from tools.collector_recommendation.response import OPS, SdkShape, sample, sdk_model

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticRecommendationSession:
    """Record declared in-memory SDK requests and expose supported failure shapes."""

    def __init__(self, service: str, variant: str) -> None:
        """Bind one finite synthetic provider, never a credentials-backed session."""
        self.service = service
        self.variant = variant
        self.calls: list[dict[str, object]] = []
        self.models = sdk_model(service)

    def create_client(self, service: str, *, region_name: str, audit_context: AwsAuditContext) -> SyntheticRecommendationSession:
        """Require the selected finite endpoint and the actual audited scanner context."""
        if (
            service != self.service
            or region_name != "eu-west-2"
            or audit_context.scanner_id not in {"compute-optimizer-recommendation-review", "cost-optimization-hub-recommendation-review"}
        ):
            message = "Unexpected synthetic provider endpoint"
            raise ValueError(message)
        return self

    def get_available_regions(self, service: str) -> list[str]:
        """Return explicit local endpoint metadata, including supported missing scope."""
        if service != self.service:
            message = "Unexpected synthetic service metadata request"
            raise ValueError(message)
        return [] if self.variant == "missing_scope" else ["eu-west-2"]

    def get_sdk_available_regions(self, service: str) -> list[str]:
        """Preserve the actual endpoint-selection metadata interface."""
        return self.get_available_regions(service)

    def can_paginate(self, operation: str) -> bool:
        """Exercise actual reader pagination only for declared operations."""
        return operation in OPS and self.variant in {"partial", "capped"}

    def get_paginator(self, operation: str) -> SimpleNamespace:
        """Provide the normal generator interface with actual page-boundary failures."""
        return SimpleNamespace(paginate=lambda **params: self.pages(operation, params))

    def __getattr__(self, operation: str) -> Callable[..., dict[str, object]]:
        """Expose only the finite SDK operations used by these collectors."""
        if operation not in OPS:
            raise AttributeError(operation)
        return lambda **params: next(self.pages(operation, params))

    def pages(self, operation: str, params: dict[str, object]) -> Iterator[dict[str, object]]:
        """Validate real SDK requests and return populated/partial/malformed responses."""
        name, key = OPS[operation]
        model = self.models.operation_model(name)
        validate_parameters(params, model.input_shape)
        self.calls.append({"operation": operation, "parameters": deepcopy(params)})
        self._failure(name)
        if self.variant == "missing_page":
            yield {}
            return
        shape = cast("SdkShape", model.output_shape).members[key].member
        row = cast("dict[str,object]", sample(shape))
        self._mutate(row, operation)
        rows: list[object] = [] if self.variant == "empty" else [row]
        if self.variant == "success" and operation == "get_rds_database_recommendations":
            rows.append(self._storage_recommendation(row))
        if self.variant == "capped" and "summar" not in operation:
            rows = [deepcopy(row) for _ in range(101)]
        if self.variant == "malformed_record" and "summar" not in operation:
            rows.append(None)
        if self.variant in {"success", "empty", "partial", "nullable", "adversarial", "capped", "count_collision", "metric_collision", "error_code_collision"}:
            validate_parameters({key: rows}, model.output_shape)
        yield {key: rows}
        if self.variant == "partial" and "summar" not in operation:
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "Synthetic later page"}}, name)

    def _failure(self, operation: str) -> None:
        if self.variant in {"unsupported", "failure"}:
            message = "Synthetic unsupported operation" if self.variant == "unsupported" else "Synthetic failure only"
            if self.variant == "unsupported":
                raise AttributeError(message)
            raise RuntimeError(message)
        code = {"denied": "AccessDeniedException", "not_enabled": "AccountNotOptedInException", "unavailable": "ServiceUnavailableException"}.get(self.variant)
        if code:
            raise ClientError({"Error": {"Code": code, "Message": "Synthetic provider message must not escape"}}, operation)

    def _mutate(self, row: dict[str, object], operation: str) -> None:
        self._numeric_collision(row, operation)
        if self.variant == "success" and operation == "get_ec2_instance_recommendations":
            row["instanceName"] = "AccessDeniedException"
        if self.variant == "null_fields" and "summar" not in operation:
            for key in ("finding", "instanceFinding", "storageFinding", "region"):
                if key in row:
                    row[key] = None
            row["confidence"] = None
        self._identity_mutation(row)

    def _identity_mutation(self, row: dict[str, object]) -> None:
        """Apply only independently supported optional and malformed identity shapes."""
        if self.variant == "nullable":
            keep = {"instanceArn", "volumeArn", "functionArn", "resourceArn", "serviceArn", "resourceId", "recommendationId"}
            for key in set(row) - keep:
                row.pop(key)
        if self.variant in {"adversarial", "error_code_collision"}:
            for key in ("instanceName", "resourceId", "recommendationId"):
                if key in row:
                    row[key] = "AccessDeniedException" if self.variant == "error_code_collision" else "recorded"
        if self.variant in {"oversized", "malformed_identity"}:
            for key in ("instanceArn", "resourceArn", "recommendationId"):
                if key in row:
                    row[key] = 12 if self.variant == "malformed_identity" else "SyntheticCustomer-" + "x" * 70000
                    break

    def _numeric_collision(self, row: dict[str, object], operation: str) -> None:
        if self.variant == "count_collision":
            if operation == "get_ec2_instance_recommendations":
                row["instanceName"] = "1200"
            if operation == "get_ebs_volume_recommendations":
                current = cast("dict[str,object]", row["currentConfiguration"])
                current["volumeSize"] = 1200
            if operation == "list_recommendation_summaries":
                row["recommendationCount"] = 1200
            if operation == "list_recommendations":
                row.update(recommendationId="1200", resourceId="1200")
        if self.variant == "metric_collision" and operation == "get_ec2_instance_recommendations":
            row["instanceName"] = "42.125"
            option = cast("list[dict[str,object]]", row["recommendationOptions"])[0]
            metric = cast("list[dict[str,object]]", option["projectedUtilizationMetrics"])[0]
            metric["value"] = 42.125

    @staticmethod
    def _storage_recommendation(row: dict[str, object]) -> dict[str, object]:
        """Exercise the real optional storage-only SDK branch in the populated fixture."""
        storage = deepcopy(row)
        storage.pop("instanceRecommendationOptions", None)
        for field in ("dbInstanceIdentifier", "resourceArn"):
            value = storage.get(field)
            if isinstance(value, str):
                storage[field] = value + "-storage"
        return storage
