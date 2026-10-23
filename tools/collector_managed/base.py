"""Strict local provider composition and retained actual regional diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from botocore.exceptions import ClientError

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticManagedSession:
    """Forbid unexpected services while supplying only deterministic local values."""

    failing_operations: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, service: str, variant: str) -> None:
        """Keep each operation isolated without constructing an AWS session/client."""
        self.service = service
        self.variant = variant
        self.region = "eu-west-2"
        self.calls: list[str] = []
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticManagedSession:
        """Validate actual provider composition and preserve unavailable-client paths."""
        del audit_context
        allowed = {self.service, "cloudwatch"} if self.service == "elasticache" else {self.service}
        if service_name not in allowed or region_name not in {"eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic managed-platform service or region."
            raise ValueError(message)
        self.region = region_name
        self.calls.append("create_client:" + service_name + ":" + region_name)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic unavailable"}}, "CreateClient")
        return self

    def get_region_name(self) -> str:
        """Keep real metric helper region selection local and deterministic."""
        return self.region

    def can_paginate(self, _name: str) -> bool:
        """Use the real supported one-page fallback for SDK operations."""
        return False

    def _fail(self, operation: str) -> None:
        self.calls.append(operation)
        if operation in self.failing_operations and self.variant in {"denied", "unsupported", "failure"}:
            code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}[self.variant]
            raise ClientError({"Error": {"Code": code, "Message": "synthetic provider failure"}}, operation)

    def _response(self, operation: str, key: str, rows: list[Any]) -> dict[str, Any]:
        self._fail(operation)
        return {key: [] if self.variant == "empty" else rows}
