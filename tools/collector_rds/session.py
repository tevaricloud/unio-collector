"""Isolated RDS provider session with genuine collection diagnostics."""

from __future__ import annotations

from typing import Any

from tools.collector_rds.client import VARIANTS, SyntheticRdsClient
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics


class SyntheticRdsSession:
    """Bind one finite scenario to local RDS and CloudWatch responses."""

    def __init__(self, variant: str) -> None:
        """Use bounded serial workers and actual collection diagnostics."""
        if variant not in VARIANTS:
            message = "Unknown synthetic RDS variant"
            raise ValueError(message)
        self.variant = variant
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()
        self.calls: list[dict[str, Any]] = []

    def create_client(self, service: str, *, region_name: str | None, audit_context: object) -> SyntheticRdsClient:
        """Reject undeclared endpoints without creating an SDK session."""
        del audit_context
        if service not in {"rds", "cloudwatch"} or region_name not in {"eu-west-1", "eu-west-2"}:
            message = "Unexpected synthetic RDS endpoint"
            raise ValueError(message)
        return SyntheticRdsClient(service, str(region_name), self.variant, self.calls)

    def get_available_regions(self, service: str) -> list[str]:
        """Return declared synthetic regions only."""
        if service != "rds":
            message = "Unexpected synthetic region discovery service"
            raise ValueError(message)
        return ["eu-west-1", "eu-west-2"] if self.variant == "partial_region" else ["eu-west-2"]
