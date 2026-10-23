"""Strict synthetic provider composition for the three related registered wrappers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from tools.collector_serverless.lambda_client import SyntheticLambdaClient
from tools.collector_serverless.lifecycle_client import SyntheticLifecycleClient
from tools.collector_serverless.metric_client import SyntheticMetricClient
from tools.collector_serverless.s3_client import SyntheticNotificationClient
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from tools.collector_serverless.base import SyntheticServerlessClient
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticServerlessSession:
    """Return only explicit local service clients and retain actual diagnostics."""

    def __init__(self, variant: str) -> None:
        """Keep each synthetic scenario isolated with a bounded worker count."""
        self.variant = variant
        self.calls: list[str] = []
        self.collection_diagnostics = AwsCollectionDiagnostics()
        self.runtime_config = AwsRuntimeConfig(max_workers=1)

    def create_client(self, service_name: str, *, region_name: str | None = None, audit_context: AwsAuditContext) -> SyntheticServerlessClient:
        """Forbid any undeclared service or region; never construct boto3 objects."""
        del audit_context
        mapping = {
            "lambda": SyntheticLambdaClient,
            "cloudwatch": SyntheticMetricClient,
            "s3": SyntheticNotificationClient,
            **dict.fromkeys(("rds", "ec2", "elasticache", "opensearch", "eks"), SyntheticLifecycleClient),
        }
        if service_name not in mapping or region_name not in {None, "eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic serverless service or region."
            raise ValueError(message)
        self.calls.append("create_client:" + service_name + ":" + str(region_name))
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic unavailable service"}}, "CreateClient")
        return mapping[service_name](self, service_name)

    def get_region_name(self) -> str:
        """Return the explicit synthetic local region for metric helpers."""
        return "eu-west-2"
