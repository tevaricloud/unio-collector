"""Local DynamoDB service composition with real collector diagnostics."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from tools.collector_dynamodb.client import SyntheticDynamoClient
from tools.collector_dynamodb.metric_client import SyntheticMetricClient
from tools.collector_dynamodb.scaling_client import SyntheticScalingClient
from tools.collector_dynamodb.table_client import SyntheticTableClient
from tools.collector_dynamodb.tagging_client import SyntheticTaggingClient
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticDynamoSession:
    """Expose only deterministic offline SDK response providers."""

    def __init__(self, variant: str) -> None:
        """Create only local response providers and isolated diagnostic state."""
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()
        self.clients = {
            name: SyntheticDynamoClient(client, variant)
            for name, client in {
                "dynamodb": SyntheticTableClient(),
                "application-autoscaling": SyntheticScalingClient(),
                "cloudwatch": SyntheticMetricClient(),
                "resourcegroupstaggingapi": SyntheticTaggingClient(),
            }.items()
        }

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> Any:  # noqa: ANN401
        """Retain actual service and region requests without a live SDK session."""
        del audit_context
        client = self.clients[service_name]
        client.calls.append("create_client:" + str(region_name))
        return client
