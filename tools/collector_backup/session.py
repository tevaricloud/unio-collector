"""Strict local Backup service provider and actual diagnostic storage."""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from tools.collector_backup.client import SyntheticBackupClient
from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticBackupSession:
    """Never instantiate a boto3 session, service client or live credentials."""

    def __init__(self, variant: str) -> None:
        """Bind one isolated provider or exact Backup note parent."""
        self.variant = variant
        self.calls: list[str] = []
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None = None, audit_context: AwsAuditContext) -> SyntheticBackupClient:
        """Handle the declared synthetic create client operation locally."""
        del audit_context
        if service_name != "backup" or region_name is None or region_name not in {"eu-west-2", "us-east-1"}:
            message = "Unexpected synthetic backup service or region."
            raise ValueError(message)
        self.calls.append("create_client:" + region_name)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic service is not enabled"}}, "CreateClient")
        return SyntheticBackupClient(self, region_name)
