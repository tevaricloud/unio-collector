"""Synthetic OpenSearch and Redshift providers for actual registered collection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from unio_collector.aws.client.config import AwsRuntimeConfig
from unio_collector.aws.collection.diagnostics import AwsCollectionDiagnostics

if TYPE_CHECKING:
    from unio_collector.aws.audit.context import AwsAuditContext


class SyntheticSearchSession:
    """Provide populated, nullable, partial and failed real SDK response shapes."""

    def __init__(self, service: str, variant: str) -> None:
        """Select one deterministic provider branch and retain collection diagnostics."""
        self.service = service
        self.variant = variant
        self.calls: list[str] = []
        self.runtime_config = AwsRuntimeConfig(max_workers=1)
        self.collection_diagnostics = AwsCollectionDiagnostics()

    def create_client(self, service_name: str, *, region_name: str | None, audit_context: AwsAuditContext) -> SyntheticSearchSession:
        """Return only the selected synthetic regional provider family."""
        del audit_context
        services = {self.service, "redshift-serverless"} if self.service == "redshift" else {self.service}
        if service_name not in services or region_name != "eu-west-2":
            message = "Unexpected synthetic search or warehouse provider."
            raise ValueError(message)
        self.calls.append("create_client:" + service_name)
        if self.variant == "unavailable":
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic unavailable"}}, "CreateClient")
        return self

    def can_paginate(self, _name: str) -> bool:
        """Use the real non-paginator SDK fallback without network."""
        return False

    def _response(self, operation: str, key: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        self.calls.append(operation)
        failing = operation in {"describe_domains", "describe_clusters"}
        if failing and self.variant in {"denied", "unsupported", "failure"}:
            code = {"denied": "AccessDeniedException", "unsupported": "UnknownOperationException", "failure": "InternalFailure"}[self.variant]
            raise ClientError({"Error": {"Code": code, "Message": "synthetic provider failure"}}, operation)
        if self.variant == "empty":
            rows = []
        if self.variant == "partial" and operation in {"describe_domains", "list_namespaces"}:
            rows = []
        return {key: rows}

    def list_domain_names(self, **_kwargs: object) -> dict[str, Any]:
        """Retain customer names in the actual discovery response."""
        return self._response(
            "list_domain_names", "DomainNames", [{"DomainName": "synthetic-customer-domain"}, {"DomainName": "synthetic-customer-domain-two"}]
        )

    def describe_domains(self, **_kwargs: object) -> dict[str, Any]:
        """Drive both AZ branches, warm/master/EBS counts and optional configs."""
        rows = [
            {
                "DomainName": "synthetic-customer-domain",
                "EngineVersion": "OpenSearch_2.17",
                "Processing": True,
                "ClusterConfig": {
                    "InstanceCount": 3,
                    "InstanceType": "r6g.large.search",
                    "DedicatedMasterEnabled": True,
                    "WarmEnabled": True,
                    "ZoneAwarenessEnabled": True,
                },
                "EBSOptions": {"EBSEnabled": True, "VolumeSize": 50},
            },
            {
                "DomainName": "synthetic-customer-domain-two",
                "EngineVersion": "synthetic-customer-engine",
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "synthetic-customer-instance", "ZoneAwarenessConfig": {"AvailabilityZoneCount": 2}},
                "EBSOptions": {"EBSEnabled": False},
            },
        ]
        if self.variant == "nullable":
            rows = [{"DomainName": "synthetic-customer-domain", "EngineVersion": None, "Processing": None, "ClusterConfig": None, "EBSOptions": None}]
        return self._response("describe_domains", "DomainStatusList", rows)

    def describe_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise available/paused, optional logging and both multi-AZ controls."""
        rows = [
            {
                "ClusterIdentifier": "synthetic-customer-cluster",
                "ClusterStatus": "available",
                "NodeType": "ra3.xlplus",
                "NumberOfNodes": 2,
                "MultiAZ": True,
                "Encrypted": True,
                "LoggingStatus": {"LoggingEnabled": True},
            },
            {
                "ClusterIdentifier": "synthetic-customer-paused",
                "ClusterStatus": "paused",
                "NodeType": "synthetic-customer-node",
                "NumberOfNodes": 1,
                "MultiAZStatus": "enabled",
                "Encrypted": False,
                "LoggingStatus": None,
            },
        ]
        if self.variant == "nullable":
            rows = [{"ClusterIdentifier": "synthetic-customer-cluster", "NodeType": None, "NumberOfNodes": None, "LoggingStatus": None, "MultiAZStatus": None}]
        return self._response("describe_clusters", "Clusters", rows)

    def list_workgroups(self, **_kwargs: object) -> dict[str, Any]:
        """Retain provider casing alternatives and nullable serverless capacities."""
        return self._response(
            "list_workgroups",
            "workgroups",
            [
                {"workgroupName": "synthetic-customer-workgroup", "baseCapacity": 8, "maxCapacity": 16},
                {"WorkgroupName": "synthetic-customer-workgroup-two", "BaseCapacity": None, "MaxCapacity": None},
            ],
        )

    def list_namespaces(self, **_kwargs: object) -> dict[str, Any]:
        """Drive the actual serverless namespace-name extraction."""
        return self._response(
            "list_namespaces", "namespaces", [{"namespaceName": "synthetic-customer-namespace"}, {"NamespaceName": "synthetic-customer-namespace-two"}]
        )
