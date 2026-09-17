from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.opensearch.region_record import OpenSearchRegionRecord
from unio_collector.aws.redshift.region_record import RedshiftRegionRecord


class ManagedPlatformSearchRedshiftMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_opensearch_record(
        self,
        region: str,
    ) -> list[OpenSearchRegionRecord]:
        permission_errors: list[str] = []
        client = self._collector._safe_client("opensearch", region, permission_errors)  # noqa: SLF001
        if client is None:
            return [
                OpenSearchRegionRecord(
                    account_id=self._collector.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]
        domain_names = self._collector._collect_opensearch_domain_names(  # noqa: SLF001
            client,
            permission_errors,
        )
        domains = self._collector._describe_opensearch_domains(  # noqa: SLF001
            client,
            domain_names,
            permission_errors,
        )
        return [
            OpenSearchRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                domain_count=len(domain_names),
                processing_domain_count=sum(1 for domain in domains if bool(domain.get("Processing"))),
                total_instance_count=sum(self._collector._get_opensearch_instance_count(domain) for domain in domains),  # noqa: SLF001
                multi_az_domain_count=sum(1 for domain in domains if self._collector._has_opensearch_multi_az(domain)),  # noqa: SLF001
                dedicated_master_domain_count=sum(
                    1
                    for domain in domains
                    if self._collector._get_opensearch_cluster_config(domain).get(  # noqa: SLF001
                        "DedicatedMasterEnabled",
                    )
                ),
                warm_storage_domain_count=sum(
                    1
                    for domain in domains
                    if self._collector._get_opensearch_cluster_config(domain).get(  # noqa: SLF001
                        "WarmEnabled",
                    )
                ),
                ebs_enabled_domain_count=sum(
                    1
                    for domain in domains
                    if self._collector._get_opensearch_ebs_options(domain).get(  # noqa: SLF001
                        "EBSEnabled",
                    )
                ),
                total_ebs_volume_gb=sum(self._collector._get_opensearch_ebs_volume_gb(domain) for domain in domains),  # noqa: SLF001
                sample_domain_names=self._collector._limit_samples(domain_names),  # noqa: SLF001
                sample_engine_versions=self._collector._limit_samples(  # noqa: SLF001
                    [str(domain.get("EngineVersion")) for domain in domains if domain.get("EngineVersion")],
                ),
                sample_instance_types=self._collector._limit_samples(  # noqa: SLF001
                    [
                        str(instance_type)
                        for domain in domains
                        if (
                            instance_type := self._collector._get_opensearch_cluster_config(  # noqa: SLF001
                                domain,
                            ).get("InstanceType")
                        )
                    ],
                ),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_redshift_record(self, region: str) -> list[RedshiftRegionRecord]:
        permission_errors: list[str] = []
        cluster_client = self._collector._safe_client(  # noqa: SLF001
            "redshift",
            region,
            permission_errors,
        )
        serverless_client = self._collector._safe_client(  # noqa: SLF001
            "redshift-serverless",
            region,
            permission_errors,
        )
        clusters = (
            self._collector._collect_redshift_clusters(  # noqa: SLF001
                cluster_client,
                permission_errors,
            )
            if cluster_client
            else []
        )
        workgroups = (
            self._collector._collect_redshift_serverless_workgroups(  # noqa: SLF001
                serverless_client,
                permission_errors,
            )
            if serverless_client
            else []
        )
        namespaces = (
            self._collector._collect_redshift_serverless_namespaces(  # noqa: SLF001
                serverless_client,
                permission_errors,
            )
            if serverless_client
            else []
        )
        return [
            RedshiftRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                cluster_count=len(clusters),
                available_cluster_count=sum(1 for cluster in clusters if str(cluster.get("ClusterStatus") or "").lower() == "available"),
                paused_cluster_count=sum(1 for cluster in clusters if str(cluster.get("ClusterStatus") or "").lower() == "paused"),
                total_node_count=sum(self._collector._get_int(cluster.get("NumberOfNodes")) for cluster in clusters),  # noqa: SLF001
                multi_az_cluster_count=sum(1 for cluster in clusters if self._collector._is_redshift_multi_az(cluster)),  # noqa: SLF001
                encrypted_cluster_count=sum(1 for cluster in clusters if bool(cluster.get("Encrypted"))),
                logging_enabled_cluster_count=sum(1 for cluster in clusters if self._collector._has_redshift_logging(cluster)),  # noqa: SLF001
                serverless_namespace_count=len(namespaces),
                serverless_workgroup_count=len(workgroups),
                serverless_base_capacity_rpu_total=sum(
                    self._collector._get_int(  # noqa: SLF001
                        workgroup.get("baseCapacity") or workgroup.get("BaseCapacity"),
                    )
                    for workgroup in workgroups
                ),
                serverless_max_capacity_rpu_total=sum(
                    self._collector._get_int(  # noqa: SLF001
                        workgroup.get("maxCapacity") or workgroup.get("MaxCapacity"),
                    )
                    for workgroup in workgroups
                ),
                sample_cluster_identifiers=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("ClusterIdentifier")) for cluster in clusters if cluster.get("ClusterIdentifier")],
                ),
                sample_node_types=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("NodeType")) for cluster in clusters if cluster.get("NodeType")],
                ),
                sample_serverless_names=self._collector._limit_samples(  # noqa: SLF001
                    self._collector._get_redshift_serverless_names(  # noqa: SLF001
                        workgroups,
                        namespaces,
                    ),
                ),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_opensearch_domain_names(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "list_domain_names",
                result_key="DomainNames",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_domain_names",
                exc=exc,
            )
            return []
        names: list[str] = []
        for page in result.pages:
            for item in page.get("DomainNames", []):
                if isinstance(item, dict) and item.get("DomainName"):
                    names.append(str(item["DomainName"]))
                elif isinstance(item, str):
                    names.append(item)
        return names

    def _describe_opensearch_domains(
        self,
        client: Any,  # noqa: ANN401
        domain_names: list[str],
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        domains: list[dict[str, Any]] = []
        for name_batch in self._collector._chunk_values(domain_names, 5):  # noqa: SLF001
            try:
                response = client.describe_domains(DomainNames=name_batch)
            except Exception as exc:  # noqa: BLE001
                self._collector._record_collection_error(  # noqa: SLF001
                    permission_errors,
                    method_name="describe_domains",
                    exc=exc,
                )
                continue
            domain_statuses = response.get("DomainStatusList", []) if isinstance(response, dict) else []
            domains.extend(domain for domain in domain_statuses if isinstance(domain, dict))
        return domains

    def _collect_redshift_clusters(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_pages(  # noqa: SLF001
                client,
                "describe_clusters",
                result_key="Clusters",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_clusters",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "Clusters")  # noqa: SLF001

    def _collect_redshift_serverless_workgroups(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_workgroups",
                result_key="workgroups",
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_workgroups",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "workgroups")  # noqa: SLF001

    def _collect_redshift_serverless_namespaces(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[dict[str, Any]]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_namespaces",
                result_key="namespaces",
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_namespaces",
                exc=exc,
            )
            return []
        return self._collector._collect_items(result.pages, "namespaces")  # noqa: SLF001

    def _get_opensearch_cluster_config(
        self,
        domain: dict[str, Any],
    ) -> dict[str, Any]:
        config = domain.get("ClusterConfig")
        return config if isinstance(config, dict) else {}

    def _get_opensearch_ebs_options(
        self,
        domain: dict[str, Any],
    ) -> dict[str, Any]:
        options = domain.get("EBSOptions")
        return options if isinstance(options, dict) else {}

    def _get_opensearch_instance_count(self, domain: dict[str, Any]) -> int:
        value = self._collector._get_opensearch_cluster_config(domain).get(  # noqa: SLF001
            "InstanceCount",
        )
        return int(value) if isinstance(value, int) else 0

    def _get_opensearch_ebs_volume_gb(self, domain: dict[str, Any]) -> int:
        value = self._collector._get_opensearch_ebs_options(domain).get("VolumeSize")  # noqa: SLF001
        return int(value) if isinstance(value, int) else 0

    def _has_opensearch_multi_az(self, domain: dict[str, Any]) -> bool:
        config = self._collector._get_opensearch_cluster_config(domain)  # noqa: SLF001
        zone_config = config.get("ZoneAwarenessConfig")
        if config.get("ZoneAwarenessEnabled"):
            return True
        if isinstance(zone_config, dict):
            value = zone_config.get("AvailabilityZoneCount")
            return isinstance(value, int) and value > 1
        return False

    def _is_redshift_multi_az(self, cluster: dict[str, Any]) -> bool:
        if bool(cluster.get("MultiAZ")):
            return True
        return str(cluster.get("MultiAZStatus") or "").lower() in {
            "enabled",
            "available",
        }

    def _has_redshift_logging(self, cluster: dict[str, Any]) -> bool:
        logging_status = cluster.get("LoggingStatus")
        if isinstance(logging_status, dict):
            return bool(logging_status.get("LoggingEnabled"))
        return False

    def _get_redshift_serverless_names(
        self,
        workgroups: list[dict[str, Any]],
        namespaces: list[dict[str, Any]],
    ) -> list[str]:
        names: list[str] = []
        for workgroup in workgroups:
            name = workgroup.get("workgroupName") or workgroup.get("WorkgroupName")
            if name:
                names.append(f"workgroup:{name}")
        for namespace in namespaces:
            name = namespace.get("namespaceName") or namespace.get("NamespaceName")
            if name:
                names.append(f"namespace:{name}")
        return names
