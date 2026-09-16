from __future__ import annotations  # noqa: D100

from typing import Any

from unio_collector.aws.eks.region_record import EksRegionRecord


class ManagedPlatformEksMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _collect_eks_record(self, region: str) -> list[EksRegionRecord]:
        permission_errors: list[str] = []
        client = self._collector._safe_client("eks", region, permission_errors)  # noqa: SLF001
        if client is None:
            return [
                EksRegionRecord(
                    account_id=self._collector.account_id,
                    region=region,
                    permission_errors=permission_errors,
                ),
            ]
        cluster_names = self._collector._collect_eks_cluster_names(  # noqa: SLF001
            client,
            permission_errors,
        )
        clusters = [
            cluster
            for cluster_name in cluster_names
            if (
                cluster := self._collector._describe_eks_cluster(  # noqa: SLF001
                    client,
                    cluster_name,
                    permission_errors,
                )
            )
        ]
        nodegroups_by_cluster = {
            cluster_name: self._collector._collect_eks_nodegroup_names(  # noqa: SLF001
                client,
                cluster_name,
                permission_errors,
            )
            for cluster_name in cluster_names
        }
        fargate_profiles_by_cluster = {
            cluster_name: self._collector._collect_eks_fargate_profile_names(  # noqa: SLF001
                client,
                cluster_name,
                permission_errors,
            )
            for cluster_name in cluster_names
        }
        nodegroup_details = [
            nodegroup
            for cluster_name, nodegroup_names in nodegroups_by_cluster.items()
            for nodegroup_name in nodegroup_names
            if (
                nodegroup := self._collector._describe_eks_nodegroup(  # noqa: SLF001
                    client,
                    cluster_name,
                    nodegroup_name,
                    permission_errors,
                )
            )
        ]
        fargate_profile_details = [
            profile
            for cluster_name, profile_names in fargate_profiles_by_cluster.items()
            for profile_name in profile_names
            if (
                profile := self._collector._describe_eks_fargate_profile(  # noqa: SLF001
                    client,
                    cluster_name,
                    profile_name,
                    permission_errors,
                )
            )
        ]
        public_endpoint_clusters = [cluster for cluster in clusters if self._collector._get_eks_endpoint_access(cluster, "endpointPublicAccess")]  # noqa: SLF001
        endpoint_cidrs = [cidr for cluster in public_endpoint_clusters for cidr in self._collector._get_eks_public_access_cidrs(cluster)]  # noqa: SLF001
        enabled_log_types = sorted(
            {log_type for cluster in clusters for log_type in self._collector._get_eks_enabled_log_types(cluster)},  # noqa: SLF001
        )
        return [
            EksRegionRecord(
                account_id=self._collector.account_id,
                region=region,
                cluster_count=len(cluster_names),
                active_cluster_count=sum(1 for cluster in clusters if str(cluster.get("status") or "").upper() == "ACTIVE"),
                nodegroup_count=sum(len(names) for names in nodegroups_by_cluster.values()),
                fargate_profile_count=sum(len(names) for names in fargate_profiles_by_cluster.values()),
                fargate_selector_count=sum(len(self._collector._get_eks_fargate_selectors(profile)) for profile in fargate_profile_details),  # noqa: SLF001
                cluster_without_managed_compute_count=sum(
                    1 for cluster_name in cluster_names if not nodegroups_by_cluster.get(cluster_name) and not fargate_profiles_by_cluster.get(cluster_name)
                ),
                public_endpoint_cluster_count=sum(
                    1
                    for cluster in clusters
                    if self._collector._get_eks_endpoint_access(  # noqa: SLF001
                        cluster,
                        "endpointPublicAccess",
                    )
                ),
                private_endpoint_cluster_count=sum(
                    1
                    for cluster in clusters
                    if self._collector._get_eks_endpoint_access(  # noqa: SLF001
                        cluster,
                        "endpointPrivateAccess",
                    )
                ),
                public_endpoint_open_cidr_count=sum(1 for cidr in endpoint_cidrs if cidr == "0.0.0.0/0"),
                public_endpoint_restricted_cidr_count=sum(1 for cidr in endpoint_cidrs if cidr != "0.0.0.0/0"),
                secrets_encryption_enabled_cluster_count=sum(1 for cluster in clusters if self._collector._has_eks_secret_encryption(cluster)),  # noqa: SLF001
                control_plane_logging_enabled_cluster_count=sum(1 for cluster in clusters if self._collector._get_eks_enabled_log_types(cluster)),  # noqa: SLF001
                tagged_cluster_count=sum(1 for cluster in clusters if self._collector._get_eks_cluster_tags(cluster)),  # noqa: SLF001
                untagged_cluster_count=sum(1 for cluster in clusters if not self._collector._get_eks_cluster_tags(cluster)),  # noqa: SLF001
                nodegroup_desired_size_total=sum(
                    self._collector._get_eks_nodegroup_scaling_value(  # noqa: SLF001
                        nodegroup,
                        "desiredSize",
                    )
                    for nodegroup in nodegroup_details
                ),
                nodegroup_min_size_total=sum(
                    self._collector._get_eks_nodegroup_scaling_value(  # noqa: SLF001
                        nodegroup,
                        "minSize",
                    )
                    for nodegroup in nodegroup_details
                ),
                nodegroup_max_size_total=sum(
                    self._collector._get_eks_nodegroup_scaling_value(  # noqa: SLF001
                        nodegroup,
                        "maxSize",
                    )
                    for nodegroup in nodegroup_details
                ),
                sample_cluster_names=self._collector._limit_samples(cluster_names),  # noqa: SLF001
                sample_nodegroup_names=self._collector._limit_samples(  # noqa: SLF001
                    [
                        f"{cluster_name}/{nodegroup_name}"
                        for cluster_name, nodegroup_names in nodegroups_by_cluster.items()
                        for nodegroup_name in nodegroup_names
                    ],
                ),
                sample_fargate_profile_names=self._collector._limit_samples(  # noqa: SLF001
                    [
                        f"{cluster_name}/{profile_name}"
                        for cluster_name, profile_names in (fargate_profiles_by_cluster.items())
                        for profile_name in profile_names
                    ],
                ),
                sample_versions=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("version")) for cluster in clusters if cluster.get("version")],
                ),
                sample_public_endpoint_cluster_names=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("name")) for cluster in public_endpoint_clusters if cluster.get("name")],
                ),
                sample_untagged_cluster_names=self._collector._limit_samples(  # noqa: SLF001
                    [str(cluster.get("name")) for cluster in clusters if cluster.get("name") and not self._collector._get_eks_cluster_tags(cluster)],  # noqa: SLF001
                ),
                sample_public_endpoint_cidrs=self._collector._limit_samples(  # noqa: SLF001
                    endpoint_cidrs,
                ),
                sample_enabled_log_types=self._collector._limit_samples(  # noqa: SLF001
                    enabled_log_types,
                ),
                sample_nodegroup_instance_types=self._collector._limit_samples(  # noqa: SLF001
                    [
                        instance_type
                        for nodegroup in nodegroup_details
                        for instance_type in self._collector._get_eks_nodegroup_instance_types(  # noqa: SLF001
                            nodegroup,
                        )
                    ],
                ),
                sample_nodegroup_capacity_types=self._collector._limit_samples(  # noqa: SLF001
                    sorted(
                        {str(nodegroup.get("capacityType")) for nodegroup in nodegroup_details if nodegroup.get("capacityType")},
                    ),
                ),
                permission_errors=permission_errors,
            ),
        ]

    def _collect_eks_cluster_names(
        self,
        client: Any,  # noqa: ANN401
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_clusters",
                result_key="clusters",
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_clusters",
                exc=exc,
            )
            return []
        return [str(cluster_name) for page in result.pages for cluster_name in page.get("clusters", []) if cluster_name]

    def _describe_eks_cluster(
        self,
        client: Any,  # noqa: ANN401
        cluster_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.describe_cluster(name=cluster_name)
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_cluster",
                exc=exc,
            )
            return None
        cluster = response.get("cluster") if isinstance(response, dict) else None
        return cluster if isinstance(cluster, dict) else None

    def _collect_eks_nodegroup_names(
        self,
        client: Any,  # noqa: ANN401
        cluster_name: str,
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_nodegroups",
                result_key="nodegroups",
                request_parameters={"clusterName": cluster_name},
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_nodegroups",
                exc=exc,
            )
            return []
        return [str(nodegroup_name) for page in result.pages for nodegroup_name in page.get("nodegroups", []) if nodegroup_name]

    def _collect_eks_fargate_profile_names(
        self,
        client: Any,  # noqa: ANN401
        cluster_name: str,
        permission_errors: list[str],
    ) -> list[str]:
        try:
            result = self._collector._pagination.collect_token_pages(  # noqa: SLF001
                client,
                "list_fargate_profiles",
                result_key="fargateProfileNames",
                request_parameters={"clusterName": cluster_name},
                response_cursor_keys=("nextToken", "NextToken"),
                request_cursor_key="nextToken",
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="list_fargate_profiles",
                exc=exc,
            )
            return []
        return [str(profile_name) for page in result.pages for profile_name in page.get("fargateProfileNames", []) if profile_name]

    def _describe_eks_nodegroup(
        self,
        client: Any,  # noqa: ANN401
        cluster_name: str,
        nodegroup_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.describe_nodegroup(
                clusterName=cluster_name,
                nodegroupName=nodegroup_name,
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_nodegroup",
                exc=exc,
            )
            return None
        nodegroup = response.get("nodegroup") if isinstance(response, dict) else None
        return nodegroup if isinstance(nodegroup, dict) else None

    def _describe_eks_fargate_profile(
        self,
        client: Any,  # noqa: ANN401
        cluster_name: str,
        profile_name: str,
        permission_errors: list[str],
    ) -> dict[str, Any] | None:
        try:
            response = client.describe_fargate_profile(
                clusterName=cluster_name,
                fargateProfileName=profile_name,
            )
        except Exception as exc:  # noqa: BLE001
            self._collector._record_collection_error(  # noqa: SLF001
                permission_errors,
                method_name="describe_fargate_profile",
                exc=exc,
            )
            return None
        profile = response.get("fargateProfile") if isinstance(response, dict) else None
        return profile if isinstance(profile, dict) else None
