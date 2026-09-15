from __future__ import annotations  # noqa: D100

from typing import Any


class ManagedPlatformEksHelpersMixin:
    """Managed platform inventory collector helpers."""

    @property
    def _collector(self) -> Any:  # noqa: ANN401
        return self

    def _get_eks_public_access_cidrs(self, cluster: dict[str, Any]) -> list[str]:
        config = cluster.get("resourcesVpcConfig", {})
        if not isinstance(config, dict):
            return []
        cidrs = config.get("publicAccessCidrs", [])
        if not isinstance(cidrs, list):
            return []
        return [str(cidr) for cidr in cidrs if cidr]

    def _has_eks_secret_encryption(self, cluster: dict[str, Any]) -> bool:
        config = cluster.get("encryptionConfig", [])
        if not isinstance(config, list):
            return False
        for item in config:
            if not isinstance(item, dict):
                continue
            resources = item.get("resources", [])
            if isinstance(resources, list) and "secrets" in resources:
                return True
        return False

    def _get_eks_enabled_log_types(self, cluster: dict[str, Any]) -> list[str]:
        logging = cluster.get("logging", {})
        if not isinstance(logging, dict):
            return []
        cluster_logging = logging.get("clusterLogging", [])
        if not isinstance(cluster_logging, list):
            return []
        log_types: list[str] = []
        for item in cluster_logging:
            if not isinstance(item, dict) or not bool(item.get("enabled")):
                continue
            types = item.get("types", [])
            if isinstance(types, list):
                log_types.extend(str(log_type) for log_type in types if log_type)
        return sorted(set(log_types))

    def _get_eks_cluster_tags(self, cluster: dict[str, Any]) -> dict[str, str]:
        tags = cluster.get("tags", {})
        if not isinstance(tags, dict):
            return {}
        return {str(key): str(value) for key, value in tags.items() if key and value is not None}

    def _get_eks_nodegroup_scaling_value(
        self,
        nodegroup: dict[str, Any],
        key: str,
    ) -> int:
        scaling_config = nodegroup.get("scalingConfig", {})
        if not isinstance(scaling_config, dict):
            return 0
        return self._collector._get_int(scaling_config.get(key))  # noqa: SLF001

    def _get_eks_nodegroup_instance_types(
        self,
        nodegroup: dict[str, Any],
    ) -> list[str]:
        instance_types = nodegroup.get("instanceTypes", [])
        if not isinstance(instance_types, list):
            return []
        return [str(instance_type) for instance_type in instance_types if instance_type]

    def _get_eks_fargate_selectors(
        self,
        profile: dict[str, Any],
    ) -> list[dict[str, Any]]:
        selectors = profile.get("selectors", [])
        if not isinstance(selectors, list):
            return []
        return [selector for selector in selectors if isinstance(selector, dict)]

    def _get_eks_endpoint_access(
        self,
        cluster: dict[str, Any],
        key: str,
    ) -> bool:
        config = cluster.get("resourcesVpcConfig")
        return bool(config.get(key)) if isinstance(config, dict) else False
