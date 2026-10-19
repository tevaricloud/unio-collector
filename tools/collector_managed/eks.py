"""Actual EKS cluster, compute and optional nested SDK responses."""

from __future__ import annotations

from typing import Any, ClassVar

from tools.collector_managed.base import SyntheticManagedSession


class SyntheticEksSession(SyntheticManagedSession):
    """Exercise populated control-plane, nodegroup and Fargate evidence."""

    failing_operations: ClassVar[frozenset[str]] = frozenset({"describe_nodegroup"})

    def list_clusters(self, **_kwargs: object) -> dict[str, Any]:
        """Discover a customer-labelled cluster through the real paginator."""
        return self._response("list_clusters", "clusters", ["synthetic-customer-cluster"])

    def describe_cluster(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise endpoint CIDRs, encryption, logging, tags and nullable nesting."""
        self._fail("describe_cluster")
        cluster = {
            "name": "synthetic-customer-cluster",
            "status": "ACTIVE",
            "version": "1.33",
            "resourcesVpcConfig": {"endpointPublicAccess": True, "endpointPrivateAccess": True, "publicAccessCidrs": ["0.0.0.0/0", "192.0.2.0/24"]},
            "encryptionConfig": [{"resources": ["secrets"], "provider": {"keyArn": "arn:aws:kms:eu-west-2:123456789012:key/synthetic"}}],
            "logging": {"clusterLogging": [{"enabled": True, "types": ["api", "audit"]}]},
            "tags": {},
        }
        if self.variant == "nullable":
            cluster.update(resourcesVpcConfig=None, encryptionConfig=None, logging=None, tags=None)
        return {"cluster": cluster}

    def list_nodegroups(self, **_kwargs: object) -> dict[str, Any]:
        """Retain the actual per-cluster managed-compute discovery path."""
        return self._response("list_nodegroups", "nodegroups", [] if self.variant == "partial" else ["synthetic-customer-nodegroup"])

    def describe_nodegroup(self, **_kwargs: object) -> dict[str, Any]:
        """Provide scaling, instance classes and capacity types to the real collector."""
        self._fail("describe_nodegroup")
        return {
            "nodegroup": {
                "scalingConfig": {"desiredSize": 2, "minSize": 1, "maxSize": 4},
                "instanceTypes": ["m5.large", "synthetic-customer-instance"],
                "capacityType": "SPOT",
            }
        }

    def list_fargate_profiles(self, **_kwargs: object) -> dict[str, Any]:
        """Exercise absent managed compute independently of denied descriptions."""
        return self._response("list_fargate_profiles", "fargateProfileNames", [] if self.variant == "partial" else ["synthetic-customer-profile"])

    def describe_fargate_profile(self, **_kwargs: object) -> dict[str, Any]:
        """Retain actual Fargate selector aggregation without manual DTO assembly."""
        self._fail("describe_fargate_profile")
        return {"fargateProfile": {"selectors": [{"namespace": "synthetic-customer-namespace", "labels": {"Owner": "synthetic-customer-owner"}}]}}
