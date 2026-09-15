# noqa: D100
# pyright: reportAttributeAccessIssue=false
from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from unio_collector.scanners.service_quota.parsing import quota_response_records
from unio_collector.scanners.service_quota.usage import (
    ServiceQuotaUsage,
)

if TYPE_CHECKING:
    from unio_collector.scanners.scanner.context import (
        ScannerContext,
    )


class ServiceQuotaUsageCountMixin:  # noqa: D101
    def _count_security_groups(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        client = self._create_ec2_client(context, region)
        groups = self._collect_operation_items(
            client,
            "describe_security_groups",
            "SecurityGroups",
        )
        return ServiceQuotaUsage(
            value=len(groups),
            confidence="high",
            method="ec2:DescribeSecurityGroups count",
        )

    def _count_nat_gateways_per_az(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        client = self._create_ec2_client(context, region)
        gateways = self._collect_operation_items(
            client,
            "describe_nat_gateways",
            "NatGateways",
        )
        if any(str(gateway.get("State") or "").lower() not in {"pending", "available", "deleting", "deleted", "failed"} for gateway in gateways):
            return ServiceQuotaUsage(
                value=None,
                confidence="low",
                method="ec2:DescribeNatGateways max active count per Availability Zone",
                limitation=f"NAT gateway usage per Availability Zone was unavailable in {region} because gateway state evidence was missing or unknown.",
            )
        active = [gateway for gateway in gateways if str(gateway.get("State") or "").lower() not in {"deleted", "deleting", "failed"}]
        if any(
            not gateway.get("State") or not isinstance(gateway.get("AvailabilityZone"), str) or not gateway["AvailabilityZone"].strip() for gateway in active
        ):
            return ServiceQuotaUsage(
                value=None,
                confidence="low",
                method="ec2:DescribeNatGateways max active count per Availability Zone",
                limitation=f"NAT gateway usage per Availability Zone was unavailable in {region} because gateway state or zone evidence was missing.",
            )
        by_az = Counter(str(gateway["AvailabilityZone"]) for gateway in active)
        return ServiceQuotaUsage(
            value=max(by_az.values(), default=0),
            confidence="medium",
            method="ec2:DescribeNatGateways max active count per Availability Zone",
        )

    def _count_application_load_balancers(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        return self._count_load_balancers(
            context,
            region,
            load_balancer_type="application",
        )

    def _count_network_load_balancers(
        self,
        context: ScannerContext,
        region: str,
    ) -> ServiceQuotaUsage:
        return self._count_load_balancers(context, region, load_balancer_type="network")

    def _count_load_balancers(
        self,
        context: ScannerContext,
        region: str,
        *,
        load_balancer_type: str,
    ) -> ServiceQuotaUsage:
        client = context.security.create_client(
            "elbv2",
            region_name=region,
            collector_name="ServiceQuotaProximityCollector",
        )
        balancers = self._collect_operation_items(
            client,
            "describe_load_balancers",
            "LoadBalancers",
        )
        if any(balancer.get("Type") not in {"application", "network", "gateway"} for balancer in balancers):
            message = "Quota usage collection is missing a recognized load balancer type."
            raise ValueError(message)
        return ServiceQuotaUsage(
            value=sum(1 for balancer in balancers if balancer.get("Type") == load_balancer_type),
            confidence="high",
            method=f"elbv2:DescribeLoadBalancers {load_balancer_type} count",
        )

    def _create_ec2_client(
        self,
        context: ScannerContext,
        region: str,
    ) -> Any:  # noqa: ANN401
        return context.security.create_client(
            "ec2",
            region_name=region,
            collector_name="ServiceQuotaProximityCollector",
        )

    def _collect_operation_items(
        self,
        client: Any,  # noqa: ANN401
        operation_name: str,
        result_key: str,
    ) -> list[dict[str, Any]]:
        pages = client.get_paginator(operation_name).paginate() if client.can_paginate(operation_name) else [getattr(client, operation_name)()]
        records: list[dict[str, Any]] = []
        observed_page = False
        for page in pages:
            observed_page = True
            records.extend(quota_response_records(page, result_key))
        if not observed_page:
            message = "Quota usage collection returned no response pages."
            raise ValueError(message)
        return records
