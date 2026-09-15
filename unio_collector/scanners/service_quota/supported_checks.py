from __future__ import annotations  # noqa: D100

from unio_collector.scanners.service_quota.check_spec import (
    ServiceQuotaCheckSpec,
)

SUPPORTED_SERVICE_QUOTA_CHECKS: tuple[ServiceQuotaCheckSpec, ...] = (
    ServiceQuotaCheckSpec(
        check_id="ec2-elastic-ips-per-region",
        service="Amazon EC2",
        quota_service_code="ec2",
        quota_code="L-0263D0A3",
        quota_name_terms=("elastic ip",),
        resource_type="Elastic IP address",
        usage_method="ec2_describe_addresses_count",
    ),
    ServiceQuotaCheckSpec(
        check_id="vpc-vpcs-per-region",
        service="Amazon VPC",
        quota_service_code="vpc",
        quota_code="L-F678F1CE",
        quota_name_terms=("vpcs per region", "vpcs per account"),
        resource_type="VPC",
        usage_method="ec2_describe_vpcs_count",
    ),
    ServiceQuotaCheckSpec(
        check_id="vpc-security-groups-per-region",
        service="Amazon VPC",
        quota_service_code="vpc",
        quota_code="L-E79EC296",
        quota_name_terms=(
            "vpc security groups per region",
            "security groups per region",
        ),
        resource_type="Security group",
        usage_method="ec2_describe_security_groups_count",
    ),
    ServiceQuotaCheckSpec(
        check_id="vpc-nat-gateways-per-az",
        service="Amazon VPC",
        quota_service_code="vpc",
        quota_code="L-FE5A380F",
        quota_name_terms=("nat gateways per availability zone", "nat gateways per az"),
        resource_type="NAT gateway",
        usage_method="ec2_describe_nat_gateways_max_per_az",
    ),
    ServiceQuotaCheckSpec(
        check_id="elb-application-load-balancers-per-region",
        service="Elastic Load Balancing",
        quota_service_code="elasticloadbalancing",
        quota_code="L-53DA6B97",
        quota_name_terms=("application load balancers per region",),
        resource_type="Application Load Balancer",
        usage_method="elbv2_describe_load_balancers_application_count",
    ),
    ServiceQuotaCheckSpec(
        check_id="elb-network-load-balancers-per-region",
        service="Elastic Load Balancing",
        quota_service_code="elasticloadbalancing",
        quota_code="L-69A177A2",
        quota_name_terms=("network load balancers per region",),
        resource_type="Network Load Balancer",
        usage_method="elbv2_describe_load_balancers_network_count",
    ),
)
