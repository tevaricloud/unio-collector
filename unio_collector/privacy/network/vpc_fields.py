"""Explicit historical VPC endpoint record fields, alongside current topology."""

from unio_collector.privacy.network.fields import FIELDS as TOPOLOGY_FIELDS

CLASSIFICATIONS = frozenset(
    {"ec2_instance", "lambda_managed", "load_balancer", "vpc_endpoint", "nat_gateway", "transit_gateway", "managed_service", "rds", "unknown"}
)
SERVICE_LABELS = frozenset(
    {
        "Amazon ECR API",
        "Amazon ECR Docker",
        "Amazon EC2 API",
        "AWS KMS",
        "CloudWatch Logs",
        "CloudWatch Metrics",
        "Secrets Manager",
        "AWS Systems Manager",
        "Systems Manager Messages",
        "AWS STS",
    }
)
COUNTS = (
    "nat_gateway_count",
    "route_table_count",
    "private_route_table_count",
    "default_routes_to_nat_count",
    "s3_gateway_endpoint_count",
    "dynamodb_gateway_endpoint_count",
    "s3_nat_route_table_gateway_coverage_count",
    "dynamodb_nat_route_table_gateway_coverage_count",
    "s3_nat_route_table_gap_count",
    "dynamodb_nat_route_table_gap_count",
    "interface_endpoint_count",
    "explicit_nat_route_table_subnet_count",
    "inferred_main_route_table_subnet_count",
    "candidate_subnet_count",
    "candidate_network_interface_count",
    "candidate_instance_network_interface_count",
    "candidate_requester_managed_network_interface_count",
    "nat_route_table_without_explicit_subnet_association_count",
    "tagged_nat_gateway_count",
    "tagged_endpoint_count",
)
IDENTIFIER_LISTS = (
    "sample_nat_gateway_ids",
    "sample_route_table_ids",
    "sample_candidate_subnet_ids",
    "sample_inferred_main_route_table_subnet_ids",
    "sample_candidate_network_interface_ids",
    "sample_route_table_ids_without_s3_gateway_endpoint",
    "sample_route_table_ids_without_dynamodb_gateway_endpoint",
    "nat_gateway_ids",
    "nat_route_table_ids",
)
MAPS = {"records[].vpc_tags": "tag_key", "records[].nat_gateway_tags[]": "tag_key", "records[].nat_gateway_availability_zones": "resource_id"}
FIELDS = {
    **TOPOLOGY_FIELDS,
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "records[].account_id": ("string", "aws_account_id", False),
    "records[].region": ("string", "region", False),
    "records[].vpc_id": ("string", "resource_id", False),
    **{f"records[].{key}": ("count", "safe_metadata", False) for key in COUNTS},
    **{f"records[].{key}": ("array", "safe_metadata", False) for key in IDENTIFIER_LISTS},
    **{f"records[].{key}[]": ("string", "resource_id", False) for key in IDENTIFIER_LISTS},
    "records[].candidate_network_interface_type_counts": ("object", "safe_metadata", False),
    **{f"records[].candidate_network_interface_type_counts.{key}": ("count", "safe_metadata", False) for key in CLASSIFICATIONS},
    "records[].endpoint_service_names": ("array", "safe_metadata", False),
    "records[].endpoint_service_names[]": ("string", "network_service", False),
    **{
        f"records[].{key}": ("array", "safe_metadata", False)
        for key in ("present_common_interface_endpoint_services", "missing_common_interface_endpoint_services")
    },
    **{
        f"records[].{key}[]": ("service_label", "safe_metadata", False)
        for key in ("present_common_interface_endpoint_services", "missing_common_interface_endpoint_services")
    },
    "records[].sample_candidate_network_interface_contexts": ("array", "safe_metadata", False),
    "records[].sample_candidate_network_interface_contexts[]": ("object", "safe_metadata", False),
    **{
        f"records[].sample_candidate_network_interface_contexts[].{key}": ("string", "resource_id", False)
        for key in ("network_interface_id", "subnet_id", "attachment_id")
    },
    "records[].sample_candidate_network_interface_contexts[].classification": ("classification", "safe_metadata", False),
    "records[].sample_candidate_network_interface_contexts[].interface_type": ("interface_type", "safe_metadata", False),
    "records[].sample_candidate_network_interface_contexts[].requester_managed": ("true_string", "safe_metadata", False),
    "records[].vpc_tags": ("string_map", "tag_value", False),
    "records[].nat_gateway_tags": ("array", "safe_metadata", False),
    "records[].nat_gateway_tags[]": ("string_map", "tag_value", False),
    "records[].nat_route_table_subnet_ids": ("array", "safe_metadata", False),
    "records[].nat_route_table_subnet_ids[]": ("object", "safe_metadata", False),
    **{f"records[].nat_route_table_subnet_ids[].{key}": ("string", "resource_id", False) for key in ("route_table_id", "subnet_id")},
    "records[].nat_gateway_availability_zones": ("string_map", "region", False),
}
