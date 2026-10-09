"""Explicit fields emitted by the four service coverage collectors."""

from __future__ import annotations

Spec = tuple[str, str, bool]

COMMON: dict[str, Spec] = {
    "": ("object", "safe_metadata", False),
    "records": ("array", "safe_metadata", False),
    "records[]": ("object", "safe_metadata", False),
    "regions": ("array", "region", False),
    "regions[]": ("string", "region", False),
    "warnings": ("array", "free_text", False),
    "warnings[]": ("string", "free_text", False),
    "metadata": ("object", "safe_metadata", False),
    "account_id": ("string", "aws_account_id", False),
    "records[].service": ("string", "safe_metadata", False),
    "records[].region": ("string", "region", False),
    "records[].resource_type": ("string", "safe_metadata", False),
    "records[].resource_id": ("string", "resource_id", False),
    "records[].resource_name": ("string", "resource_name", True),
    "records[].arn": ("string", "arn", True),
    "records[].tags": ("tag_map", "tag_value", False),
    "records[].attributes": ("object", "safe_metadata", False),
}
ATTRIBUTES: dict[str, Spec] = {
    "record_set_count": ("count", "safe_metadata", True),
    "private_zone": ("boolean", "safe_metadata", True),
    "health_check_type": ("health_type", "safe_metadata", True),
    "traffic_policy_type": ("record_type", "safe_metadata", True),
    "subscription_count": ("string", "safe_metadata", True),
    "kms_master_key_id": ("string", "arn_or_name", True),
    "fifo_topic": ("boolean_string", "safe_metadata", True),
    "attributes_collection_status": ("unavailable", "safe_metadata", False),
    "subscription_count_status": ("unavailable", "safe_metadata", False),
    "tags_collection_status": ("status", "safe_metadata", False),
    "state_machine_type": ("machine_type", "safe_metadata", True),
    "creation_date": ("timestamp", "timestamp", False),
    "state": ("string", "free_text", True),
    "attached": ("boolean", "safe_metadata", True),
    "attached_to": ("string", "resource_name", True),
    "blueprint_id": ("string", "resource_id", True),
    "bundle_id": ("string", "resource_id", True),
}
RESOURCE_ATTRIBUTES = {
    "Hosted zone": {"record_set_count", "private_zone"},
    "Health check": {"health_check_type"},
    "Traffic policy": {"traffic_policy_type"},
    "SNS topic": {
        "subscription_count",
        "kms_master_key_id",
        "fifo_topic",
        "attributes_collection_status",
        "subscription_count_status",
        "tags_collection_status",
    },
    "State machine": {"state_machine_type", "creation_date", "tags_collection_status"},
    "Activity": {"creation_date"},
    **{
        kind: {"state", "attached", "attached_to", "blueprint_id", "bundle_id"}
        for kind in ("Instance", "Static IP", "Disk", "Load balancer", "Database", "Bucket", "Container service")
    },
}
SCANNERS = {
    "route53-cost-governance-review": (
        "Amazon Route 53",
        {"Hosted zone", "Health check", "Traffic policy"},
        {"hosted_zone_count", "health_check_count", "traffic_policy_count"},
    ),
    "sns-cost-governance-review": ("Amazon Simple Notification Service", {"SNS topic"}, {"topic_count"}),
    "step-functions-cost-governance-review": ("AWS Step Functions", {"State machine", "Activity"}, {"state_machine_count", "activity_count"}),
    "lightsail-cost-governance-review": (
        "Amazon Lightsail",
        {"Instance", "Static IP", "Disk", "Load balancer", "Database", "Bucket", "Container service"},
        {
            "endpoint_strategy",
            "operation_names",
            "instance_count",
            "static_ip_count",
            "disk_count",
            "database_count",
            "load_balancer_count",
            "bucket_count",
            "container_service_count",
        },
    ),
}
VOCABULARIES = {
    "health_type": {"HTTP", "HTTPS", "HTTP_STR_MATCH", "HTTPS_STR_MATCH", "TCP", "CALCULATED", "CLOUDWATCH_METRIC", "RECOVERY_CONTROL"},
    "record_type": {"SOA", "A", "TXT", "NS", "CNAME", "MX", "NAPTR", "PTR", "SRV", "SPF", "AAAA", "CAA", "DS", "TLSA", "SSHFP", "SVCB", "HTTPS"},
    "machine_type": {"STANDARD", "EXPRESS"},
    "boolean_string": {"true", "false"},
    "unavailable": {"unavailable"},
    "status": {"complete", "unavailable"},
    "endpoint": {"explicit_region_override", "botocore_lightsail_endpoint_metadata"},
    "operation": {"GetInstances", "GetStaticIps", "GetDisks", "GetLoadBalancers", "GetRelationalDatabases", "GetBuckets", "GetContainerServices"},
}
FIELDS = {
    **COMMON,
    **{"records[].attributes." + key: value for key, value in ATTRIBUTES.items()},
    **{"metadata." + key: ("count", "safe_metadata", False) for _, _, keys in SCANNERS.values() for key in keys if key.endswith("_count")},
    "metadata.endpoint_strategy": ("endpoint", "safe_metadata", False),
    "metadata.operation_names": ("array", "safe_metadata", False),
    "metadata.operation_names[]": ("operation", "safe_metadata", False),
}
